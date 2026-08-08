"""Real PostgreSQL parity and multi-connection invalidation-state tests."""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import psycopg
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from psycopg import sql

from glassbox_compiler import (
    LiveReceiptPipeline,
    PostgresReceiptStateConfig,
    RegistrationDisposition,
)
from glassbox_datahub import ReceiptEmitter, receipt_document_urn
from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    seal_receipt,
    signing_key_fingerprint,
    signing_key_public_key,
)
from glassbox_forensics import ForensicsService
from glassbox_forensics.live_state import TransactionalCampaignReader
from glassbox_invalidation import (
    SQLITE_STATE_SCHEMA_VERSION,
    AuditPhase,
    InvalidationActionError,
    OutboxStatus,
    ReceiptPublicationEvidence,
    SQLiteInvalidationStore,
    TransactionalInvalidationAction,
    TransactionalStoreError,
    build_state_transfer_bundle,
    import_state_transfer_bundle,
)
from glassbox_invalidation import datahub_action as datahub_action_module
from glassbox_invalidation.postgres_store import (
    POSTGRES_STATE_SCHEMA_VERSION,
    PostgresInvalidationStore,
)
from glassbox_invalidation.state_cli import main as state_main
from glassbox_policy import (
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    PolicyInputError,
    create_campaign,
)
from tests.helpers import receipt_payload

POSTGRES_DSN = os.getenv("GLASSBOX_TEST_POSTGRES_DSN")
DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
OTHER_DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.customers,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},average_order_value)"

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not POSTGRES_DSN,
        reason="GLASSBOX_TEST_POSTGRES_DSN is not configured",
    ),
]


def _receipt(
    *,
    run_id: str = "postgres-run-001",
    signing_key: SigningKey | None = None,
) -> dict[str, Any]:
    payload = receipt_payload()
    payload["run"]["run_id"] = run_id
    payload["evidence"][0]["schema_field_urn"] = FIELD
    key = signing_key or SigningKey("postgres-integration-test", Ed25519PrivateKey.generate())
    return seal_receipt(payload, signing_keys=(key,))


def _trust_policy(
    key: SigningKey,
    *,
    status: SignerStatus = SignerStatus.ACTIVE,
) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id="postgres-integration-trust-v1",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=key.key_id,
                public_key=signing_key_public_key(key),
                public_key_sha256=signing_key_fingerprint(key),
                status=status,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )


def _lineage() -> FieldLineageProof:
    return FieldLineageProof(
        coverage=FieldCoverage.COMPLETE,
        rule_id="glassbox.postgres-integration.v1",
        wildcard_query=False,
    )


def _change(*, event_id: str = "postgres-mcl-001") -> NormalizedChange:
    return NormalizedChange(
        event_id=event_id,
        entity_urn=DATASET,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-07T00:00:00Z",
        schema_field_urn=FIELD,
    )


def _evidence(campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
    return InvalidationWriteEvidence(
        incident_aspects=("incidentInfo", "incidentKey"),
        target_summary_verified=True,
        quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
    )


class FakeBackend:
    def __init__(self) -> None:
        self.upserts = 0
        self.verifications = 0
        self.tested = False

    def test_connection(self) -> None:
        self.tested = True

    def upsert_campaign(self, campaign: InvalidationCampaign) -> None:
        del campaign
        self.upserts += 1

    def direct_verify(self, campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
        self.verifications += 1
        return _evidence(campaign)


class FakeReceiptBackend:
    def __init__(self) -> None:
        self.receipts: list[Mapping[str, Any]] = []

    def upsert_receipt(self, receipt: Mapping[str, Any]) -> str:
        self.receipts.append(receipt)
        return receipt_document_urn(str(receipt["receipt_id"]))

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        del urn
        return ("documentInfo",)


class RecordingRouter:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.keys: list[str] = []

    def route(
        self,
        campaign: InvalidationCampaign,
        *,
        idempotency_key: str,
    ) -> tuple[str, ...]:
        del campaign
        self.keys.append(idempotency_key)
        if self.fail:
            raise ConnectionError("synthetic sensitive routing details")
        return ("urn:li:corpGroup:commerce",)


@pytest.fixture
def postgres_schema() -> str:
    if POSTGRES_DSN is None:  # pragma: no cover - skip marker owns this branch
        raise AssertionError("PostgreSQL test DSN is absent")
    schema = f"gbx_test_{uuid.uuid4().hex}"
    try:
        yield schema
    finally:
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


@pytest.fixture
def store(postgres_schema: str) -> PostgresInvalidationStore:
    if POSTGRES_DSN is None:  # pragma: no cover - skip marker owns this branch
        raise AssertionError("PostgreSQL test DSN is absent")
    return PostgresInvalidationStore(POSTGRES_DSN, schema=postgres_schema)


def _campaign(store: PostgresInvalidationStore, *, event_id: str = "postgres-mcl-001") -> Any:
    return create_campaign(_change(event_id=event_id), store.all_profiles())


def test_postgres_full_lifecycle_integrity_and_redelivery(
    store: PostgresInvalidationStore,
) -> None:
    receipt = _receipt()
    assert store.register(receipt, field_lineage=_lineage())
    assert not store.register(receipt, field_lineage=_lineage())
    stored = store.get_receipt(receipt["receipt_id"])
    assert stored is not None
    stored["run"] = {}
    assert store.get_receipt(receipt["receipt_id"])["run"]["run_id"] == "postgres-run-001"
    assert len(store.candidates(_change())) == 1
    unrelated = NormalizedChange(
        event_id="postgres-unrelated",
        entity_urn=OTHER_DATASET,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-07T00:00:00Z",
        schema_field_urn=f"urn:li:schemaField:({OTHER_DATASET},id)",
    )
    assert store.candidates(unrelated) == ()

    backend = FakeBackend()
    router = RecordingRouter()
    first = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="postgres-worker-a",
        owner_router=router,
    ).process(_change(), store.all_profiles())
    second = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="postgres-worker-b",
        owner_router=router,
    ).process(_change(), store.all_profiles())

    assert first.valid and first.emissions == 2 and not first.reused_completion
    assert second.valid and second.emissions == 0 and second.reused_completion
    assert second.reused_routing and second.routed_destinations == ()
    assert backend.upserts == 2 and backend.verifications == 2
    assert router.keys == [first.campaign.campaign_id]
    task = store.get_task(first.campaign.campaign_id)
    routing = store.get_owner_routing_task(first.campaign.campaign_id)
    assert task is not None and task.status is OutboxStatus.COMPLETED
    assert routing is not None and routing.status is OutboxStatus.COMPLETED
    assert routing.delivery_evidence is not None
    assert routing.delivery_evidence.destination_count == 1
    assert store.list_tasks() == (task,)
    assert store.list_owner_routing_tasks() == (routing,)
    assert [item.phase for item in store.read_audit_records()] == [
        AuditPhase.CLASSIFIED,
        AuditPhase.DATAHUB_VERIFIED,
        AuditPhase.OWNER_ROUTING_ACCEPTED,
    ]
    assert store.verify_integrity() == store.verify_integrity()


def test_live_receipt_pipeline_uses_existing_postgres_action_state(
    store: PostgresInvalidationStore,
    postgres_schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_DSN is not None
    monkeypatch.setenv("GLASSBOX_TEST_LIVE_RECEIPT_DSN", POSTGRES_DSN)
    configured_state = PostgresReceiptStateConfig(
        dsn_environment_variable="GLASSBOX_TEST_LIVE_RECEIPT_DSN",
        schema=postgres_schema,
    ).connect()
    backend = FakeReceiptBackend()
    receipt = _receipt(run_id="postgres-automatic-live-receipt")
    pipeline = LiveReceiptPipeline(configured_state, ReceiptEmitter(backend))

    first = pipeline.publish_compiled(receipt, field_lineage=_lineage())
    second = pipeline.publish_compiled(receipt, field_lineage=_lineage())

    assert first.valid and second.valid
    assert first.registration is RegistrationDisposition.INSERTED
    assert second.registration is RegistrationDisposition.REUSED
    assert first.datahub_write_performed
    assert not second.datahub_write_performed
    assert first.state_readback_verified and second.state_readback_verified
    assert store.get_receipt(receipt["receipt_id"]) == receipt
    assert store.all_profiles()[0].field_lineage == _lineage()
    assert len(backend.receipts) == 2
    assert "postgresql://" not in repr(first.to_dict())


def test_postgres_enforces_trusted_admission_and_rotation_history(
    postgres_schema: str,
) -> None:
    assert POSTGRES_DSN is not None
    key = SigningKey("postgres-rotation-key", Ed25519PrivateKey.generate())
    original = _receipt(run_id="postgres-trusted-original", signing_key=key)
    active = PostgresInvalidationStore(
        POSTGRES_DSN,
        schema=postgres_schema,
        signer_trust_policy=_trust_policy(key),
    )
    assert active.register(original, field_lineage=_lineage())

    retired = PostgresInvalidationStore(
        POSTGRES_DSN,
        schema=postgres_schema,
        signer_trust_policy=_trust_policy(key, status=SignerStatus.RETIRED),
        initialize_schema=False,
    )
    assert retired.register(original, field_lineage=_lineage()) is False
    assert retired.get_receipt(original["receipt_id"]) == original
    with pytest.raises(PolicyInputError, match="SIGNER_RETIRED"):
        retired.register(
            _receipt(run_id="postgres-backdated-new", signing_key=key),
            field_lineage=_lineage(),
        )
    assert retired.verify_integrity().receipts == 1

    with pytest.raises(TransactionalStoreError, match="stored receipt failed verification"):
        PostgresInvalidationStore(
            POSTGRES_DSN,
            schema=postgres_schema,
            signer_trust_policy=_trust_policy(key, status=SignerStatus.REVOKED),
            initialize_schema=False,
        )


def test_signed_state_transfer_round_trips_between_sqlite_and_postgres(
    tmp_path: Path,
    postgres_schema: str,
) -> None:
    assert POSTGRES_DSN is not None
    receipt_key = SigningKey("cross-engine-receipts", Ed25519PrivateKey.generate())
    transfer_key = SigningKey("cross-engine-transfers", Ed25519PrivateKey.generate())
    receipt_policy = _trust_policy(receipt_key)
    transfer_policy = _trust_policy(transfer_key)
    sqlite_source = SQLiteInvalidationStore(
        tmp_path / "cross-engine-source.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    for index in range(2):
        sqlite_source.register(
            _receipt(
                run_id=f"cross-engine-{index}",
                signing_key=receipt_key,
            ),
            field_lineage=_lineage(),
        )
    sqlite_bundle = build_state_transfer_bundle(
        sqlite_source,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(transfer_key,),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    postgres_target = PostgresInvalidationStore(
        POSTGRES_DSN,
        schema=postgres_schema,
        signer_trust_policy=receipt_policy,
    )

    imported = import_state_transfer_bundle(
        postgres_target,
        sqlite_bundle,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )

    assert (imported.inserted, imported.reused) == (2, 0)
    assert postgres_target.all_profiles() == sqlite_source.all_profiles()
    assert all(
        item.status is OutboxStatus.READY
        for item in postgres_target.list_receipt_publication_tasks()
    )

    postgres_bundle = build_state_transfer_bundle(
        postgres_target,
        source_engine="POSTGRESQL",
        source_schema_version=POSTGRES_STATE_SCHEMA_VERSION,
        signing_keys=(transfer_key,),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    sqlite_target = SQLiteInvalidationStore(
        tmp_path / "cross-engine-target.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    returned = import_state_transfer_bundle(
        sqlite_target,
        postgres_bundle,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    assert (returned.inserted, returned.reused) == (2, 0)
    assert sqlite_target.all_profiles() == postgres_target.all_profiles()


def test_postgres_state_transfer_rolls_back_earlier_insert_on_late_conflict(
    tmp_path: Path,
    postgres_schema: str,
) -> None:
    assert POSTGRES_DSN is not None
    receipt_key = SigningKey("postgres-batch-receipts", Ed25519PrivateKey.generate())
    transfer_key = SigningKey("postgres-batch-transfers", Ed25519PrivateKey.generate())
    receipt_policy = _trust_policy(receipt_key)
    transfer_policy = _trust_policy(transfer_key)
    source = SQLiteInvalidationStore(
        tmp_path / "postgres-batch-source.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    for index in range(2):
        source.register(_receipt(run_id=f"postgres-batch-{index}", signing_key=receipt_key))
    bundle = build_state_transfer_bundle(
        source,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(transfer_key,),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    receipts = [entry["receipt"] for entry in bundle["receipts"]]
    target = PostgresInvalidationStore(
        POSTGRES_DSN,
        schema=postgres_schema,
        signer_trust_policy=receipt_policy,
    )
    target.register(
        receipts[-1],
        field_lineage=FieldLineageProof(
            coverage=FieldCoverage.PARTIAL,
            rule_id="conflicting-postgres-target-proof",
        ),
    )

    with pytest.raises(TransactionalStoreError, match="conflicting dependency metadata"):
        import_state_transfer_bundle(
            target,
            bundle,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=receipt_policy,
        )

    assert target.get_receipt(receipts[0]["receipt_id"]) is None
    assert target.verify_integrity().receipts == 1


def test_postgres_cannot_silently_promote_pre_policy_state_to_trusted_history(
    postgres_schema: str,
) -> None:
    assert POSTGRES_DSN is not None
    key = SigningKey("postgres-legacy-key", Ed25519PrivateKey.generate())
    legacy = PostgresInvalidationStore(POSTGRES_DSN, schema=postgres_schema)
    legacy.register(
        _receipt(run_id="postgres-pre-policy-receipt", signing_key=key),
        field_lineage=_lineage(),
    )

    with pytest.raises(TransactionalStoreError, match="stored receipt failed verification"):
        PostgresInvalidationStore(
            POSTGRES_DSN,
            schema=postgres_schema,
            signer_trust_policy=_trust_policy(key),
            initialize_schema=False,
        )


def test_postgres_receipt_publication_outbox_lease_and_completion(
    store: PostgresInvalidationStore,
) -> None:
    receipt = _receipt(run_id="postgres-publication-outbox")
    receipt_id = receipt["receipt_id"]
    store.register(receipt, field_lineage=_lineage())
    ready = store.get_receipt_publication_task(receipt_id)
    assert ready is not None and ready.status is OutboxStatus.READY

    claimed = store.claim_receipt_publication(
        receipt_id,
        worker_id="postgres-publisher-a",
        now_ms=1,
        lease_duration_ms=1_000,
    )
    assert claimed is not None and claimed.attempt_count == 1
    assert (
        store.claim_receipt_publication(
            receipt_id,
            worker_id="postgres-publisher-b",
            now_ms=9_999_999_999_999,
            lease_duration_ms=1_000,
        )
        is None
    )
    store.release_receipt_publication(
        receipt_id,
        worker_id="postgres-publisher-a",
        error_type="ReceiptEmissionError",
    )
    reclaimed = store.claim_receipt_publication(
        receipt_id,
        worker_id="postgres-publisher-b",
        now_ms=1,
        lease_duration_ms=1_000,
    )
    assert reclaimed is not None and reclaimed.attempt_count == 2
    evidence = ReceiptPublicationEvidence(
        document_urn=receipt_document_urn(receipt_id),
        aspect_names=("documentInfo",),
    )
    assert store.complete_receipt_publication(
        receipt_id, evidence, worker_id="postgres-publisher-b"
    )
    completed = store.get_receipt_publication_task(receipt_id)
    assert completed is not None and completed.status is OutboxStatus.COMPLETED
    assert completed.publication_evidence == evidence
    assert store.verify_integrity().receipt_publication_tasks == 1


def test_postgres_action_campaign_is_read_through_live_forensics(
    store: PostgresInvalidationStore,
) -> None:
    receipt = _receipt(run_id="postgres-live-forensics")
    assert store.register(receipt, field_lineage=_lineage())
    campaign = _campaign(store, event_id="postgres-live-forensics-event")
    store.stage_campaign(campaign)
    assert store.claim(
        campaign.campaign_id,
        worker_id="postgres-live-forensics-worker",
        now_ms=1,
        lease_duration_ms=500,
    )
    assert store.complete(
        campaign,
        _evidence(campaign),
        worker_id="postgres-live-forensics-worker",
    )

    service = ForensicsService(
        store,
        artifacts=store,
        findings=TransactionalCampaignReader(store),
    )
    persisted = service.get_invalidation_campaign(campaign.campaign_id)
    findings = service.list_decision_findings(receipt["receipt_id"])

    assert persisted["availability"] == "AVAILABLE"
    assert persisted["campaign"]["processing"] == {
        "workflow_status": "COMPLETED",
        "attempt_count": 1,
        "datahub_writeback_state": "VERIFIED",
        "last_error_recorded": False,
    }
    assert persisted["campaign"]["assessments"][0]["state"] == "STALE"
    assert findings["scan_complete"] is True
    assert findings["campaigns_scanned"] == 1
    assert findings["findings_total"] == 1
    assert findings["findings"][0]["campaign_id"] == campaign.campaign_id
    assert findings["findings"][0]["assessment"]["state"] == "STALE"
    assert persisted["raw_content_returned"] is False
    assert findings["raw_content_returned"] is False


def test_postgres_row_locks_allow_only_one_concurrent_claim(
    store: PostgresInvalidationStore,
    postgres_schema: str,
) -> None:
    assert POSTGRES_DSN is not None
    store.register(_receipt(), field_lineage=_lineage())
    campaign = _campaign(store)
    store.stage_campaign(campaign)
    stores = [PostgresInvalidationStore(POSTGRES_DSN, schema=postgres_schema) for _ in range(8)]
    barrier = threading.Barrier(len(stores))

    def claim(index: int) -> str | None:
        barrier.wait(timeout=10)
        result = stores[index].claim(
            campaign.campaign_id,
            worker_id=f"postgres-worker-{index}",
            now_ms=1,
            lease_duration_ms=10_000,
        )
        return result.lease_owner if result is not None else None

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        claims = list(executor.map(claim, range(len(stores))))

    assert sum(item is not None for item in claims) == 1
    assert store.get_task(campaign.campaign_id).attempt_count == 1  # type: ignore[union-attr]


def test_postgres_row_locks_allow_only_one_receipt_publisher(
    store: PostgresInvalidationStore,
    postgres_schema: str,
) -> None:
    assert POSTGRES_DSN is not None
    receipt = _receipt(run_id="postgres-concurrent-publication")
    receipt_id = receipt["receipt_id"]
    store.register(receipt, field_lineage=_lineage())
    stores = [PostgresInvalidationStore(POSTGRES_DSN, schema=postgres_schema) for _ in range(8)]
    barrier = threading.Barrier(len(stores))

    def claim(index: int) -> str | None:
        barrier.wait(timeout=10)
        result = stores[index].claim_receipt_publication(
            receipt_id,
            worker_id=f"postgres-publisher-{index}",
            now_ms=1,
            lease_duration_ms=10_000,
        )
        return result.lease_owner if result is not None else None

    with ThreadPoolExecutor(max_workers=len(stores)) as executor:
        claims = list(executor.map(claim, range(len(stores))))

    assert sum(item is not None for item in claims) == 1
    task = store.get_receipt_publication_task(receipt_id)
    assert task is not None and task.attempt_count == 1


def test_postgres_uses_server_clock_for_expired_lease_recovery(
    store: PostgresInvalidationStore,
) -> None:
    store.register(_receipt(), field_lineage=_lineage())
    campaign = _campaign(store)
    store.stage_campaign(campaign)
    first = store.claim(
        campaign.campaign_id,
        worker_id="first",
        now_ms=1,
        lease_duration_ms=50,
    )
    blocked = store.claim(
        campaign.campaign_id,
        worker_id="second",
        now_ms=9_999_999_999_999,
        lease_duration_ms=50,
    )
    time.sleep(0.08)
    recovered = store.claim(
        campaign.campaign_id,
        worker_id="second",
        now_ms=1,
        lease_duration_ms=500,
    )

    assert first is not None and first.attempt_count == 1
    assert blocked is None
    assert recovered is not None and recovered.attempt_count == 2
    assert recovered.lease_owner == "second"
    renewed = store.renew(
        campaign.campaign_id,
        worker_id="second",
        now_ms=1,
        lease_duration_ms=500,
    )
    assert renewed.lease_expires_at_ms is not None
    with pytest.raises(TransactionalStoreError, match="not owned"):
        store.renew(
            campaign.campaign_id,
            worker_id="first",
            now_ms=1,
            lease_duration_ms=500,
        )
    store.release(campaign, worker_id="second", error_type="SyntheticFailure")
    released = store.get_task(campaign.campaign_id)
    assert released is not None and released.status is OutboxStatus.READY
    assert released.last_error_type == "SyntheticFailure"


def test_postgres_atomic_rollback_and_checksum_failure(
    store: PostgresInvalidationStore,
) -> None:
    with store._transaction() as cursor:
        cursor.execute(
            """
            CREATE FUNCTION reject_dependency() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'synthetic dependency failure';
            END;
            $$ LANGUAGE plpgsql
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER reject_dependency_insert
            BEFORE INSERT ON receipt_dependencies
            FOR EACH ROW EXECUTE FUNCTION reject_dependency()
            """
        )
    with pytest.raises(TransactionalStoreError, match="transactional write failed"):
        store.register(_receipt(), field_lineage=_lineage())
    assert store.verify_integrity().receipts == 0

    with store._transaction() as cursor:
        cursor.execute("DROP TRIGGER reject_dependency_insert ON receipt_dependencies")
        cursor.execute("DROP FUNCTION reject_dependency()")
    store.register(_receipt(run_id="postgres-corruption"), field_lineage=_lineage())
    campaign = _campaign(store, event_id="postgres-corruption-event")
    store.stage_campaign(campaign)
    with store._transaction() as cursor:
        cursor.execute(
            "UPDATE campaign_outbox SET material = %s WHERE campaign_id = %s",
            (b"{}", campaign.campaign_id),
        )
    with pytest.raises(TransactionalStoreError, match="checksum"):
        store.verify_integrity()


def test_postgres_receipt_rolls_back_when_publication_obligation_insert_fails(
    store: PostgresInvalidationStore,
) -> None:
    with store._transaction() as cursor:
        cursor.execute(
            """
            CREATE FUNCTION reject_publication() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'synthetic publication failure';
            END;
            $$ LANGUAGE plpgsql
            """
        )
        cursor.execute(
            """
            CREATE TRIGGER reject_publication_insert
            BEFORE INSERT ON receipt_publication_outbox
            FOR EACH ROW EXECUTE FUNCTION reject_publication()
            """
        )
    with pytest.raises(TransactionalStoreError, match="transactional write failed"):
        store.register(_receipt(run_id="postgres-publication-rollback"), field_lineage=_lineage())
    report = store.verify_integrity()
    assert report.receipts == 0
    assert report.dependencies == 0
    assert report.receipt_publication_tasks == 0


def test_postgres_reverse_index_tampering_fails_integrity(
    store: PostgresInvalidationStore,
) -> None:
    store.register(_receipt(), field_lineage=_lineage())
    with store._transaction() as cursor:
        cursor.execute(
            "UPDATE receipt_dependencies SET datahub_urn = %s",
            (OTHER_DATASET,),
        )

    with pytest.raises(TransactionalStoreError, match="reverse index diverges"):
        store.verify_integrity()


def test_postgres_routing_failure_recovers_without_rewriting_datahub(
    store: PostgresInvalidationStore,
) -> None:
    store.register(_receipt(), field_lineage=_lineage())
    backend = FakeBackend()
    failing_router = RecordingRouter(fail=True)
    failing = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="routing-failure",
        owner_router=failing_router,
    )
    with pytest.raises(InvalidationActionError, match="owner routing failed"):
        failing.process(_change(), store.all_profiles())

    campaign = _campaign(store)
    datahub_task = store.get_task(campaign.campaign_id)
    routing_task = store.get_owner_routing_task(campaign.campaign_id)
    assert datahub_task is not None and datahub_task.status is OutboxStatus.COMPLETED
    assert routing_task is not None and routing_task.status is OutboxStatus.READY
    assert routing_task.last_error_type == "ConnectionError"
    healthy_router = RecordingRouter()
    recovered = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="routing-recovery",
        owner_router=healthy_router,
    ).process(_change(), store.all_profiles())
    assert recovered.reused_completion and recovered.emissions == 0
    assert backend.upserts == 2
    assert failing_router.keys == healthy_router.keys == [campaign.campaign_id]


def test_postgres_rejects_wrong_owners_and_conflicting_completions(
    store: PostgresInvalidationStore,
) -> None:
    store.register(_receipt(), field_lineage=_lineage())
    campaign = _campaign(store)
    evidence = _evidence(campaign)
    store.stage_campaign(campaign)
    with pytest.raises(TransactionalStoreError, match="lease owned elsewhere"):
        store.complete(campaign, evidence, worker_id="not-the-owner")
    with pytest.raises(TransactionalStoreError, match="lease owned elsewhere"):
        store.release(campaign, worker_id="not-the-owner", error_type="WrongOwner")

    assert store.claim(campaign.campaign_id, worker_id="writer", now_ms=1, lease_duration_ms=500)
    assert store.complete(campaign, evidence, worker_id="writer")
    assert (
        store.claim(
            campaign.campaign_id,
            worker_id="late-writer",
            now_ms=1,
            lease_duration_ms=500,
        )
        is None
    )
    assert not store.complete(campaign, evidence, worker_id="writer")
    conflicting_evidence = InvalidationWriteEvidence(
        incident_aspects=("incidentKey", "incidentInfo"),
        target_summary_verified=True,
        quarantined_documents=evidence.quarantined_documents,
    )
    with pytest.raises(TransactionalStoreError, match="conflicting write evidence"):
        store.complete(campaign, conflicting_evidence, worker_id="writer")

    with pytest.raises(TransactionalStoreError, match="not owned"):
        store.renew_owner_routing(
            campaign.campaign_id,
            worker_id="not-the-owner",
            now_ms=1,
            lease_duration_ms=500,
        )
    with pytest.raises(TransactionalStoreError, match="lease owned elsewhere"):
        store.complete_owner_routing(campaign, (), worker_id="not-the-owner")
    assert store.claim_owner_routing(
        campaign.campaign_id,
        worker_id="router",
        now_ms=1,
        lease_duration_ms=500,
    )
    with pytest.raises(TransactionalStoreError, match="lease owned elsewhere"):
        store.release_owner_routing(
            campaign,
            worker_id="not-the-owner",
            error_type="WrongOwner",
        )
    accepted = store.complete_owner_routing(
        campaign,
        ("urn:li:corpGroup:commerce",),
        worker_id="router",
    )
    assert accepted.destination_count == 1
    assert (
        store.claim_owner_routing(
            campaign.campaign_id,
            worker_id="late-router",
            now_ms=1,
            lease_duration_ms=500,
        )
        is None
    )
    assert (
        store.complete_owner_routing(
            campaign,
            ("urn:li:corpGroup:commerce",),
            worker_id="router",
        )
        == accepted
    )
    with pytest.raises(TransactionalStoreError, match="conflicting delivery evidence"):
        store.complete_owner_routing(
            campaign,
            ("urn:li:corpGroup:finance",),
            worker_id="router",
        )


def test_postgres_integrity_rejects_missing_and_premature_routing(
    store: PostgresInvalidationStore,
) -> None:
    store.register(_receipt(), field_lineage=_lineage())
    completed = _campaign(store)
    store.stage_campaign(completed)
    store.claim(completed.campaign_id, worker_id="writer", now_ms=1, lease_duration_ms=500)
    store.complete(completed, _evidence(completed), worker_id="writer")
    with store._transaction() as cursor:
        cursor.execute(
            "DELETE FROM owner_routing_outbox WHERE campaign_id = %s",
            (completed.campaign_id,),
        )
    with pytest.raises(TransactionalStoreError, match="no owner-routing obligation"):
        store.verify_integrity()

    pending = _campaign(store, event_id="postgres-premature-routing")
    store.stage_campaign(pending)
    with store._transaction() as cursor:
        cursor.execute(
            "INSERT INTO owner_routing_outbox(campaign_id, status) VALUES (%s, 'READY')",
            (completed.campaign_id,),
        )
        cursor.execute(
            "INSERT INTO owner_routing_outbox(campaign_id, status) VALUES (%s, 'READY')",
            (pending.campaign_id,),
        )
    with pytest.raises(TransactionalStoreError, match="before campaign completion"):
        store.verify_integrity()


def test_postgres_cli_and_schema_version_fail_closed(
    store: PostgresInvalidationStore,
    postgres_schema: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert POSTGRES_DSN is not None
    monkeypatch.setenv("GLASSBOX_TEST_CLI_DSN", POSTGRES_DSN)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(_receipt()))
    assert (
        state_main(
            [
                "postgres-register-receipt",
                str(receipt_path),
                "--dsn-env",
                "GLASSBOX_TEST_CLI_DSN",
                "--schema",
                postgres_schema,
                "--field-coverage",
                "COMPLETE",
                "--field-rule",
                "glassbox.postgres-cli.v1",
                "--wildcard-query",
                "false",
                "--allow-untrusted-signers",
            ]
        )
        == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["valid"] and result["database"]["receipts"] == 1
    assert "postgresql://" not in json.dumps(result)
    assert (
        state_main(
            [
                "postgres-verify",
                "--dsn-env",
                "GLASSBOX_TEST_CLI_DSN",
                "--schema",
                postgres_schema,
                "--allow-untrusted-signers",
            ]
        )
        == 0
    )
    capsys.readouterr()

    with store._transaction() as cursor:
        cursor.execute("UPDATE state_metadata SET value = '999' WHERE key = 'schema_version'")
    with pytest.raises(TransactionalStoreError, match="schema version"):
        PostgresInvalidationStore(POSTGRES_DSN, schema=postgres_schema)


def test_datahub_action_factory_uses_initialized_postgres_without_exposing_dsn(
    store: PostgresInvalidationStore,
    postgres_schema: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert POSTGRES_DSN is not None
    backend = FakeBackend()
    monkeypatch.setenv("GLASSBOX_TEST_ACTION_DSN", POSTGRES_DSN)
    monkeypatch.setattr(
        datahub_action_module.DataHubInvalidationBackend,
        "from_graph",
        classmethod(lambda cls, graph, actor_urn: backend),
    )

    action = datahub_action_module.GlassBoxInvalidationAction.create(
        {
            "state_postgres_dsn_env": "GLASSBOX_TEST_ACTION_DSN",
            "state_postgres_schema": postgres_schema,
            "require_trusted_receipt_signer": False,
        },
        SimpleNamespace(
            graph=SimpleNamespace(graph=object()),
            pipeline_name="glassbox-postgres-factory-test",
        ),
    )

    assert backend.tested
    assert action.config.state_postgres_schema == postgres_schema
    assert action.config.state_postgres_dsn_env == "GLASSBOX_TEST_ACTION_DSN"
    assert POSTGRES_DSN not in json.dumps(action.config.model_dump(mode="json"))
    assert store.verify_integrity().receipts == 0


def test_postgres_rejects_invalid_connection_and_schema() -> None:
    with pytest.raises(TransactionalStoreError, match="DSN"):
        PostgresInvalidationStore("")
    with pytest.raises(TransactionalStoreError, match="schema name"):
        PostgresInvalidationStore("unused", schema="unsafe-schema")
    with pytest.raises(TransactionalStoreError, match="connect_timeout"):
        PostgresInvalidationStore("unused", connect_timeout_seconds=0)
    with pytest.raises(TransactionalStoreError, match="failed to connect"):
        PostgresInvalidationStore(
            "postgresql://glassbox:synthetic@127.0.0.1:1/glassbox",
            connect_timeout_seconds=1,
        )


def test_postgres_runtime_mode_refuses_to_bootstrap_schema() -> None:
    assert POSTGRES_DSN is not None
    schema = f"gbx_absent_{uuid.uuid4().hex}"
    with pytest.raises(TransactionalStoreError, match="run postgres-init"):
        PostgresInvalidationStore(
            POSTGRES_DSN,
            schema=schema,
            initialize_schema=False,
        )
    with psycopg.connect(POSTGRES_DSN) as connection:
        exists = connection.execute(
            "SELECT 1 FROM information_schema.schemata WHERE schema_name = %s",
            (schema,),
        ).fetchone()
    assert exists is None


def test_postgres_bootstrap_refuses_unversioned_application_tables() -> None:
    assert POSTGRES_DSN is not None
    schema = f"gbx_unversioned_{uuid.uuid4().hex}"
    try:
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(schema)))
            connection.execute(
                sql.SQL("CREATE TABLE {}.orphan_state(id INTEGER)").format(sql.Identifier(schema))
            )
        with pytest.raises(TransactionalStoreError, match="no schema version"):
            PostgresInvalidationStore(POSTGRES_DSN, schema=schema)
    finally:
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def test_postgres_cli_bootstraps_a_fresh_schema(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert POSTGRES_DSN is not None
    schema = f"gbx_cli_{uuid.uuid4().hex}"
    monkeypatch.setenv("GLASSBOX_TEST_BOOTSTRAP_DSN", POSTGRES_DSN)
    try:
        assert (
            state_main(
                [
                    "postgres-init",
                    "--dsn-env",
                    "GLASSBOX_TEST_BOOTSTRAP_DSN",
                    "--schema",
                    schema,
                    "--allow-untrusted-signers",
                ]
            )
            == 0
        )
        result = json.loads(capsys.readouterr().out)
        assert result["valid"]
        assert result["database"] == {
            "audit_records": 0,
            "campaigns": 0,
            "dependencies": 0,
            "owner_routing_tasks": 0,
            "receipt_publication_tasks": 0,
            "receipts": 0,
        }
    finally:
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
