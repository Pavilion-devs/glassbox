"""Transactional receipt index, campaign outbox, and recovery tests."""

from __future__ import annotations

import json
import multiprocessing
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from glassbox_datahub import receipt_document_urn
from glassbox_dbom import SigningKey, seal_receipt
from glassbox_invalidation import (
    AuditPhase,
    InvalidationActionError,
    OutboxStatus,
    ReceiptPublicationEvidence,
    SQLiteInvalidationStore,
    TransactionalInvalidationAction,
    TransactionalStoreError,
)
from glassbox_invalidation import datahub_action as datahub_action_module
from glassbox_invalidation.datahub_action import GlassBoxInvalidationActionConfig
from glassbox_invalidation.state_cli import main as state_main
from glassbox_policy import (
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    ReceiptDependencyProfile,
    create_campaign,
)
from tests.helpers import receipt_payload

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
OTHER_DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.customers,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},average_order_value)"


def _signed_receipt(*, run_id: str = "run-pricing-001") -> dict[str, Any]:
    payload = receipt_payload()
    payload["run"]["run_id"] = run_id
    payload["evidence"][0]["schema_field_urn"] = FIELD
    key = SigningKey("transactional-store-test", Ed25519PrivateKey.generate())
    return seal_receipt(payload, signing_keys=(key,))


def _lineage() -> FieldLineageProof:
    return FieldLineageProof(
        coverage=FieldCoverage.COMPLETE,
        rule_id="glassbox.transactional-test-lineage.v1",
        wildcard_query=False,
    )


def _change(
    *, entity_urn: str = DATASET, event_id: str = "mcl-transactional-001"
) -> NormalizedChange:
    field = FIELD if entity_urn == DATASET else f"urn:li:schemaField:({entity_urn},id)"
    return NormalizedChange(
        event_id=event_id,
        entity_urn=entity_urn,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-07T00:00:00Z",
        schema_field_urn=field,
    )


def _campaign(profile: ReceiptDependencyProfile) -> InvalidationCampaign:
    return create_campaign(_change(), (profile,))


def _write_evidence(campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
    return InvalidationWriteEvidence(
        incident_aspects=("incidentInfo", "incidentKey"),
        target_summary_verified=True,
        quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
    )


class FakeBackend:
    def __init__(self, *, fail_write: bool = False, invalid_readback: bool = False) -> None:
        self.fail_write = fail_write
        self.invalid_readback = invalid_readback
        self.upserts: list[InvalidationCampaign] = []
        self.verifications = 0
        self.tested = False

    def test_connection(self) -> None:
        self.tested = True

    def upsert_campaign(self, campaign: InvalidationCampaign) -> None:
        if self.fail_write:
            raise ConnectionError("synthetic sensitive connection details")
        self.upserts.append(campaign)

    def direct_verify(self, campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
        self.verifications += 1
        if self.invalid_readback:
            return InvalidationWriteEvidence((), False, ())
        return _write_evidence(campaign)


class RecordingRouter:
    def __init__(self, *destinations: str, fail: bool = False) -> None:
        self.destinations = tuple(destinations)
        self.fail = fail
        self.keys: list[str] = []

    def route(self, campaign: InvalidationCampaign, *, idempotency_key: str) -> tuple[str, ...]:
        del campaign
        self.keys.append(idempotency_key)
        if self.fail:
            raise ConnectionError("synthetic sensitive owner destination")
        return self.destinations


def _claim_in_process(
    database_path: str,
    campaign_id: str,
    worker_id: str,
    start: Any,
    results: Any,
) -> None:
    store = SQLiteInvalidationStore(Path(database_path))
    start.wait()
    task = store.claim(
        campaign_id,
        worker_id=worker_id,
        now_ms=1_000,
        lease_duration_ms=10_000,
    )
    results.put(task.lease_owner if task is not None else None)


def _claim_owner_routing_in_process(
    database_path: str,
    campaign_id: str,
    worker_id: str,
    start: Any,
    results: Any,
) -> None:
    store = SQLiteInvalidationStore(Path(database_path))
    start.wait()
    task = store.claim_owner_routing(
        campaign_id,
        worker_id=worker_id,
        now_ms=1_000,
        lease_duration_ms=10_000,
    )
    results.put(task.lease_owner if task is not None else None)


def test_receipt_and_reverse_index_are_atomic_idempotent_and_reopenable(tmp_path: Path) -> None:
    path = tmp_path / "invalidation.sqlite3"
    store = SQLiteInvalidationStore(path)
    receipt = _signed_receipt()

    assert store.register(receipt, field_lineage=_lineage())
    assert not store.register(receipt, field_lineage=_lineage())
    assert path.stat().st_mode & 0o777 == 0o600
    assert len(store.all_profiles()) == 1
    stored = store.get_receipt(receipt["receipt_id"])
    assert stored is not None
    stored["run"] = {}
    assert store.get_receipt(receipt["receipt_id"])["run"]["run_id"] == "run-pricing-001"
    assert len(store.candidates(_change())) == 1
    assert store.candidates(_change(entity_urn=OTHER_DATASET)) == ()
    with pytest.raises(TransactionalStoreError, match="conflicting"):
        store.register(receipt, field_lineage=FieldLineageProof())

    reopened = SQLiteInvalidationStore(path)
    report = reopened.verify_integrity()
    assert report.receipts == 1
    assert report.dependencies == 1
    assert reopened.all_profiles()[0].field_lineage == _lineage()
    assert reopened.get_receipt(receipt["receipt_id"])["receipt_id"] == receipt["receipt_id"]


def test_receipt_registration_rolls_back_if_dependency_index_insert_fails(tmp_path: Path) -> None:
    path = tmp_path / "rollback.sqlite3"
    store = SQLiteInvalidationStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_dependency
            BEFORE INSERT ON receipt_dependencies
            BEGIN
                SELECT RAISE(ABORT, 'synthetic dependency failure');
            END
            """
        )

    with pytest.raises(TransactionalStoreError, match="database write failed"):
        store.register(_signed_receipt(), field_lineage=_lineage())

    assert store.verify_integrity().receipts == 0
    assert store.verify_integrity().dependencies == 0


def test_receipt_registration_and_publication_obligation_are_atomic(tmp_path: Path) -> None:
    path = tmp_path / "publication-rollback.sqlite3"
    store = SQLiteInvalidationStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_publication
            BEFORE INSERT ON receipt_publication_outbox
            BEGIN
                SELECT RAISE(ABORT, 'synthetic publication failure');
            END
            """
        )

    with pytest.raises(TransactionalStoreError, match="database write failed"):
        store.register(_signed_receipt(), field_lineage=_lineage())

    report = store.verify_integrity()
    assert report.receipts == 0
    assert report.dependencies == 0
    assert report.receipt_publication_tasks == 0


def test_receipt_publication_obligation_is_leased_recoverable_and_sealed(
    tmp_path: Path,
) -> None:
    path = tmp_path / "publication.sqlite3"
    store = SQLiteInvalidationStore(path)
    receipt = _signed_receipt()
    receipt_id = receipt["receipt_id"]
    store.register(receipt, field_lineage=_lineage())

    ready = store.get_receipt_publication_task(receipt_id)
    assert ready is not None and ready.status is OutboxStatus.READY
    claimed = store.claim_receipt_publication(
        receipt_id, worker_id="publisher-a", now_ms=1_000, lease_duration_ms=1_000
    )
    assert claimed is not None and claimed.attempt_count == 1
    assert (
        SQLiteInvalidationStore(path).claim_receipt_publication(
            receipt_id,
            worker_id="publisher-b",
            now_ms=1_500,
            lease_duration_ms=1_000,
        )
        is None
    )
    store.release_receipt_publication(
        receipt_id, worker_id="publisher-a", error_type="ReceiptEmissionError"
    )
    reclaimed = store.claim_receipt_publication(
        receipt_id, worker_id="publisher-b", now_ms=2_000, lease_duration_ms=1_000
    )
    assert reclaimed is not None and reclaimed.attempt_count == 2
    evidence = ReceiptPublicationEvidence(
        document_urn=receipt_document_urn(receipt_id),
        aspect_names=("documentInfo", "status"),
    )
    assert store.complete_receipt_publication(receipt_id, evidence, worker_id="publisher-b")
    assert not store.complete_receipt_publication(receipt_id, evidence, worker_id="publisher-b")
    completed = store.get_receipt_publication_task(receipt_id)
    assert completed is not None
    assert completed.status is OutboxStatus.COMPLETED
    assert completed.publication_evidence == evidence
    assert (
        store.claim_receipt_publication(
            receipt_id,
            worker_id="publisher-c",
            now_ms=4_000,
            lease_duration_ms=1_000,
        )
        is None
    )
    assert store.verify_integrity().receipt_publication_tasks == 1


def test_receipt_publication_missing_or_tampered_evidence_fails_integrity(
    tmp_path: Path,
) -> None:
    path = tmp_path / "publication-corrupt.sqlite3"
    store = SQLiteInvalidationStore(path)
    receipt = _signed_receipt()
    receipt_id = receipt["receipt_id"]
    store.register(receipt, field_lineage=_lineage())
    with sqlite3.connect(path) as connection:
        connection.execute(
            "DELETE FROM receipt_publication_outbox WHERE receipt_id = ?", (receipt_id,)
        )
    with pytest.raises(TransactionalStoreError, match="no publication obligation"):
        store.verify_integrity()

    second_path = tmp_path / "publication-evidence-corrupt.sqlite3"
    second = SQLiteInvalidationStore(second_path)
    second.register(receipt, field_lineage=_lineage())
    second.claim_receipt_publication(
        receipt_id, worker_id="publisher", now_ms=1, lease_duration_ms=1_000
    )
    second.complete_receipt_publication(
        receipt_id,
        ReceiptPublicationEvidence(
            document_urn=receipt_document_urn(receipt_id),
            aspect_names=("documentInfo",),
        ),
        worker_id="publisher",
    )
    with sqlite3.connect(second_path) as connection:
        connection.execute(
            """
            UPDATE receipt_publication_outbox
            SET publication_evidence_sha256 = ? WHERE receipt_id = ?
            """,
            ("0" * 64, receipt_id),
        )
    with pytest.raises(TransactionalStoreError, match="failed its checksum"):
        second.verify_integrity()


def test_receipt_reverse_index_tampering_fails_integrity(tmp_path: Path) -> None:
    path = tmp_path / "reverse-index-corrupt.sqlite3"
    store = SQLiteInvalidationStore(path)
    store.register(_signed_receipt(), field_lineage=_lineage())
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE receipt_dependencies SET datahub_urn = ?",
            (OTHER_DATASET,),
        )

    with pytest.raises(TransactionalStoreError, match="reverse index diverges"):
        store.verify_integrity()


def test_only_one_process_claims_a_live_campaign_lease(tmp_path: Path) -> None:
    path = tmp_path / "multiprocess.sqlite3"
    store = SQLiteInvalidationStore(path)
    receipt = _signed_receipt()
    store.register(receipt, field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)

    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_claim_in_process,
            args=(str(path), campaign.campaign_id, worker, start, results),
        )
        for worker in ("worker-a", "worker-b")
    ]
    for process in processes:
        process.start()
    start.set()
    claims = [results.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert sum(item is not None for item in claims) == 1
    assert {item for item in claims if item is not None} <= {"worker-a", "worker-b"}


def test_only_one_process_claims_a_live_owner_routing_lease(tmp_path: Path) -> None:
    path = tmp_path / "multiprocess-routing.sqlite3"
    store = SQLiteInvalidationStore(path)
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)
    store.claim(campaign.campaign_id, worker_id="datahub", now_ms=1, lease_duration_ms=10)
    store.complete(campaign, _write_evidence(campaign), worker_id="datahub")

    context = multiprocessing.get_context("spawn")
    start = context.Event()
    results = context.Queue()
    processes = [
        context.Process(
            target=_claim_owner_routing_in_process,
            args=(str(path), campaign.campaign_id, worker, start, results),
        )
        for worker in ("router-a", "router-b")
    ]
    for process in processes:
        process.start()
    start.set()
    claims = [results.get(timeout=10) for _ in processes]
    for process in processes:
        process.join(timeout=10)
        assert process.exitcode == 0

    assert sum(item is not None for item in claims) == 1
    assert {item for item in claims if item is not None} <= {"router-a", "router-b"}


def test_campaign_completion_and_owner_routing_stage_roll_back_together(
    tmp_path: Path,
) -> None:
    path = tmp_path / "routing-stage-rollback.sqlite3"
    store = SQLiteInvalidationStore(path)
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)
    store.claim(campaign.campaign_id, worker_id="worker", now_ms=1, lease_duration_ms=10)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_owner_routing_stage
            BEFORE INSERT ON owner_routing_outbox
            BEGIN
                SELECT RAISE(ABORT, 'synthetic owner-routing stage failure');
            END
            """
        )

    with pytest.raises(TransactionalStoreError, match="database write failed"):
        store.complete(campaign, _write_evidence(campaign), worker_id="worker")

    task = store.get_task(campaign.campaign_id)
    assert task is not None and task.status is OutboxStatus.LEASED
    assert task.write_evidence is None
    assert store.get_owner_routing_task(campaign.campaign_id) is None
    assert [item.phase for item in store.read_audit_records()] == [AuditPhase.CLASSIFIED]


def test_expired_lease_is_recovered_and_completion_is_atomic(tmp_path: Path) -> None:
    store = SQLiteInvalidationStore(tmp_path / "leases.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    assert store.stage_campaign(campaign)

    first = store.claim(
        campaign.campaign_id,
        worker_id="worker-a",
        now_ms=1_000,
        lease_duration_ms=100,
    )
    blocked = store.claim(
        campaign.campaign_id,
        worker_id="worker-b",
        now_ms=1_050,
        lease_duration_ms=100,
    )
    recovered = store.claim(
        campaign.campaign_id,
        worker_id="worker-b",
        now_ms=1_101,
        lease_duration_ms=100,
    )

    assert first is not None and first.attempt_count == 1
    assert blocked is None
    assert recovered is not None and recovered.attempt_count == 2
    with pytest.raises(TransactionalStoreError, match="not owned"):
        store.renew(
            campaign.campaign_id,
            worker_id="worker-a",
            now_ms=1_102,
            lease_duration_ms=100,
        )

    evidence = _write_evidence(campaign)
    assert store.complete(campaign, evidence, worker_id="worker-b")
    assert not store.complete(campaign, evidence, worker_id="any-redelivery")
    task = store.get_task(campaign.campaign_id)
    assert task is not None
    assert task.status is OutboxStatus.COMPLETED
    assert task.write_evidence == evidence
    assert [item.phase for item in store.read_audit_records()] == [
        AuditPhase.CLASSIFIED,
        AuditPhase.DATAHUB_VERIFIED,
    ]


def test_transactional_action_reuses_completion_only_after_fresh_readback(tmp_path: Path) -> None:
    store = SQLiteInvalidationStore(tmp_path / "redelivery.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    backend = FakeBackend()
    first_worker = TransactionalInvalidationAction(backend, store, worker_id="worker-a")
    second_worker = TransactionalInvalidationAction(backend, store, worker_id="worker-b")

    first = first_worker.process(_change(), (profile,))
    second = second_worker.process(_change(), (profile,))

    assert first.valid and not first.reused_completion and first.emissions == 2
    assert second.valid and second.reused_completion and second.emissions == 0
    assert len(backend.upserts) == 2
    assert backend.verifications == 2
    assert [item.phase for item in store.read_audit_records()] == [
        AuditPhase.CLASSIFIED,
        AuditPhase.DATAHUB_VERIFIED,
        AuditPhase.OWNER_ROUTING_ACCEPTED,
    ]


def test_failed_write_releases_task_for_next_worker_without_sensitive_audit(
    tmp_path: Path,
) -> None:
    store = SQLiteInvalidationStore(tmp_path / "recovery.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    failing = TransactionalInvalidationAction(FakeBackend(fail_write=True), store, worker_id="bad")

    with pytest.raises(InvalidationActionError, match="writeback failed"):
        failing.process(_change(), (profile,))

    task = store.get_task(_campaign(profile).campaign_id)
    assert task is not None
    assert task.status is OutboxStatus.READY
    assert task.attempt_count == 1
    assert task.last_error_type == "ConnectionError"
    assert "sensitive" not in " ".join(item.detail for item in store.read_audit_records())

    healthy = TransactionalInvalidationAction(FakeBackend(), store, worker_id="healthy")
    report = healthy.process(_change(), (profile,))
    assert report.valid
    recovered = store.get_task(report.campaign.campaign_id)
    assert recovered is not None and recovered.attempt_count == 2
    assert [item.phase for item in store.read_audit_records()] == [
        AuditPhase.CLASSIFIED,
        AuditPhase.DATAHUB_FAILED,
        AuditPhase.DATAHUB_VERIFIED,
        AuditPhase.OWNER_ROUTING_ACCEPTED,
    ]


def test_owner_routing_obligation_is_atomic_private_and_not_repeated(tmp_path: Path) -> None:
    path = tmp_path / "routing.sqlite3"
    store = SQLiteInvalidationStore(path)
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    backend = FakeBackend()
    destination = "urn:li:corpuser:private-owner"
    router = RecordingRouter(destination)

    first = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="router-a",
        owner_router=router,
    ).process(_change(), (profile,))
    second = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="router-b",
        owner_router=router,
    ).process(_change(), (profile,))

    routing = store.get_owner_routing_task(first.campaign.campaign_id)
    assert routing is not None and routing.status is OutboxStatus.COMPLETED
    assert routing.delivery_evidence is not None
    assert routing.delivery_evidence.destination_count == 1
    assert len(routing.delivery_evidence.destination_digests) == 1
    assert destination.encode() not in path.read_bytes()
    assert first.routed_destinations == (destination,)
    assert not first.reused_routing
    assert second.routed_destinations == ()
    assert second.reused_completion and second.reused_routing
    assert router.keys == [first.campaign.campaign_id]
    assert store.verify_integrity().owner_routing_tasks == 1


def test_routing_failure_survives_after_datahub_completion_and_recovers(
    tmp_path: Path,
) -> None:
    store = SQLiteInvalidationStore(tmp_path / "routing-recovery.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    backend = FakeBackend()
    failing_router = RecordingRouter("owner:commerce", fail=True)
    failing = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="routing-failure",
        owner_router=failing_router,
    )

    with pytest.raises(InvalidationActionError, match="owner routing failed"):
        failing.process(_change(), (profile,))

    campaign = _campaign(profile)
    datahub_task = store.get_task(campaign.campaign_id)
    routing_task = store.get_owner_routing_task(campaign.campaign_id)
    assert datahub_task is not None and datahub_task.status is OutboxStatus.COMPLETED
    assert routing_task is not None and routing_task.status is OutboxStatus.READY
    assert routing_task.last_error_type == "ConnectionError"
    assert len(backend.upserts) == 2
    assert "sensitive" not in " ".join(item.detail for item in store.read_audit_records())

    healthy_router = RecordingRouter("owner:commerce")
    recovered = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="routing-recovery",
        owner_router=healthy_router,
    ).process(_change(), (profile,))

    assert recovered.valid and recovered.reused_completion and recovered.emissions == 0
    assert recovered.routed_destinations == ("owner:commerce",)
    assert len(backend.upserts) == 2
    assert backend.verifications == 2
    assert failing_router.keys == healthy_router.keys == [campaign.campaign_id]
    assert [item.phase for item in store.read_audit_records()] == [
        AuditPhase.CLASSIFIED,
        AuditPhase.DATAHUB_VERIFIED,
        AuditPhase.OWNER_ROUTING_FAILED,
        AuditPhase.OWNER_ROUTING_ACCEPTED,
    ]


def test_crash_window_retries_router_with_the_same_idempotency_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = SQLiteInvalidationStore(tmp_path / "routing-crash-window.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    backend = FakeBackend()
    router = RecordingRouter("owner:commerce")
    original_complete = store.complete_owner_routing
    failures = 1

    def fail_after_remote_acceptance(
        campaign: InvalidationCampaign,
        destinations: tuple[str, ...],
        *,
        worker_id: str,
    ) -> Any:
        nonlocal failures
        if failures:
            failures -= 1
            raise OSError("synthetic local completion failure")
        return original_complete(campaign, destinations, worker_id=worker_id)

    monkeypatch.setattr(store, "complete_owner_routing", fail_after_remote_acceptance)
    action = TransactionalInvalidationAction(
        backend,
        store,
        worker_id="crash-window",
        owner_router=router,
    )
    with pytest.raises(InvalidationActionError, match="owner routing failed"):
        action.process(_change(), (profile,))

    recovered = action.process(_change(), (profile,))
    assert recovered.valid and recovered.reused_completion
    assert router.keys == [recovered.campaign.campaign_id, recovered.campaign.campaign_id]


def test_owner_routing_lease_recovery_and_idempotent_completion(tmp_path: Path) -> None:
    store = SQLiteInvalidationStore(tmp_path / "routing-leases.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)
    store.claim(campaign.campaign_id, worker_id="datahub", now_ms=1, lease_duration_ms=10)
    store.complete(campaign, _write_evidence(campaign), worker_id="datahub")

    first = store.claim_owner_routing(
        campaign.campaign_id,
        worker_id="router-a",
        now_ms=1_000,
        lease_duration_ms=100,
    )
    blocked = store.claim_owner_routing(
        campaign.campaign_id,
        worker_id="router-b",
        now_ms=1_050,
        lease_duration_ms=100,
    )
    recovered = store.claim_owner_routing(
        campaign.campaign_id,
        worker_id="router-b",
        now_ms=1_101,
        lease_duration_ms=100,
    )

    assert first is not None and first.attempt_count == 1
    assert blocked is None
    assert recovered is not None and recovered.attempt_count == 2
    with pytest.raises(TransactionalStoreError, match="not owned"):
        store.renew_owner_routing(
            campaign.campaign_id,
            worker_id="router-a",
            now_ms=1_102,
            lease_duration_ms=100,
        )
    renewed = store.renew_owner_routing(
        campaign.campaign_id,
        worker_id="router-b",
        now_ms=1_102,
        lease_duration_ms=100,
    )
    assert renewed.lease_expires_at_ms == 1_202

    evidence = store.complete_owner_routing(
        campaign,
        ("owner:commerce",),
        worker_id="router-b",
    )
    assert evidence.destination_count == 1
    assert (
        store.complete_owner_routing(
            campaign,
            ("owner:commerce",),
            worker_id="redelivery",
        )
        == evidence
    )
    assert (
        store.claim_owner_routing(
            campaign.campaign_id,
            worker_id="redelivery",
            now_ms=2_000,
            lease_duration_ms=100,
        )
        is None
    )
    with pytest.raises(TransactionalStoreError, match="conflicting delivery evidence"):
        store.complete_owner_routing(
            campaign,
            ("owner:finance",),
            worker_id="redelivery",
        )


def test_owner_routing_store_rejects_missing_ownership_and_invalid_destinations(
    tmp_path: Path,
) -> None:
    store = SQLiteInvalidationStore(tmp_path / "routing-invalid.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])

    with pytest.raises(TransactionalStoreError, match="not staged"):
        store.claim_owner_routing(
            campaign.campaign_id,
            worker_id="router",
            now_ms=1,
            lease_duration_ms=1,
        )
    with pytest.raises(TransactionalStoreError, match="not staged"):
        store.renew_owner_routing(
            campaign.campaign_id,
            worker_id="router",
            now_ms=1,
            lease_duration_ms=1,
        )
    with pytest.raises(TransactionalStoreError, match="not staged"):
        store.release_owner_routing(campaign, worker_id="router", error_type="Failure")
    with pytest.raises(TransactionalStoreError, match="not staged"):
        store.complete_owner_routing(campaign, (), worker_id="router")

    store.stage_campaign(campaign)
    store.claim(campaign.campaign_id, worker_id="datahub", now_ms=1, lease_duration_ms=10)
    store.complete(campaign, _write_evidence(campaign), worker_id="datahub")
    with pytest.raises(TransactionalStoreError, match="now_ms"):
        store.claim_owner_routing(
            campaign.campaign_id,
            worker_id="router",
            now_ms=0,
            lease_duration_ms=1,
        )
    with pytest.raises(TransactionalStoreError, match="worker_id"):
        store.claim_owner_routing(
            campaign.campaign_id,
            worker_id="",
            now_ms=1,
            lease_duration_ms=1,
        )
    with pytest.raises(TransactionalStoreError, match="owned elsewhere"):
        store.release_owner_routing(campaign, worker_id="router", error_type="Failure")
    with pytest.raises(TransactionalStoreError, match="owned elsewhere"):
        store.complete_owner_routing(campaign, (), worker_id="router")

    store.claim_owner_routing(
        campaign.campaign_id,
        worker_id="router",
        now_ms=1,
        lease_duration_ms=10,
    )
    invalid_destinations: tuple[Any, ...] = ("",)
    with pytest.raises(TransactionalStoreError, match="destination is invalid"):
        store.complete_owner_routing(
            campaign,
            invalid_destinations,  # type: ignore[arg-type]
            worker_id="router",
        )
    with pytest.raises(TransactionalStoreError, match="duplicates"):
        store.complete_owner_routing(
            campaign,
            ("owner:commerce", "owner:commerce"),
            worker_id="router",
        )
    with pytest.raises(TransactionalStoreError, match="bounded limit"):
        store.complete_owner_routing(
            campaign,
            tuple(f"owner:{index}" for index in range(257)),
            worker_id="router",
        )
    with pytest.raises(TransactionalStoreError, match="must be a tuple"):
        store.complete_owner_routing(  # type: ignore[arg-type]
            campaign,
            ["owner:commerce"],
            worker_id="router",
        )


def test_record_checksum_corruption_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "corrupt.sqlite3"
    store = SQLiteInvalidationStore(path)
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE campaign_outbox SET material = ? WHERE campaign_id = ?",
            (b"{}", campaign.campaign_id),
        )

    with pytest.raises(TransactionalStoreError, match="checksum"):
        store.verify_integrity()
    with pytest.raises(TransactionalStoreError, match="checksum"):
        SQLiteInvalidationStore(path)


def test_unknown_database_schema_version_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "future.sqlite3"
    SQLiteInvalidationStore(path)
    with sqlite3.connect(path) as connection:
        connection.execute("UPDATE state_metadata SET value = '999' WHERE key = 'schema_version'")

    with pytest.raises(TransactionalStoreError, match="schema version"):
        SQLiteInvalidationStore(path)


def test_database_with_application_tables_but_no_schema_version_is_rejected(
    tmp_path: Path,
) -> None:
    path = tmp_path / "unversioned.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE legacy_state(value TEXT)")

    with pytest.raises(TransactionalStoreError, match="no schema version"):
        SQLiteInvalidationStore(path)


def test_integrity_rejects_missing_or_premature_owner_routing_obligations(
    tmp_path: Path,
) -> None:
    missing_path = tmp_path / "missing-routing.sqlite3"
    missing = SQLiteInvalidationStore(missing_path)
    missing.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(missing.all_profiles()[0])
    missing.stage_campaign(campaign)
    missing.claim(campaign.campaign_id, worker_id="worker", now_ms=1, lease_duration_ms=10)
    missing.complete(campaign, _write_evidence(campaign), worker_id="worker")
    with sqlite3.connect(missing_path) as connection:
        connection.execute(
            "DELETE FROM owner_routing_outbox WHERE campaign_id = ?",
            (campaign.campaign_id,),
        )
    with pytest.raises(TransactionalStoreError, match="no owner-routing obligation"):
        missing.verify_integrity()
    with pytest.raises(TransactionalStoreError, match="no owner-routing obligation"):
        missing.complete(campaign, _write_evidence(campaign), worker_id="redelivery")

    premature_path = tmp_path / "premature-routing.sqlite3"
    premature = SQLiteInvalidationStore(premature_path)
    premature.stage_campaign(campaign)
    with sqlite3.connect(premature_path) as connection:
        connection.execute(
            "INSERT INTO owner_routing_outbox(campaign_id, status) VALUES (?, 'READY')",
            (campaign.campaign_id,),
        )
    with pytest.raises(TransactionalStoreError, match="before campaign completion"):
        premature.verify_integrity()


def test_owner_routing_evidence_checksum_corruption_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "routing-corrupt.sqlite3"
    store = SQLiteInvalidationStore(path)
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)
    store.claim(campaign.campaign_id, worker_id="datahub", now_ms=1, lease_duration_ms=10)
    store.complete(campaign, _write_evidence(campaign), worker_id="datahub")
    store.claim_owner_routing(
        campaign.campaign_id,
        worker_id="router",
        now_ms=1,
        lease_duration_ms=10,
    )
    store.complete_owner_routing(campaign, ("owner:commerce",), worker_id="router")
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            UPDATE owner_routing_outbox SET delivery_evidence = ? WHERE campaign_id = ?
            """,
            (b"{}", campaign.campaign_id),
        )

    with pytest.raises(TransactionalStoreError, match="delivery evidence failed its checksum"):
        store.verify_integrity()


def test_plugin_configuration_requires_exactly_one_state_profile(tmp_path: Path) -> None:
    database = tmp_path / "state.sqlite3"
    with pytest.raises(ValidationError, match="signer_trust_policy_path"):
        GlassBoxInvalidationActionConfig(state_database_path=database)
    transactional = GlassBoxInvalidationActionConfig(
        state_database_path=database,
        require_trusted_receipt_signer=False,
    )
    assert transactional.state_database_path == database
    postgres = GlassBoxInvalidationActionConfig(
        state_postgres_dsn_env="GLASSBOX_STATE_POSTGRES_DSN",
        state_postgres_schema="glassbox_runtime",
        require_trusted_receipt_signer=False,
    )
    assert postgres.state_postgres_dsn_env == "GLASSBOX_STATE_POSTGRES_DSN"
    assert postgres.state_postgres_schema == "glassbox_runtime"

    with pytest.raises(ValidationError, match="exactly one state profile"):
        GlassBoxInvalidationActionConfig(
            state_database_path=database,
            receipt_store_path=tmp_path / "receipts.jsonl",
            audit_log_path=tmp_path / "audit.jsonl",
        )
    with pytest.raises(ValidationError, match="exactly one state profile"):
        GlassBoxInvalidationActionConfig()
    with pytest.raises(ValidationError, match="exactly one state profile"):
        GlassBoxInvalidationActionConfig(
            state_database_path=database,
            state_postgres_dsn_env="GLASSBOX_STATE_POSTGRES_DSN",
        )
    with pytest.raises(ValidationError, match="JSONL state requires both"):
        GlassBoxInvalidationActionConfig(receipt_store_path=tmp_path / "receipts.jsonl")
    with pytest.raises(ValidationError, match="must be non-empty"):
        GlassBoxInvalidationActionConfig(state_postgres_dsn_env="")
    with pytest.raises(ValidationError, match="worker_id must be non-empty"):
        GlassBoxInvalidationActionConfig(
            state_database_path=database,
            worker_id="",
            require_trusted_receipt_signer=False,
        )
    with pytest.raises(ValidationError, match="bearer_token_env must be non-empty"):
        GlassBoxInvalidationActionConfig(
            state_database_path=database,
            owner_webhook_url="https://example.test/hook",
            owner_webhook_bearer_token_env="",
            require_trusted_receipt_signer=False,
        )
    with pytest.raises(ValidationError, match="transactional state profile"):
        GlassBoxInvalidationActionConfig(
            receipt_store_path=tmp_path / "receipts.jsonl",
            audit_log_path=tmp_path / "audit.jsonl",
            owner_webhook_url="https://example.test/hook",
            require_trusted_receipt_signer=False,
        )
    with pytest.raises(ValidationError, match="requires owner_webhook_url"):
        GlassBoxInvalidationActionConfig(
            state_database_path=database,
            owner_webhook_bearer_token_env="GLASSBOX_OWNER_TOKEN",
            require_trusted_receipt_signer=False,
        )
    with pytest.raises(ValidationError, match="requires owner_webhook_url"):
        GlassBoxInvalidationActionConfig(
            state_database_path=database,
            allow_insecure_owner_webhook_http=True,
            require_trusted_receipt_signer=False,
        )


def test_plugin_factory_loads_webhook_secret_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeBackend()
    monkeypatch.setattr(
        datahub_action_module.DataHubInvalidationBackend,
        "from_graph",
        classmethod(lambda cls, graph, actor_urn: backend),
    )
    captured: dict[str, Any] = {}

    class FakeRouter:
        def __init__(self, graph: object, **kwargs: Any) -> None:
            captured["graph"] = graph
            captured.update(kwargs)

        def route(
            self,
            campaign: InvalidationCampaign,
            *,
            idempotency_key: str,
        ) -> tuple[str, ...]:
            del campaign, idempotency_key
            return ()

    monkeypatch.setattr(datahub_action_module, "DataHubOwnershipWebhookRouter", FakeRouter)
    monkeypatch.setenv("GLASSBOX_OWNER_TOKEN", "secret-from-environment")
    graph = object()
    context = SimpleNamespace(
        graph=SimpleNamespace(graph=graph),
        pipeline_name="glassbox-webhook-test",
    )
    created = datahub_action_module.GlassBoxInvalidationAction.create(
        {
            "state_database_path": str(tmp_path / "state.sqlite3"),
            "owner_webhook_url": "https://example.test/hook",
            "owner_webhook_bearer_token_env": "GLASSBOX_OWNER_TOKEN",
            "require_trusted_receipt_signer": False,
        },
        context,
    )

    assert created.config.owner_webhook_url == "https://example.test/hook"
    assert captured == {
        "graph": graph,
        "webhook_url": "https://example.test/hook",
        "bearer_token": "secret-from-environment",
        "timeout_seconds": 10.0,
        "allow_insecure_http": False,
    }

    monkeypatch.delenv("GLASSBOX_OWNER_TOKEN")
    with pytest.raises(ValueError, match="environment variable is unset"):
        datahub_action_module.GlassBoxInvalidationAction.create(
            {
                "state_database_path": str(tmp_path / "state-2.sqlite3"),
                "owner_webhook_url": "https://example.test/hook",
                "owner_webhook_bearer_token_env": "GLASSBOX_OWNER_TOKEN",
                "require_trusted_receipt_signer": False,
            },
            context,
        )


def test_plugin_factory_builds_transactional_and_legacy_profiles(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = FakeBackend()
    monkeypatch.setattr(
        datahub_action_module.DataHubInvalidationBackend,
        "from_graph",
        classmethod(lambda cls, graph, actor_urn: backend),
    )
    context = SimpleNamespace(
        graph=SimpleNamespace(graph=object()),
        pipeline_name="glassbox-factory-test",
    )

    transactional = datahub_action_module.GlassBoxInvalidationAction.create(
        {
            "state_database_path": str(tmp_path / "state.sqlite3"),
            "require_trusted_receipt_signer": False,
        },
        context,
    )
    legacy = datahub_action_module.GlassBoxInvalidationAction.create(
        {
            "receipt_store_path": str(tmp_path / "receipts.jsonl"),
            "audit_log_path": str(tmp_path / "audit.jsonl"),
            "sync_audit": False,
            "require_trusted_receipt_signer": False,
        },
        context,
    )

    assert transactional.config.state_database_path == tmp_path / "state.sqlite3"
    assert legacy.config.receipt_store_path == tmp_path / "receipts.jsonl"
    assert backend.tested
    with pytest.raises(ValueError, match="requires the pipeline datahub"):
        datahub_action_module.GlassBoxInvalidationAction.create(
            {
                "state_database_path": str(tmp_path / "unused.sqlite3"),
                "require_trusted_receipt_signer": False,
            },
            SimpleNamespace(graph=None, pipeline_name="missing-graph"),
        )

    with pytest.raises(ValueError, match="PostgreSQL DSN environment variable is unset"):
        datahub_action_module.GlassBoxInvalidationAction.create(
            {
                "state_postgres_dsn_env": "GLASSBOX_MISSING_POSTGRES_DSN",
                "require_trusted_receipt_signer": False,
            },
            context,
        )


def test_noop_campaign_completes_without_lease_or_write_evidence(tmp_path: Path) -> None:
    store = SQLiteInvalidationStore(tmp_path / "noop.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    action = TransactionalInvalidationAction(FakeBackend(), store, worker_id="noop")

    report = action.process(_change(entity_urn=OTHER_DATASET), (profile,))
    task = store.get_task(report.campaign.campaign_id)

    assert report.no_op and report.valid
    assert task is not None and task.status is OutboxStatus.COMPLETED
    assert task.write_evidence is None
    assert task.lease_owner is None
    assert len(store.list_tasks()) == 1
    assert store.get_task("gbx:invalidation:sha256:" + "0" * 64) is None


def test_claim_timeout_and_invalid_direct_readback_never_acknowledge(tmp_path: Path) -> None:
    store = SQLiteInvalidationStore(tmp_path / "timeout.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    campaign = _campaign(profile)
    store.stage_campaign(campaign)
    store.claim(
        campaign.campaign_id,
        worker_id="holder",
        now_ms=1_000_000,
        lease_duration_ms=10_000,
    )
    blocked = TransactionalInvalidationAction(
        FakeBackend(),
        store,
        worker_id="blocked",
        claim_timeout_seconds=0.01,
        claim_poll_seconds=0.001,
        wall_clock_ms=lambda: 1_000_001,
    )
    with pytest.raises(InvalidationActionError, match="leased by another worker"):
        blocked.process(_change(), (profile,))

    recovered_store = SQLiteInvalidationStore(tmp_path / "invalid-readback.sqlite3")
    invalid = TransactionalInvalidationAction(
        FakeBackend(invalid_readback=True),
        recovered_store,
        worker_id="invalid-readback",
    )
    with pytest.raises(InvalidationActionError, match="direct verification"):
        invalid.process(_change(), (profile,))
    invalid_task = recovered_store.get_task(campaign.campaign_id)
    assert invalid_task is not None and invalid_task.status is OutboxStatus.READY


def test_owner_routing_claim_timeout_preserves_verified_datahub_completion(
    tmp_path: Path,
) -> None:
    store = SQLiteInvalidationStore(tmp_path / "routing-timeout.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    profile = store.all_profiles()[0]
    campaign = _campaign(profile)
    store.stage_campaign(campaign)
    store.claim(campaign.campaign_id, worker_id="datahub", now_ms=1, lease_duration_ms=10)
    store.complete(campaign, _write_evidence(campaign), worker_id="datahub")
    store.claim_owner_routing(
        campaign.campaign_id,
        worker_id="routing-holder",
        now_ms=1_000_000,
        lease_duration_ms=10_000,
    )
    blocked = TransactionalInvalidationAction(
        FakeBackend(),
        store,
        worker_id="routing-blocked",
        claim_timeout_seconds=0.01,
        claim_poll_seconds=0.001,
        wall_clock_ms=lambda: 1_000_001,
    )

    with pytest.raises(InvalidationActionError, match="owner routing remained leased"):
        blocked.process(_change(), (profile,))

    datahub_task = store.get_task(campaign.campaign_id)
    routing_task = store.get_owner_routing_task(campaign.campaign_id)
    assert datahub_task is not None and datahub_task.status is OutboxStatus.COMPLETED
    assert routing_task is not None and routing_task.status is OutboxStatus.LEASED


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"worker_id": ""}, "worker_id"),
        ({"worker_id": "worker", "lease_duration_ms": 0}, "lease_duration_ms"),
        ({"worker_id": "worker", "claim_timeout_seconds": 0}, "claim_timeout_seconds"),
        ({"worker_id": "worker", "claim_poll_seconds": 0}, "claim_poll_seconds"),
    ],
)
def test_transactional_action_rejects_invalid_worker_timing(
    tmp_path: Path,
    kwargs: dict[str, Any],
    message: str,
) -> None:
    store = SQLiteInvalidationStore(tmp_path / f"invalid-{message}.sqlite3")
    with pytest.raises(ValueError, match=message):
        TransactionalInvalidationAction(FakeBackend(), store, **kwargs)


def test_store_rejects_invalid_paths_timing_and_claim_inputs(tmp_path: Path) -> None:
    with pytest.raises(TransactionalStoreError, match="busy_timeout"):
        SQLiteInvalidationStore(tmp_path / "invalid.sqlite3", busy_timeout_seconds=0)
    with pytest.raises(TransactionalStoreError, match="parent directory"):
        SQLiteInvalidationStore(tmp_path / "missing" / "state.sqlite3")

    target = tmp_path / "target.sqlite3"
    SQLiteInvalidationStore(target)
    link = tmp_path / "linked.sqlite3"
    link.symlink_to(target)
    with pytest.raises(TransactionalStoreError, match="symbolic link"):
        SQLiteInvalidationStore(link)

    store = SQLiteInvalidationStore(tmp_path / "inputs.sqlite3")
    with pytest.raises(TransactionalStoreError, match="not staged"):
        store.claim("missing", worker_id="worker", now_ms=1, lease_duration_ms=1)
    with pytest.raises(TransactionalStoreError, match="now_ms"):
        store.claim("missing", worker_id="worker", now_ms=0, lease_duration_ms=1)
    with pytest.raises(TransactionalStoreError, match="worker_id"):
        store.claim("missing", worker_id="", now_ms=1, lease_duration_ms=1)


def test_invalid_completion_evidence_and_manual_release_fail_closed(tmp_path: Path) -> None:
    store = SQLiteInvalidationStore(tmp_path / "evidence.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)
    store.claim(campaign.campaign_id, worker_id="worker", now_ms=1, lease_duration_ms=10)
    with pytest.raises(TransactionalStoreError, match="does not prove"):
        store.complete(
            campaign,
            InvalidationWriteEvidence((), False, ()),
            worker_id="worker",
        )
    store.release(campaign, worker_id="worker", error_type="SyntheticError")
    task = store.get_task(campaign.campaign_id)
    assert task is not None and task.status is OutboxStatus.READY
    assert task.last_error_type == "SyntheticError"
    with pytest.raises(TransactionalStoreError, match="owned elsewhere"):
        store.release(campaign, worker_id="worker", error_type="Again")


def test_missing_tasks_conflicting_campaigns_and_evidence_fail_closed(tmp_path: Path) -> None:
    store = SQLiteInvalidationStore(tmp_path / "conflicts.sqlite3")
    store.register(_signed_receipt(), field_lineage=_lineage())
    campaign = _campaign(store.all_profiles()[0])
    store.stage_campaign(campaign)
    conflicting = InvalidationCampaign(
        campaign_id=campaign.campaign_id,
        incident_urn=campaign.incident_urn,
        change=campaign.change,
        assessments=(),
    )
    with pytest.raises(TransactionalStoreError, match="conflicting outbox"):
        store.stage_campaign(conflicting)
    with pytest.raises(TransactionalStoreError, match="not staged"):
        store.renew("missing", worker_id="worker", now_ms=1, lease_duration_ms=1)
    missing_campaign = create_campaign(
        _change(event_id="mcl-transactional-missing"),
        (store.all_profiles()[0],),
    )
    with pytest.raises(TransactionalStoreError, match="not staged"):
        store.release(missing_campaign, worker_id="worker", error_type="Synthetic")

    store.claim(campaign.campaign_id, worker_id="worker", now_ms=1, lease_duration_ms=10)
    evidence = _write_evidence(campaign)
    store.complete(campaign, evidence, worker_id="worker")
    conflicting_evidence = InvalidationWriteEvidence(
        incident_aspects=("extra", "incidentInfo", "incidentKey"),
        target_summary_verified=True,
        quarantined_documents=evidence.quarantined_documents,
    )
    with pytest.raises(TransactionalStoreError, match="conflicting write evidence"):
        store.complete(campaign, conflicting_evidence, worker_id="redelivery")


def test_store_rejects_directory_and_non_database_file(tmp_path: Path) -> None:
    directory = tmp_path / "directory.sqlite3"
    directory.mkdir()
    with pytest.raises(TransactionalStoreError, match="not a regular file"):
        SQLiteInvalidationStore(directory)

    invalid = tmp_path / "invalid.sqlite3"
    invalid.write_bytes(b"not a sqlite database")
    with pytest.raises(TransactionalStoreError, match="failed to initialize"):
        SQLiteInvalidationStore(invalid)


def test_state_cli_rejects_missing_and_malformed_receipts(tmp_path: Path) -> None:
    database = tmp_path / "cli-errors.sqlite3"
    with pytest.raises(ValueError, match="parent directory"):
        state_main(
            [
                "init",
                str(tmp_path / "missing" / "state.sqlite3"),
                "--allow-untrusted-signers",
            ]
        )
    with pytest.raises(ValueError, match="regular file"):
        state_main(
            [
                "register-receipt",
                str(database),
                str(tmp_path / "absent.json"),
                "--allow-untrusted-signers",
            ]
        )

    malformed = tmp_path / "malformed.json"
    malformed.write_text("{")
    with pytest.raises(ValueError, match="not valid JSON"):
        state_main(
            [
                "register-receipt",
                str(database),
                str(malformed),
                "--allow-untrusted-signers",
            ]
        )
    non_object = tmp_path / "array.json"
    non_object.write_text("[]")
    with pytest.raises(ValueError, match="JSON object"):
        state_main(
            [
                "register-receipt",
                str(database),
                str(non_object),
                "--allow-untrusted-signers",
            ]
        )


def test_state_cli_initializes_registers_and_reports_without_receipt_body(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "operator.sqlite3"
    receipt_path = tmp_path / "receipt.json"
    receipt = _signed_receipt()
    receipt_path.write_text(json.dumps(receipt))

    assert state_main(["init", str(database), "--allow-untrusted-signers"]) == 0
    capsys.readouterr()
    assert (
        state_main(
            [
                "register-receipt",
                str(database),
                str(receipt_path),
                "--field-coverage",
                "COMPLETE",
                "--field-rule",
                "glassbox.cli-test.v1",
                "--wildcard-query",
                "false",
                "--allow-untrusted-signers",
            ]
        )
        == 0
    )
    registration = json.loads(capsys.readouterr().out)
    assert registration["registration"] == {
        "receipt_id": receipt["receipt_id"],
        "inserted": True,
    }
    assert "receipt" not in registration["registration"]
    assert registration["database"]["receipt_publication_tasks"] == 1
    assert registration["receipt_publication_outbox"] == [
        {
            "attempt_count": 0,
            "document_urn": None,
            "last_error_type": None,
            "receipt_id": receipt["receipt_id"],
            "status": "READY",
        }
    ]
    assert state_main(["verify", str(database), "--allow-untrusted-signers"]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["valid"]
    assert verified["database"]["receipts"] == 1
