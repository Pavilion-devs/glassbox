"""Real PostgreSQL recovery workflow, concurrency, and restart tests."""

from __future__ import annotations

import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

import psycopg
import pytest
from psycopg import sql

from glassbox_invalidation.postgres_store import PostgresInvalidationStore
from glassbox_policy import FieldCoverage, FieldLineageProof
from glassbox_replay import (
    RecoveryArtifacts,
    RecoveryEffectEvidence,
    RecoveryOperation,
    RecoveryStage,
    build_replay_diff,
)
from glassbox_replay.postgres_recovery import (
    POSTGRES_RECOVERY_SCHEMA_VERSION,
    PostgresRecoveryStore,
    RecoveryStoreError,
)
from tests.unit.test_recovery_closure import _artifacts, _source

POSTGRES_DSN = os.getenv("GLASSBOX_TEST_POSTGRES_DSN")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not POSTGRES_DSN,
        reason="GLASSBOX_TEST_POSTGRES_DSN is not configured",
    ),
]


@pytest.fixture
def recovery_state() -> tuple[Any, ...]:
    if POSTGRES_DSN is None:  # pragma: no cover - skip marker owns this branch
        raise AssertionError("PostgreSQL test DSN is absent")
    schema = f"gbx_recovery_{uuid.uuid4().hex}"
    invalidation = PostgresInvalidationStore(POSTGRES_DSN, schema=schema)
    try:
        (
            source,
            task,
            bundle,
            authorization,
            trusted,
            execution,
            replay_receipt,
            supersession,
            closure,
        ) = _artifacts()
        assert invalidation.register(
            source,
            field_lineage=FieldLineageProof(
                FieldCoverage.COMPLETE,
                "glassbox.closure-test.v1",
                False,
            ),
        )
        assert invalidation.stage_campaign(task.campaign)
        claimed = invalidation.claim(
            task.campaign.campaign_id,
            worker_id="invalidation-worker",
            now_ms=1,
            lease_duration_ms=60_000,
        )
        assert claimed is not None and task.write_evidence is not None
        assert invalidation.complete(
            task.campaign,
            task.write_evidence,
            worker_id="invalidation-worker",
        )
        authoritative = invalidation.get_task(task.campaign.campaign_id)
        assert authoritative == task
        diff = build_replay_diff(
            source,
            replay_receipt,
            source_output=_source()[2],
            replay_output=execution.output,
        )
        artifacts = RecoveryArtifacts.from_domain(
            execution,
            replay_receipt,
            diff,
            supersession,
            closure,
        )
        recovery = PostgresRecoveryStore(
            POSTGRES_DSN,
            invalidation,
            schema=schema,
        )
        assert recovery.stage_authorized(
            authorization,
            bundle,
            evaluated_at="2026-08-08T12:05:00Z",
            trusted_signer_fingerprints=trusted,
        )
        yield (
            schema,
            invalidation,
            recovery,
            source,
            task,
            authorization,
            trusted,
            bundle,
            artifacts,
        )
    finally:
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )


def _evidence(
    operation: RecoveryOperation,
    campaign_id: str,
    artifact_id: str,
    *,
    recorded_at: str,
) -> RecoveryEffectEvidence:
    return RecoveryEffectEvidence.create(
        operation=operation,
        campaign_id=campaign_id,
        artifact_id=artifact_id,
        target_id=f"urn:li:document:{operation.value.lower()}",
        aspect_names=("documentInfo",),
        emission_count=2,
        write_performed=True,
        readback_verified=True,
        recorded_at=recorded_at,
    )


def test_postgres_recovery_persists_full_restart_safe_state_machine(
    recovery_state: tuple[Any, ...],
) -> None:
    assert POSTGRES_DSN is not None
    (
        schema,
        invalidation,
        recovery,
        source,
        task,
        authorization,
        trusted,
        bundle,
        artifacts,
    ) = recovery_state
    campaign_id = task.campaign.campaign_id
    assert not recovery.stage_authorized(
        authorization,
        bundle,
        evaluated_at="2026-08-08T12:05:00Z",
        trusted_signer_fingerprints=trusted,
    )

    def claim(index: int) -> Any:
        worker_store = PostgresRecoveryStore(
            POSTGRES_DSN,
            invalidation,
            schema=schema,
            initialize_schema=False,
        )
        return worker_store.claim(
            campaign_id,
            worker_id=f"execution-worker-{index}",
            now_ms=index + 1,
            lease_duration_ms=60_000,
        )

    with ThreadPoolExecutor(max_workers=8) as pool:
        claims = tuple(pool.map(claim, range(8)))
    winners = tuple(item for item in claims if item is not None)
    assert len(winners) == 1
    winner = winners[0]
    assert winner.lease_operation is RecoveryOperation.EXECUTE_ISOLATED_REPLAY
    assert recovery.complete_execution(
        campaign_id,
        artifacts,
        worker_id=str(winner.lease_owner),
    )
    assert not recovery.complete_execution(
        campaign_id,
        artifacts,
        worker_id="uncertain-old-worker",
    )

    restarted = PostgresRecoveryStore(
        POSTGRES_DSN,
        invalidation,
        schema=schema,
        initialize_schema=False,
    )
    execution_done = restarted.get(campaign_id)
    assert execution_done is not None
    assert execution_done.stage is RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED
    assert execution_done.artifacts == artifacts
    assert invalidation.get_receipt(source["receipt_id"]) == source

    replay_claim = restarted.claim(
        campaign_id,
        worker_id="replay-publisher",
        now_ms=10,
        lease_duration_ms=60_000,
    )
    assert replay_claim is not None
    replay_evidence = _evidence(
        RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
        campaign_id,
        str(artifacts.replay_receipt["receipt_id"]),
        recorded_at="2026-08-08T12:06:00Z",
    )
    assert restarted.complete_effect(
        campaign_id,
        replay_evidence,
        worker_id="replay-publisher",
    )
    assert not restarted.complete_effect(
        campaign_id,
        replay_evidence,
        worker_id="uncertain-old-worker",
    )
    conflicting_replay_evidence = _evidence(
        RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
        campaign_id,
        str(artifacts.replay_receipt["receipt_id"]),
        recorded_at="2026-08-08T12:06:01Z",
    )
    with pytest.raises(RecoveryStoreError, match="conflicting effect evidence"):
        restarted.complete_effect(
            campaign_id,
            conflicting_replay_evidence,
            worker_id="uncertain-old-worker",
        )

    supersession_claim = restarted.claim(
        campaign_id,
        worker_id="supersession-publisher",
        now_ms=20,
        lease_duration_ms=60_000,
    )
    assert supersession_claim is not None
    supersession_evidence = _evidence(
        RecoveryOperation.PUBLISH_SUPERSESSION,
        campaign_id,
        artifacts.supersession.supersession_id,
        recorded_at="2026-08-08T12:06:30Z",
    )
    assert restarted.complete_effect(
        campaign_id,
        supersession_evidence,
        worker_id="supersession-publisher",
    )

    closure_claim = restarted.claim(
        campaign_id,
        worker_id="incident-closer",
        now_ms=30,
        lease_duration_ms=60_000,
    )
    assert closure_claim is not None
    closure_evidence = _evidence(
        RecoveryOperation.CLOSE_INCIDENT,
        campaign_id,
        artifacts.closure.closure_id,
        recorded_at="2026-08-08T12:07:00Z",
    )
    assert restarted.complete_effect(
        campaign_id,
        closure_evidence,
        worker_id="incident-closer",
    )

    closed = restarted.get(campaign_id)
    assert closed is not None and closed.valid
    assert closed.stage is RecoveryStage.INCIDENT_CLOSED
    assert closed.next_operation is None
    assert closed.artifacts is not None
    assert closed.artifacts.supersession.supersession_id == artifacts.supersession.supersession_id
    assert closed.artifacts.closure.closure_id == artifacts.closure.closure_id
    assert (
        restarted.claim(
            campaign_id,
            worker_id="late-worker",
            now_ms=40,
            lease_duration_ms=60_000,
        )
        is None
    )
    assert restarted.list() == (closed,)
    events = restarted.read_events(campaign_id)
    assert restarted.read_events() == events
    assert [item.to_stage for item in events] == list(RecoveryStage)
    assert all(item.valid for item in events)
    assert all(item.to_dict()["event_id"] == item.event_id for item in events)
    assert restarted.verify_integrity().closed_workflows == 1


def test_postgres_recovery_uses_server_clock_for_lease_expiry(
    recovery_state: tuple[Any, ...],
) -> None:
    _schema, _invalidation, recovery, _source_value, task, *_rest = recovery_state
    campaign_id = task.campaign.campaign_id
    first = recovery.claim(
        campaign_id,
        worker_id="lease-owner",
        now_ms=9_999_999_999_999,
        lease_duration_ms=100,
    )
    assert first is not None
    assert (
        recovery.claim(
            campaign_id,
            worker_id="clock-skew-worker",
            now_ms=9_999_999_999_999,
            lease_duration_ms=100,
        )
        is None
    )
    time.sleep(0.15)
    recovered = recovery.claim(
        campaign_id,
        worker_id="recovery-worker",
        now_ms=1,
        lease_duration_ms=1_000,
    )
    assert recovered is not None and recovered.lease_owner == "recovery-worker"
    recovery.release(
        campaign_id,
        worker_id="recovery-worker",
        error_type="SyntheticFailure",
    )
    released = recovery.get(campaign_id)
    assert released is not None
    assert released.stage is RecoveryStage.AUTHORIZED
    assert released.last_error_type == "SyntheticFailure"
    renewed_claim = recovery.claim(
        campaign_id,
        worker_id="renew-worker",
        now_ms=1,
        lease_duration_ms=1_000,
    )
    assert renewed_claim is not None
    renewed = recovery.renew(
        campaign_id,
        worker_id="renew-worker",
        now_ms=1,
        lease_duration_ms=2_000,
    )
    assert renewed.lease_expires_at_ms is not None
    assert renewed.lease_expires_at_ms > int(time.time() * 1_000)


def test_postgres_recovery_rejects_out_of_order_and_corrupt_state(
    recovery_state: tuple[Any, ...],
) -> None:
    (
        _schema,
        _invalidation,
        recovery,
        _source_value,
        task,
        _authorization,
        _trusted,
        _bundle,
        artifacts,
    ) = recovery_state
    campaign_id = task.campaign.campaign_id
    wrong = _evidence(
        RecoveryOperation.PUBLISH_SUPERSESSION,
        campaign_id,
        "gbx:replay-supersession:sha256:" + "0" * 64,
        recorded_at="2026-08-08T12:06:00Z",
    )
    with pytest.raises(RecoveryStoreError, match="out of order"):
        recovery.complete_effect(campaign_id, wrong, worker_id="nobody")
    with pytest.raises(RecoveryStoreError, match="positive"):
        recovery.claim(
            campaign_id,
            worker_id="worker",
            now_ms=0,
            lease_duration_ms=1,
        )
    with pytest.raises(RecoveryStoreError, match="worker_id"):
        recovery.claim(
            campaign_id,
            worker_id="",
            now_ms=1,
            lease_duration_ms=1,
        )
    claimed = recovery.claim(
        campaign_id,
        worker_id="execution-worker",
        now_ms=1,
        lease_duration_ms=60_000,
    )
    assert claimed is not None
    with pytest.raises(RecoveryStoreError, match="owned"):
        recovery.renew(
            campaign_id,
            worker_id="wrong-worker",
            now_ms=1,
            lease_duration_ms=1,
        )
    with pytest.raises(RecoveryStoreError, match="invalid"):
        recovery.complete_execution(
            campaign_id,
            replace(artifacts, artifact_set_id="invalid"),
            worker_id="execution-worker",
        )
    assert recovery.complete_execution(
        campaign_id,
        artifacts,
        worker_id="execution-worker",
    )
    replay_claim = recovery.claim(
        campaign_id,
        worker_id="replay-worker",
        now_ms=1,
        lease_duration_ms=60_000,
    )
    assert replay_claim is not None
    wrong_artifact = _evidence(
        RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
        campaign_id,
        "gbx:receipt:sha256:" + "0" * 64,
        recorded_at="2026-08-08T12:06:00Z",
    )
    with pytest.raises(RecoveryStoreError, match="wrong artifact"):
        recovery.complete_effect(
            campaign_id,
            wrong_artifact,
            worker_id="replay-worker",
        )
    invalid_evidence = replace(wrong_artifact, readback_verified=False)
    with pytest.raises(RecoveryStoreError, match="evidence is invalid"):
        recovery.complete_effect(
            campaign_id,
            invalid_evidence,
            worker_id="replay-worker",
        )
    recovery.release(
        campaign_id,
        worker_id="replay-worker",
        error_type="ExpectedTestRelease",
    )
    with recovery._transaction() as cursor:
        cursor.execute(
            """
            UPDATE recovery_jobs SET job_material_sha256 = %s
            WHERE campaign_id = %s
            """,
            ("0" * 64, campaign_id),
        )
    with pytest.raises(RecoveryStoreError, match="checksum"):
        recovery.get(campaign_id)


def test_postgres_recovery_configuration_fails_closed() -> None:
    class Authority:
        schema = "glassbox"

        def get_task(self, campaign_id: str) -> None:
            del campaign_id

        def get_receipt(self, receipt_id: str) -> None:
            del receipt_id

    with pytest.raises(RecoveryStoreError, match="DSN"):
        PostgresRecoveryStore("", Authority())
    with pytest.raises(RecoveryStoreError, match="schema name"):
        PostgresRecoveryStore("unused", Authority(), schema="unsafe-schema")
    with pytest.raises(RecoveryStoreError, match="one schema"):
        PostgresRecoveryStore("unused", Authority(), schema="different")
    with pytest.raises(RecoveryStoreError, match="connect_timeout"):
        PostgresRecoveryStore("unused", Authority(), connect_timeout_seconds=0)
    with pytest.raises(RecoveryStoreError, match="failed to connect"):
        PostgresRecoveryStore(
            "postgresql://glassbox:synthetic@127.0.0.1:1/glassbox",
            Authority(),
            connect_timeout_seconds=1,
        )


def test_postgres_recovery_refuses_missing_source_and_untrusted_authorization(
    recovery_state: tuple[Any, ...],
) -> None:
    (
        _schema,
        invalidation,
        recovery,
        _source_value,
        task,
        authorization,
        _trusted,
        bundle,
        _artifacts_value,
    ) = recovery_state
    with pytest.raises(RecoveryStoreError, match="live-state verification"):
        recovery.stage_authorized(
            authorization,
            bundle,
            evaluated_at="2026-08-08T12:05:00Z",
            trusted_signer_fingerprints={"nobody": "0" * 64},
        )
    missing_source = replace(authorization, source_receipt_id="gbx:receipt:sha256:" + "0" * 64)
    with pytest.raises(RecoveryStoreError, match="source state"):
        recovery.stage_authorized(
            missing_source,
            bundle,
            evaluated_at="2026-08-08T12:05:00Z",
            trusted_signer_fingerprints={"nobody": "0" * 64},
        )
    other_schema = f"gbx_empty_recovery_{uuid.uuid4().hex}"
    empty = PostgresInvalidationStore(POSTGRES_DSN or "", schema=other_schema)
    try:
        empty_recovery = PostgresRecoveryStore(
            POSTGRES_DSN or "",
            empty,
            schema=other_schema,
        )
        with pytest.raises(RecoveryStoreError, match="source state"):
            empty_recovery.stage_authorized(
                authorization,
                bundle,
                evaluated_at="2026-08-08T12:05:00Z",
                trusted_signer_fingerprints={},
            )
        assert empty_recovery.get(task.campaign.campaign_id) is None
    finally:
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(other_schema))
            )
    assert invalidation.get_task(task.campaign.campaign_id) is not None


def test_postgres_recovery_integrity_rejects_incomplete_event_history(
    recovery_state: tuple[Any, ...],
) -> None:
    _schema, _invalidation, recovery, _source_value, task, *_rest = recovery_state
    with recovery._transaction() as cursor:
        cursor.execute(
            """
            DELETE FROM recovery_events
            WHERE workflow_id = (
                SELECT workflow_id FROM recovery_jobs WHERE campaign_id = %s
            )
            """,
            (task.campaign.campaign_id,),
        )
    with pytest.raises(RecoveryStoreError, match="event history is incomplete"):
        recovery.verify_integrity()
    with pytest.raises(RecoveryStoreError, match="not staged"):
        recovery.claim(
            "gbx:invalidation-campaign:sha256:" + "0" * 64,
            worker_id="worker",
            now_ms=1,
            lease_duration_ms=1,
        )


def test_postgres_recovery_bootstrap_and_schema_versions_fail_closed() -> None:
    assert POSTGRES_DSN is not None

    class Authority:
        def __init__(self, schema: str) -> None:
            self.schema = schema

        def get_task(self, campaign_id: str) -> None:
            del campaign_id

        def get_receipt(self, receipt_id: str) -> None:
            del receipt_id

    absent_schema = f"gbx_recovery_absent_{uuid.uuid4().hex}"
    with pytest.raises(RecoveryStoreError, match="invalidation state"):
        PostgresRecoveryStore(
            POSTGRES_DSN,
            Authority(absent_schema),
            schema=absent_schema,
        )

    schema = f"gbx_recovery_bootstrap_{uuid.uuid4().hex}"
    invalidation = PostgresInvalidationStore(POSTGRES_DSN, schema=schema)
    try:
        with pytest.raises(RecoveryStoreError, match="not initialized"):
            PostgresRecoveryStore(
                POSTGRES_DSN,
                invalidation,
                schema=schema,
                initialize_schema=False,
            )
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("CREATE TABLE {}.recovery_orphan(id INTEGER)").format(
                    sql.Identifier(schema)
                )
            )
        with pytest.raises(RecoveryStoreError, match="no version"):
            PostgresRecoveryStore(POSTGRES_DSN, invalidation, schema=schema)
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP TABLE {}.recovery_orphan").format(sql.Identifier(schema))
            )
        recovery = PostgresRecoveryStore(POSTGRES_DSN, invalidation, schema=schema)
        with recovery._transaction() as cursor:
            cursor.execute("SELECT value FROM recovery_state_metadata WHERE key = 'schema_version'")
            assert cursor.fetchone()["value"] == POSTGRES_RECOVERY_SCHEMA_VERSION
            cursor.execute(
                """
                UPDATE recovery_state_metadata SET value = '1'
                WHERE key = 'schema_version'
                """
            )
        with pytest.raises(RecoveryStoreError, match="schema version"):
            PostgresRecoveryStore(
                POSTGRES_DSN,
                invalidation,
                schema=schema,
                initialize_schema=False,
            )
    finally:
        with psycopg.connect(POSTGRES_DSN, autocommit=True) as connection:
            connection.execute(
                sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
            )
