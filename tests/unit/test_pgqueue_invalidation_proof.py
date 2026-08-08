"""Offline contracts for the guarded PostgreSQL queue recovery proof."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from datahub.pgqueue.config import PgQueueConnectionConfig
from datahub.pgqueue.repository import PgQueueMessageHandle
from examples.end_to_end_broker_invalidation import _pipeline_config
from examples.end_to_end_pgqueue_invalidation import (
    PGQUEUE_DDL_COMMIT,
    TOPIC,
    OneShotPgQueueAckFailure,
    _pgqueue_pipeline_config,
)


def _queue() -> PgQueueConnectionConfig:
    return PgQueueConnectionConfig.model_validate(
        {
            "host_port": "127.0.0.1:55434",
            "database": "glassbox",
            "username": "glassbox",
            "password": "local-proof",
            "sslmode": "disable",
            "queue_schema": "queue",
            "table_prefix": "metadata_queue",
            "topic_defaults": {
                "partition_count": 1,
                "visibility_timeout_seconds": 8,
            },
        }
    )


def test_pgqueue_pipeline_uses_official_source_and_one_precise_mcl_route(tmp_path: Path) -> None:
    base = _pipeline_config(
        name="glassbox-pgqueue-contract",
        server="http://localhost:8080",
        token=None,
        bootstrap="localhost:9092",
        schema_registry_url="http://localhost:8080/schema-registry/api/",
        state_dir=tmp_path,
        owner_webhook_url="http://127.0.0.1:9999/glassbox-owner-events",
        signer_trust_policy_path=tmp_path / "trusted-signers.json",
    )

    config = _pgqueue_pipeline_config(
        base,
        queue=_queue(),
        schema_registry_url="http://localhost:8080/schema-registry/api/",
        visibility_seconds=8,
    )

    assert config["source"]["type"] == "pg_queue"
    source = config["source"]["config"]
    assert source["topic_routes"] == {"mcl": TOPIC}
    assert source["payload_kind_by_route_key"] == {"mcl": "mcl"}
    assert source["visibility_timeout_seconds"] == 8
    assert source["batch_size"] == 1
    assert source["poll_interval_seconds"] == 0.1
    assert source["queue"]["queue_schema"] == "queue"
    assert source["queue"]["table_prefix"] == "metadata_queue"
    assert source["queue"]["password"].get_secret_value() == "local-proof"


def test_pgqueue_ack_failure_is_armed_and_fails_exactly_once() -> None:
    class Consumer:
        def __init__(self) -> None:
            self.acks = 0

        def ack(self, handles: object) -> int:
            del handles
            self.acks += 1
            return 1

        def lock_owner(self) -> str:
            return "delegated"

    consumer = Consumer()
    fault = OneShotPgQueueAckFailure(consumer)
    handles: tuple[PgQueueMessageHandle, ...] = ()

    assert fault.ack(handles) == 1
    assert fault.lock_owner() == "delegated"
    fault.arm()
    with pytest.raises(RuntimeError, match="before pgQueue acknowledgement transaction"):
        fault.ack(handles)
    assert fault.ack(handles) == 1
    assert consumer.acks == 2
    assert fault.ack_calls == 3
    assert fault.injected_failures == 1

    with pytest.raises(RuntimeError, match="only be armed once"):
        fault.arm()


def test_pgqueue_schema_fixture_pins_upstream_tables_and_proof_partition() -> None:
    ddl = (Path(__file__).parents[2] / "examples" / "datahub_pgqueue_v001_compat.sql").read_text(
        encoding="utf-8"
    )

    assert PGQUEUE_DDL_COMMIT in ddl
    for suffix in (
        "content_type",
        "topic",
        "consumer_offset",
        "message",
        "message_group_lease",
        "consumer_registration",
    ):
        assert f"metadata_queue_{suffix}" in ddl
    assert "PARTITION BY RANGE (enqueued_at)" in ddl
    assert "PARTITION OF metadata_queue_message DEFAULT" in ddl
    assert "FOREIGN KEY (message_id, message_enqueued_at)" in ddl


def test_pgqueue_live_report_proves_visibility_ack_and_fresh_restart() -> None:
    path = (
        Path(__file__).parents[2]
        / "docs"
        / "compatibility"
        / "datahub-1.6.0-pgqueue-invalidation.live.json"
    )
    report = json.loads(path.read_text(encoding="utf-8"))

    assert report["contract"] == "glassbox.datahub-pgqueue-invalidation-live-proof.v1"
    assert report["valid"] is True
    assert report["transport"]["scope"]["pgqueue_delivery"] == "PROVEN"
    assert report["first_process"]["queue_offset_after_failed_ack"] == 0
    assert report["first_process"]["lease_active"] is True
    recovery = report["same_event_recovery"]
    assert recovery["restart_blocked_before_visibility_expiry"] is True
    assert recovery["same_queue_handle"] is True
    assert recovery["reused_completion"] is True
    assert recovery["emissions"] == 0
    assert recovery["ack_marker_persisted"] is True
    assert recovery["queue_offset_after_ack"] == 1
    assert recovery["fresh_restart_empty"] is True

    serialized = path.read_text(encoding="utf-8").lower()
    for forbidden in ("glassbox-proof", "password", "postgresql://", "private/tmp"):
        assert forbidden not in serialized
