"""Offline contracts for the guarded Kafka invalidation proof."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from examples.end_to_end_broker_invalidation import (
    OneShotKafkaCommitFailure,
    _pipeline_config,
)
from examples.end_to_end_invalidation import _schema


def test_broker_proof_pipeline_uses_sync_commit_and_precise_mcl_filter(tmp_path: Path) -> None:
    config = _pipeline_config(
        name="glassbox-broker-contract",
        server="http://localhost:8080",
        token=None,
        bootstrap="localhost:9092",
        schema_registry_url="http://localhost:8080/schema-registry/api/",
        state_dir=tmp_path,
        owner_webhook_url="http://127.0.0.1:9999/glassbox-owner-events",
        signer_trust_policy_path=tmp_path / "trusted-signers.json",
    )

    source = config["source"]["config"]
    assert source["async_commit_enabled"] is False
    assert source["connection"]["consumer_config"] == {"auto.offset.reset": "latest"}
    assert source["connection"]["schema_registry_url"].endswith("/schema-registry/api/")
    predicates = config["filters"][0]["config"]["filter"]["MetadataChangeLogEvent_v1"]
    assert predicates["event"] == [
        {
            "entityType": "dataset",
            "entityUrn": ("urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"),
            "aspectName": "schemaMetadata",
        }
    ]
    assert config["action"]["type"] == "glassbox_invalidation"
    assert config["action"]["config"]["state_database_path"] == str(
        tmp_path / "invalidation.sqlite3"
    )
    assert config["action"]["config"]["signer_trust_policy_path"] == str(
        tmp_path / "trusted-signers.json"
    )
    assert config["action"]["config"]["owner_webhook_url"].startswith("http://127.0.0.1:")
    assert config["action"]["config"]["allow_insecure_owner_webhook_http"] is True
    assert config["datahub"] == {"server": "http://localhost:8080"}
    assert config["options"]["retry_count"] == 1


def test_schema_builder_can_create_policy_safe_readiness_field() -> None:
    schema = _schema(
        native_type="VARCHAR",
        numeric=False,
        time_ms=1786190400000,
        include_unrelated=True,
        unrelated_field_path="broker_ready_note",
    )
    raw_schema = json.loads(schema.platformSchema.rawSchema)

    assert [field.fieldPath for field in schema.fields] == [
        "average_order_value",
        "broker_ready_note",
    ]
    assert [field["name"] for field in raw_schema["fields"]] == [
        "average_order_value",
        "broker_ready_note",
    ]


def test_commit_failure_is_inert_until_armed_then_fails_exactly_once() -> None:
    class Consumer:
        def __init__(self) -> None:
            self.commits = 0

        def commit(self, marker: str) -> str:
            self.commits += 1
            return marker

        def assignment(self) -> tuple[int, ...]:
            return (1,)

    consumer = Consumer()
    fault = OneShotKafkaCommitFailure(consumer)

    assert fault.commit("readiness") == "readiness"
    assert fault.assignment() == (1,)
    fault.arm()
    for _ in range(3):
        with pytest.raises(RuntimeError, match="before synchronous Kafka broker commit"):
            fault.commit("material")
    assert fault.commit("recovery") == "recovery"
    assert consumer.commits == 2
    assert fault.commit_calls == 5
    assert fault.injected_failures == 3

    with pytest.raises(RuntimeError, match="only be armed once"):
        fault.arm()


def test_kafka_live_report_proves_uncommitted_same_offset_recovery() -> None:
    report = json.loads(
        (
            Path(__file__).parents[2]
            / "docs"
            / "compatibility"
            / "datahub-1.6.0-kafka-invalidation.live.json"
        ).read_text(encoding="utf-8")
    )

    assert report["contract"] == "glassbox.datahub-kafka-invalidation-live-proof.v2"
    assert report["valid"] is True
    assert report["transport"]["scope"]["ack_failure_recovery"] == "PROVEN"
    assert report["material_change"]["acknowledged_after_first_process"] is False
    assert report["material_change"]["pipeline_action_stats"]["failed_ack_count"] == 1
    recovery = report["same_event_recovery"]
    assert recovery["same_topic_partition_offset"] is True
    assert recovery["reused_completion"] is True
    assert recovery["emissions"] == 0
    assert recovery["fresh_direct_readback"] is True
    assert recovery["acknowledged"] is True
