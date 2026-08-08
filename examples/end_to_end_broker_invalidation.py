"""Live proof: GMS -> Kafka -> DataHub Actions -> GlassBox -> verified DataHub state."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from confluent_kafka import Consumer, TopicPartition
from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from datahub.metadata.schema_classes import OwnerClass, OwnershipClass
from datahub.metadata.urns import SchemaFieldUrn
from datahub_actions.event.event_envelope import EventEnvelope
from datahub_actions.pipeline.pipeline import Pipeline
from examples.deterministic_pricing_agent import ORDERS_URN
from examples.end_to_end_invalidation import FIELD_URN, _emit_schema, _schema
from examples.end_to_end_receipt import (
    build_signed_receipt,
    demo_signer_trust_policy,
    demo_signing_key,
)

from glassbox_compiler import LiveReceiptPipeline, VerifiedURNResolver
from glassbox_datahub import DataHubReceiptBackend, ReceiptEmitter
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_invalidation import (
    OutboxStatus,
    SQLiteInvalidationStore,
    normalize_metadata_change_log,
)
from glassbox_invalidation.datahub_action import GlassBoxInvalidationAction
from glassbox_policy import ChangeKind, FieldCoverage, FieldLineageProof, NormalizedChange

TOPIC = "MetadataChangeLog_Versioned_v1"
BASELINE_TIME_MS = 1786190400000
MATERIAL_TIME_MS = 1786194000000
NEGATIVE_TIME_MS = 1786197600000
PROOF_OWNER_URN = "urn:li:corpuser:glassbox-proof-owner"


@dataclass(frozen=True)
class Delivery:
    """Broker coordinates captured from a matching real Actions envelope."""

    topic: str
    partition: int
    offset: int

    @classmethod
    def from_envelope(cls, event: EventEnvelope) -> Delivery:
        kafka = event.meta.get("kafka")
        if not isinstance(kafka, dict):
            raise RuntimeError("real Kafka delivery did not include Actions broker metadata")
        topic = kafka.get("topic")
        partition = kafka.get("partition")
        offset = kafka.get("offset")
        if (
            not isinstance(topic, str)
            or isinstance(partition, bool)
            or not isinstance(partition, int)
            or isinstance(offset, bool)
            or not isinstance(offset, int)
        ):
            raise RuntimeError("Actions Kafka metadata has an invalid shape")
        return cls(topic=topic, partition=partition, offset=offset)


class OwnerWebhookCapture:
    """Loopback-only receiver proving one bounded idempotent webhook acceptance."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        capture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                if length <= 0 or length > 65_536:
                    self.send_error(400)
                    return
                payload = json.loads(self.rfile.read(length))
                capture.requests.append(
                    {
                        "path": self.path,
                        "idempotency_key": self.headers.get("Idempotency-Key"),
                        "payload": payload,
                    }
                )
                self.send_response(202)
                self.end_headers()
                self.wfile.write(b"accepted")

            def log_message(self, message_format: str, *args: object) -> None:
                del message_format, args

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="glassbox-owner-webhook-proof",
            daemon=True,
        )

    @property
    def url(self) -> str:
        port = self._server.server_address[1]
        return f"http://127.0.0.1:{port}/glassbox-owner-events"

    def __enter__(self) -> OwnerWebhookCapture:
        self._thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        del args
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3.0)


class OneShotKafkaCommitFailure:
    """Fail every retry call in one explicitly armed synchronous acknowledgement."""

    def __init__(self, consumer: Any, *, commit_attempts_per_ack: int = 3) -> None:
        if commit_attempts_per_ack < 1:
            raise ValueError("commit_attempts_per_ack must be positive")
        self._consumer = consumer
        self._commit_attempts_per_ack = commit_attempts_per_ack
        self._failures_remaining = 0
        self.commit_calls = 0
        self.injected_failures = 0

    def arm(self) -> None:
        if self._failures_remaining or self.injected_failures:
            raise RuntimeError("Kafka commit fault may only be armed once")
        self._failures_remaining = self._commit_attempts_per_ack

    def commit(self, *args: Any, **kwargs: Any) -> Any:
        self.commit_calls += 1
        if self._failures_remaining:
            self._failures_remaining -= 1
            self.injected_failures += 1
            raise RuntimeError("intentional failure before synchronous Kafka broker commit")
        return self._consumer.commit(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._consumer, name)


class ProbeAction:
    """Bounded proof wrapper; production behavior remains in the installed plugin."""

    def __init__(
        self,
        inner: GlassBoxInvalidationAction,
        source: Any,
        *,
        expected_kind: ChangeKind,
        expected_field_urn: str,
        failures_before_success: int = 0,
        on_target_success: Any | None = None,
    ) -> None:
        self.inner = inner
        self.source = source
        self.expected_kind = expected_kind
        self.expected_field_urn = expected_field_urn
        self.failures_remaining = failures_before_success
        self.on_target_success = on_target_success
        self.attempts = 0
        self.delivery: Delivery | None = None
        self.reports: tuple[Any, ...] = ()
        self.matched_change: NormalizedChange | None = None
        self.ready = threading.Event()
        self.readiness_delivery: Delivery | None = None
        self.seen_deliveries: list[Delivery] = []

    def act(self, event: EventEnvelope) -> bool | None:
        delivery = Delivery.from_envelope(event)
        self.seen_deliveries.append(delivery)
        changes = normalize_metadata_change_log(event.event)
        matching = any(
            change.kind is self.expected_kind
            and change.entity_urn == ORDERS_URN
            and change.schema_field_urn == self.expected_field_urn
            for change in changes
        )
        if not matching:
            acknowledged = self.inner.act(event)
            if event.event.entityUrn == ORDERS_URN and event.event.aspectName == "schemaMetadata":
                self.readiness_delivery = delivery
                self.ready.set()
            return acknowledged

        self.attempts += 1
        self.matched_change = next(
            change
            for change in changes
            if change.kind is self.expected_kind
            and change.entity_urn == ORDERS_URN
            and change.schema_field_urn == self.expected_field_urn
        )
        self.delivery = delivery
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise RuntimeError("intentional one-shot transport proof failure")

        acknowledged = self.inner.act(event)
        self.reports = self.inner.last_reports
        if self.on_target_success is not None:
            self.on_target_success()
        self.source.running = False
        return acknowledged

    def close(self) -> None:
        self.inner.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-broker-invalidation")
    parser.add_argument("--server", default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    parser.add_argument(
        "--bootstrap",
        default=os.getenv("KAFKA_BOOTSTRAP_SERVER", "localhost:9092"),
    )
    parser.add_argument(
        "--schema-registry-url",
        default=os.getenv(
            "SCHEMA_REGISTRY_URL",
            "http://localhost:8080/schema-registry/api/",
        ),
    )
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    return parser


def _set_proof_owner(graph: DataHubGraph) -> None:
    ownership = OwnershipClass(
        owners=[OwnerClass(owner=PROOF_OWNER_URN, type="DATAOWNER")],
    )
    graph.emit(MetadataChangeProposalWrapper(entityUrn=ORDERS_URN, aspect=ownership))
    observed = graph.get_aspect(ORDERS_URN, OwnershipClass)
    if observed is None or [item.owner for item in observed.owners] != [PROOF_OWNER_URN]:
        raise RuntimeError("proof ownership aspect did not read back exactly")


def _pipeline_config(
    *,
    name: str,
    server: str,
    token: str | None,
    bootstrap: str,
    schema_registry_url: str,
    state_dir: Path,
    owner_webhook_url: str,
    signer_trust_policy_path: Path,
) -> dict[str, Any]:
    datahub: dict[str, Any] = {"server": server}
    if token:
        datahub["token"] = token
    return {
        "name": name,
        "source": {
            "type": "kafka",
            "config": {
                "connection": {
                    "bootstrap": bootstrap,
                    "schema_registry_url": schema_registry_url,
                    "consumer_config": {"auto.offset.reset": "latest"},
                },
                "async_commit_enabled": False,
                "commit_retry_count": 3,
                "commit_retry_backoff": 0.25,
            },
        },
        "filters": [
            {
                "type": "event_type",
                "config": {
                    "filter": {
                        "MetadataChangeLogEvent_v1": {
                            "event": [
                                {
                                    "entityType": "dataset",
                                    "entityUrn": ORDERS_URN,
                                    "aspectName": "schemaMetadata",
                                }
                            ]
                        }
                    }
                },
            }
        ],
        "action": {
            "type": "glassbox_invalidation",
            "config": {
                "state_database_path": str(state_dir / "invalidation.sqlite3"),
                "require_receipt_signature": True,
                "signer_trust_policy_path": str(signer_trust_policy_path),
                "lease_duration_ms": 60_000,
                "claim_timeout_seconds": 10.0,
                "owner_webhook_url": owner_webhook_url,
                "allow_insecure_owner_webhook_http": True,
            },
        },
        "datahub": datahub,
        "options": {
            "retry_count": 1,
            "failure_mode": "THROW",
            "failed_events_dir": str(state_dir / "failed-events"),
        },
    }


def _wait_for_assignment(pipeline: Pipeline, *, timeout_seconds: float) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if pipeline.source.consumer.assignment():  # type: ignore[attr-defined]
            return
        time.sleep(0.05)
    raise TimeoutError("Kafka consumer did not receive a partition assignment")


def _wait_for_readiness(
    probe: ProbeAction,
    *,
    emits: tuple[Any, ...],
    canonical: Any,
    canonical_emit: Any,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    attempt = 0
    while time.monotonic() < deadline:
        emits[attempt % len(emits)]()
        attempt += 1
        if probe.ready.wait(min(1.5, max(0.0, deadline - time.monotonic()))):
            break
    else:
        raise TimeoutError("Kafka readiness change was not delivered through Actions")

    if canonical():
        return
    previous = probe.readiness_delivery
    probe.ready.clear()
    canonical_emit()
    while time.monotonic() < deadline:
        if probe.ready.wait(min(0.25, max(0.0, deadline - time.monotonic()))):
            if probe.readiness_delivery != previous and canonical():
                return
            probe.ready.clear()
    raise TimeoutError("canonical schema restoration was not delivered through Actions")


def _run_pipeline_once(
    config: dict[str, Any],
    *,
    expected_kind: ChangeKind,
    expected_field_urn: str,
    failures_before_success: int,
    readiness_emits: tuple[Any, ...],
    readiness_canonical: Any,
    readiness_canonical_emit: Any,
    emit: Any,
    timeout_seconds: float,
    fail_target_commit_once: bool = False,
) -> tuple[Pipeline, ProbeAction, OneShotKafkaCommitFailure | None]:
    pipeline = Pipeline.create(config)
    if not isinstance(pipeline.action, GlassBoxInvalidationAction):
        raise RuntimeError("Actions registry did not create the GlassBox plugin")
    commit_fault: OneShotKafkaCommitFailure | None = None
    if fail_target_commit_once:
        commit_attempts = pipeline.source.source_config.commit_retry_count  # type: ignore[attr-defined]
        commit_fault = OneShotKafkaCommitFailure(  # type: ignore[attr-defined]
            pipeline.source.consumer,
            commit_attempts_per_ack=commit_attempts,
        )
        pipeline.source.consumer = commit_fault  # type: ignore[attr-defined]
    probe = ProbeAction(
        pipeline.action,
        pipeline.source,
        expected_kind=expected_kind,
        expected_field_urn=expected_field_urn,
        failures_before_success=failures_before_success,
        on_target_success=commit_fault.arm if commit_fault is not None else None,
    )
    pipeline.action = probe  # type: ignore[assignment]
    errors: list[BaseException] = []

    def run() -> None:
        try:
            pipeline.run()
        except BaseException as exc:  # pragma: no cover - live proof failure surfacing
            errors.append(exc)

    thread = threading.Thread(target=run, name=f"{config['name']}-runner", daemon=True)
    thread.start()
    try:
        _wait_for_assignment(pipeline, timeout_seconds=timeout_seconds)
        _wait_for_readiness(
            probe,
            emits=readiness_emits,
            canonical=readiness_canonical,
            canonical_emit=readiness_canonical_emit,
            timeout_seconds=timeout_seconds,
        )
        emit()
        thread.join(timeout_seconds)
        if thread.is_alive():
            pipeline.source.running = False  # type: ignore[attr-defined]
            thread.join(3.0)
            raise TimeoutError(f"pipeline did not observe {expected_kind.value}")
        if errors:
            raise RuntimeError("DataHub Actions pipeline failed") from errors[0]
        if probe.delivery is None:
            raise RuntimeError("pipeline exited without the expected broker delivery")
        return pipeline, probe, commit_fault
    finally:
        if thread.is_alive():
            pipeline.source.running = False  # type: ignore[attr-defined]
            thread.join(3.0)
        pipeline.stop()


def _run_same_group_redelivery(
    config: dict[str, Any],
    *,
    expected_kind: ChangeKind,
    expected_field_urn: str,
    timeout_seconds: float,
) -> tuple[Pipeline, ProbeAction]:
    """Run a fresh Actions process until the already-pending target is redelivered."""

    pipeline = Pipeline.create(config)
    if not isinstance(pipeline.action, GlassBoxInvalidationAction):
        raise RuntimeError("Actions registry did not create the GlassBox plugin")
    probe = ProbeAction(
        pipeline.action,
        pipeline.source,
        expected_kind=expected_kind,
        expected_field_urn=expected_field_urn,
    )
    pipeline.action = probe  # type: ignore[assignment]
    errors: list[BaseException] = []

    def run() -> None:
        try:
            pipeline.run()
        except BaseException as exc:  # pragma: no cover - live proof failure surfacing
            errors.append(exc)

    thread = threading.Thread(target=run, name=f"{config['name']}-redelivery", daemon=True)
    thread.start()
    try:
        thread.join(timeout_seconds)
        if thread.is_alive():
            pipeline.source.running = False  # type: ignore[attr-defined]
            thread.join(3.0)
            raise TimeoutError("same-group process did not receive the pending Kafka event")
        if errors:
            raise RuntimeError("same-group DataHub Actions process failed") from errors[0]
        if probe.delivery is None:
            raise RuntimeError("same-group process exited without the pending Kafka delivery")
        return pipeline, probe
    finally:
        if thread.is_alive():
            pipeline.source.running = False  # type: ignore[attr-defined]
            thread.join(3.0)
        pipeline.stop()


def _committed_offset(bootstrap: str, group_id: str, delivery: Delivery) -> int:
    consumer = Consumer(
        {
            "bootstrap.servers": bootstrap,
            "group.id": group_id,
            "enable.auto.commit": False,
        }
    )
    try:
        result = consumer.committed(
            [TopicPartition(delivery.topic, delivery.partition)],
            timeout=10.0,
        )[0]
    finally:
        consumer.close()
    if result.offset < 0:
        raise RuntimeError("Kafka consumer group has no committed target offset")
    return result.offset


def _action_stats(pipeline: Pipeline) -> dict[str, int]:
    stats = pipeline.stats().get_action_stats()
    return {
        "success_count": stats.get_success_count(),
        "exception_count": stats.get_exception_count(),
        "failed_ack_count": pipeline.stats().get_failed_ack_count(),
        "ack_success_count": pipeline.stats().get_success_count(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=args.token))
    graph.test_connection()

    baseline = _schema(native_type="VARCHAR", numeric=False, time_ms=BASELINE_TIME_MS)
    baseline_warm = _schema(
        native_type="VARCHAR",
        numeric=False,
        time_ms=BASELINE_TIME_MS + 1,
        include_unrelated=True,
        unrelated_field_path="broker_ready_note",
    )
    material = _schema(native_type="DECIMAL(18,2)", numeric=True, time_ms=MATERIAL_TIME_MS)
    material_warm = _schema(
        native_type="DECIMAL(18,2)",
        numeric=True,
        time_ms=MATERIAL_TIME_MS + 1,
        include_unrelated=True,
        unrelated_field_path="broker_ready_note",
    )
    negative = _schema(
        native_type="DECIMAL(18,2)",
        numeric=True,
        time_ms=NEGATIVE_TIME_MS,
        include_unrelated=True,
    )
    _emit_schema(graph, baseline)
    _set_proof_owner(graph)

    receipt_backend = DataHubReceiptBackend(server=server, token=args.token)
    receipt_backend.test_connection()
    signing_key = demo_signing_key()
    trust_policy = demo_signer_trust_policy(signing_key)
    receipt = build_signed_receipt(
        urn_resolver=VerifiedURNResolver(receipt_backend),
        schema_field_urn=FIELD_URN,
        signing_key=signing_key,
    )
    pipeline_name = f"glassbox-broker-proof-{uuid.uuid4().hex}"

    with (
        TemporaryDirectory(prefix="glassbox-broker-proof-") as directory,
        OwnerWebhookCapture() as owner_webhook,
    ):
        state_dir = Path(directory)
        policy_path = state_dir / "trusted-signers.json"
        policy_path.write_text(json.dumps(trust_policy.to_dict()), encoding="utf-8")
        store = SQLiteInvalidationStore(
            state_dir / "invalidation.sqlite3",
            signer_trust_policy=trust_policy,
        )
        receipt_publication = LiveReceiptPipeline(
            store,
            ReceiptEmitter(receipt_backend, signer_trust_policy=trust_policy),
        ).publish_compiled(
            receipt,
            field_lineage=FieldLineageProof(
                coverage=FieldCoverage.COMPLETE,
                rule_id="glassbox.runtime-field-observation.v1",
                wildcard_query=False,
            ),
        )
        receipt_emission = receipt_publication.datahub
        config = _pipeline_config(
            name=pipeline_name,
            server=server,
            token=args.token,
            bootstrap=args.bootstrap,
            schema_registry_url=args.schema_registry_url,
            state_dir=state_dir,
            owner_webhook_url=owner_webhook.url,
            signer_trust_policy_path=policy_path,
        )

        first_pipeline, first, commit_fault = _run_pipeline_once(
            config,
            expected_kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
            expected_field_urn=FIELD_URN,
            failures_before_success=1,
            readiness_emits=(
                lambda: _emit_schema(graph, baseline_warm),
                lambda: _emit_schema(graph, baseline),
            ),
            readiness_canonical=lambda: (
                graph.get_aspect(ORDERS_URN, type(baseline)).hash == baseline.hash
            ),
            readiness_canonical_emit=lambda: _emit_schema(graph, baseline),
            emit=lambda: _emit_schema(graph, material),
            timeout_seconds=args.timeout_seconds,
            fail_target_commit_once=True,
        )
        assert first.delivery is not None
        assert first.matched_change is not None
        assert commit_fault is not None
        committed_after_failure = _committed_offset(
            args.bootstrap,
            pipeline_name,
            first.delivery,
        )
        redelivery_pipeline, redelivery = _run_same_group_redelivery(
            config,
            expected_kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
            expected_field_urn=FIELD_URN,
            timeout_seconds=args.timeout_seconds,
        )
        assert redelivery.delivery is not None
        committed_after_recovery = _committed_offset(
            args.bootstrap,
            pipeline_name,
            redelivery.delivery,
        )

        second_pipeline, second, second_commit_fault = _run_pipeline_once(
            config,
            expected_kind=ChangeKind.SCHEMA_FIELD_ADDED,
            expected_field_urn=str(SchemaFieldUrn(ORDERS_URN, "internal_note")),
            failures_before_success=0,
            readiness_emits=(
                lambda: _emit_schema(graph, material_warm),
                lambda: _emit_schema(graph, material),
            ),
            readiness_canonical=lambda: (
                graph.get_aspect(ORDERS_URN, type(material)).hash == material.hash
            ),
            readiness_canonical_emit=lambda: _emit_schema(graph, material),
            emit=lambda: _emit_schema(graph, negative),
            timeout_seconds=args.timeout_seconds,
        )
        assert second_commit_fault is None
        assert second.delivery is not None
        second_committed = _committed_offset(args.bootstrap, pipeline_name, second.delivery)

        transactional_state = SQLiteInvalidationStore(
            state_dir / "invalidation.sqlite3",
            signer_trust_policy=trust_policy,
        )
        records = transactional_state.read_audit_records()
        integrity = transactional_state.verify_integrity()
        routing_task = transactional_state.get_owner_routing_task(
            first.reports[0].campaign.campaign_id
        )
        publication_task = transactional_state.get_receipt_publication_task(receipt["receipt_id"])
        first_report = first.reports[0]
        redelivery_report = redelivery.reports[0]
        second_report = second.reports[0]
        restart_seen_offsets = tuple(item.offset for item in second.seen_deliveries)
        first_event_replayed = first.delivery.offset in restart_seen_offsets
        valid = (
            first.attempts == 2
            and first_report.valid
            and first_report.campaign.quarantined[0].state.value == "STALE"
            and commit_fault.injected_failures == 3
            and _action_stats(first_pipeline)["failed_ack_count"] == 1
            and committed_after_failure < first.delivery.offset + 1
            and redelivery.delivery == first.delivery
            and redelivery.attempts == 1
            and redelivery_report.valid
            and redelivery_report.reused_completion
            and redelivery_report.emissions == 0
            and redelivery_report.campaign.campaign_id == first_report.campaign.campaign_id
            and redelivery_report.write_evidence.valid
            and committed_after_recovery >= redelivery.delivery.offset + 1
            and first_report.routed_destinations == (PROOF_OWNER_URN,)
            and not first_report.reused_routing
            and redelivery_report.reused_routing
            and routing_task is not None
            and routing_task.delivery_evidence is not None
            and routing_task.delivery_evidence.destination_count == 1
            and publication_task is not None
            and publication_task.status is OutboxStatus.COMPLETED
            and publication_task.publication_evidence is not None
            and len(owner_webhook.requests) == 1
            and owner_webhook.requests[0]["idempotency_key"] == first_report.campaign.campaign_id
            and owner_webhook.requests[0]["payload"]["owner_urns"] == [PROOF_OWNER_URN]
            and second.attempts == 1
            and second_report.valid
            and second_report.no_op
            and second_report.campaign.assessments[0].state.value == "UNAFFECTED"
            and second_committed >= second.delivery.offset + 1
            and not first_event_replayed
        )
        report = {
            "contract": "glassbox.datahub-kafka-invalidation-live-proof.v2",
            "raw_content_returned": False,
            "valid": valid,
            "transport": {
                "source": "datahub-actions-kafka",
                "topic": TOPIC,
                "consumer_group": pipeline_name,
                "commit_mode": "synchronous",
                "schema_registry_url": args.schema_registry_url,
                "scope": {
                    "kafka_delivery": "PROVEN",
                    "action_retry": "PROVEN",
                    "synchronous_offset_commit": "PROVEN",
                    "same_group_restart": "PROVEN",
                    "ack_failure_recovery": "PROVEN",
                    "pgqueue_delivery": "UNVERIFIED",
                },
                "fault_injection": {
                    "origin": "TEST_HARNESS_BEFORE_BROKER_COMMIT",
                    "boundary": "confluent-kafka synchronous consumer.commit",
                    "broker_offset_advanced_during_failure": False,
                    "physical_broker_outage": False,
                },
            },
            "material_change": {
                "kind": ChangeKind.SCHEMA_FIELD_TYPE_CHANGED.value,
                "delivery": first.delivery.__dict__,
                "attempts": first.attempts,
                "injected_failures": 1,
                "injected_commit_attempt_failures": commit_fault.injected_failures,
                "pipeline_action_stats": _action_stats(first_pipeline),
                "committed_offset_after_failed_ack": committed_after_failure,
                "acknowledged_after_first_process": (
                    committed_after_failure >= first.delivery.offset + 1
                ),
                "classification": first_report.campaign.quarantined[0].state.value,
                "campaign_id": first_report.campaign.campaign_id,
                "incident_urn": first_report.campaign.incident_urn,
                "direct_writeback_verified": first_report.write_evidence.valid,
            },
            "same_event_recovery": {
                "delivery": redelivery.delivery.__dict__,
                "same_topic_partition_offset": redelivery.delivery == first.delivery,
                "attempts": redelivery.attempts,
                "pipeline_action_stats": _action_stats(redelivery_pipeline),
                "committed_offset_after_recovery": committed_after_recovery,
                "acknowledged": committed_after_recovery >= redelivery.delivery.offset + 1,
                "campaign_id": redelivery_report.campaign.campaign_id,
                "reused_completion": redelivery_report.reused_completion,
                "emissions": redelivery_report.emissions,
                "fresh_direct_readback": redelivery_report.write_evidence.valid,
            },
            "restart_negative_control": {
                "kind": ChangeKind.SCHEMA_FIELD_ADDED.value,
                "delivery": second.delivery.__dict__,
                "attempts": second.attempts,
                "pipeline_action_stats": _action_stats(second_pipeline),
                "committed_offset": second_committed,
                "acknowledged": second_committed >= second.delivery.offset + 1,
                "seen_offsets": list(restart_seen_offsets),
                "first_event_replayed": first_event_replayed,
                "classification": second_report.campaign.assessments[0].state.value,
                "no_op": second_report.no_op,
            },
            "receipt": {
                "receipt_id": receipt["receipt_id"],
                "document_urn": receipt_emission.document_urn,
                "automatic_registration": receipt_publication.to_dict()["state"],
                "publication": receipt_publication.to_dict()["publication"],
            },
            "audit": {
                "record_count": len(records),
                "phases": [record.phase.value for record in records],
            },
            "transactional_state": {
                "profile": "sqlite-wal-single-host-multiprocess",
                "receipts": integrity.receipts,
                "dependencies": integrity.dependencies,
                "campaigns": integrity.campaigns,
                "audit_records": integrity.audit_records,
                "integrity_verified": True,
                "owner_routing_tasks": integrity.owner_routing_tasks,
                "receipt_publication_tasks": integrity.receipt_publication_tasks,
                "receipt_publication_status": (
                    publication_task.status.value if publication_task is not None else None
                ),
                "material_redelivery": {
                    "campaign_id": redelivery_report.campaign.campaign_id,
                    "reused_completion": redelivery_report.reused_completion,
                    "emissions": redelivery_report.emissions,
                    "fresh_direct_readback": redelivery_report.write_evidence.valid,
                },
                "owner_routing": {
                    "datahub_owner_urn": PROOF_OWNER_URN,
                    "webhook_requests": len(owner_webhook.requests),
                    "idempotency_key": owner_webhook.requests[0]["idempotency_key"],
                    "first_delivery_reused": first_report.reused_routing,
                    "redelivery_reused": redelivery_report.reused_routing,
                    "destination_count": (
                        routing_task.delivery_evidence.destination_count
                        if routing_task is not None and routing_task.delivery_evidence is not None
                        else None
                    ),
                    "destination_identifiers_persisted": False,
                },
            },
            "versions": {
                "datahub_core": "1.6.0",
                "datahub_sdk": "1.6.0.15",
                "datahub_actions": "1.6.0.15",
            },
        }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
