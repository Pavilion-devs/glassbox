"""Live proof: genuine GMS MCL -> PostgreSQL queue -> Actions -> GlassBox recovery."""

from __future__ import annotations

import argparse
import json
import os
import threading
import time
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from confluent_kafka.schema_registry import SchemaRegistryClient
from confluent_kafka.schema_registry.avro import AvroSerializer
from confluent_kafka.serialization import MessageField, SerializationContext
from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from datahub.metadata.schema_classes import MetadataChangeLogClass
from datahub.pgqueue.compression import PgQueuePayloadCompression, encode_inner
from datahub.pgqueue.config import PgQueueConnectionConfig, PgQueueConsumerConfig
from datahub.pgqueue.connection import create_pgqueue_connection
from datahub.pgqueue.consumer import DatahubPgQueueConsumer
from datahub.pgqueue.lease_markers import ACKED_LOCK_OWNER
from datahub.pgqueue.repository import PgQueueMessageHandle, PgQueueRepository
from datahub_actions.event.event_envelope import EventEnvelope
from datahub_actions.event.event_registry import METADATA_CHANGE_LOG_EVENT_V1_TYPE
from datahub_actions.pipeline.pipeline import Pipeline
from datahub_actions.pipeline.pipeline_context import PipelineContext
from datahub_actions.plugin.source.kafka.kafka_event_source import KafkaEventSource
from examples.deterministic_pricing_agent import ORDERS_URN
from examples.end_to_end_broker_invalidation import (
    BASELINE_TIME_MS,
    MATERIAL_TIME_MS,
    TOPIC,
    Delivery,
    OwnerWebhookCapture,
    _action_stats,
    _pipeline_config,
    _set_proof_owner,
)
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

PGQUEUE_DDL_COMMIT = "93336230f49c27eed0c07d3d2d4350781a256ba5"


@dataclass(frozen=True)
class CapturedMcl:
    """A genuine GMS-produced MCL plus its Kafka origin coordinates."""

    event: MetadataChangeLogClass
    delivery: Delivery


@dataclass(frozen=True)
class QueueDelivery:
    """Stable pgQueue message identity carried by the official Actions envelope."""

    topic: str
    partition: int
    enqueue_seq: int
    message_id: int
    enqueued_at: str

    @classmethod
    def from_envelope(cls, event: EventEnvelope) -> QueueDelivery:
        pg_queue = event.meta.get("pg_queue")
        if not isinstance(pg_queue, dict):
            raise RuntimeError("real pgQueue delivery did not include Actions queue metadata")
        handle = pg_queue.get("handle")
        if not isinstance(handle, dict):
            raise RuntimeError("real pgQueue delivery did not include a queue handle")
        topic = pg_queue.get("topic")
        partition = pg_queue.get("partition")
        enqueue_seq = pg_queue.get("enqueue_seq")
        message_id = handle.get("id")
        enqueued_at = handle.get("enqueued_at")
        values = (partition, enqueue_seq, message_id)
        if (
            not isinstance(topic, str)
            or any(isinstance(value, bool) or not isinstance(value, int) for value in values)
            or not isinstance(enqueued_at, str)
        ):
            raise RuntimeError("Actions pgQueue metadata has an invalid shape")
        return cls(topic, partition, enqueue_seq, message_id, enqueued_at)


class OneShotPgQueueAckFailure:
    """Delegate polling and close, but fail one explicitly armed queue acknowledgement."""

    def __init__(self, consumer: Any) -> None:
        self._consumer = consumer
        self._armed = False
        self.ack_calls = 0
        self.injected_failures = 0

    def arm(self) -> None:
        if self._armed or self.injected_failures:
            raise RuntimeError("pgQueue acknowledgement fault may only be armed once")
        self._armed = True

    def ack(self, handles: Sequence[PgQueueMessageHandle]) -> int:
        self.ack_calls += 1
        if self._armed:
            self._armed = False
            self.injected_failures += 1
            raise RuntimeError("intentional failure before pgQueue acknowledgement transaction")
        return int(self._consumer.ack(handles))

    def __getattr__(self, name: str) -> Any:
        return getattr(self._consumer, name)


class PgQueueProbeAction:
    """Observe the queue identity while keeping all production behavior in the plugin."""

    def __init__(
        self,
        inner: GlassBoxInvalidationAction,
        source: Any,
        *,
        on_target_success: Any | None = None,
    ) -> None:
        self.inner = inner
        self.source = source
        self.on_target_success = on_target_success
        self.delivery: QueueDelivery | None = None
        self.matched_change: NormalizedChange | None = None
        self.reports: tuple[Any, ...] = ()
        self.attempts = 0
        self.delivered = threading.Event()

    def act(self, event: EventEnvelope) -> bool | None:
        changes = normalize_metadata_change_log(event.event)
        matching = next(
            (
                change
                for change in changes
                if change.kind is ChangeKind.SCHEMA_FIELD_TYPE_CHANGED
                and change.entity_urn == ORDERS_URN
                and change.schema_field_urn == FIELD_URN
            ),
            None,
        )
        if matching is None:
            return self.inner.act(event)

        self.attempts += 1
        self.delivery = QueueDelivery.from_envelope(event)
        self.matched_change = matching
        acknowledged = self.inner.act(event)
        self.reports = self.inner.last_reports
        if self.on_target_success is not None:
            self.on_target_success()
        self.delivered.set()
        self.source.running = False
        return acknowledged

    def close(self) -> None:
        self.inner.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-pgqueue-invalidation")
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
    parser.add_argument("--pg-host-port", default="127.0.0.1:55434")
    parser.add_argument("--pg-database", default="glassbox")
    parser.add_argument("--pg-user", default="glassbox")
    parser.add_argument(
        "--pg-password",
        default=os.getenv("GLASSBOX_PGQUEUE_PASSWORD", "glassbox-proof"),
    )
    parser.add_argument("--initialize-schema", action="store_true")
    parser.add_argument("--visibility-seconds", type=int, default=8)
    parser.add_argument("--timeout-seconds", type=float, default=30.0)
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--allow-remote-pg", action="store_true")
    return parser


def _queue_connection(args: argparse.Namespace) -> PgQueueConnectionConfig:
    host = args.pg_host_port.rsplit(":", 1)[0].strip("[]").lower()
    if not args.allow_remote_pg and host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("remote pgQueue targets require --allow-remote-pg")
    return PgQueueConnectionConfig.model_validate(
        {
            "host_port": args.pg_host_port,
            "database": args.pg_database,
            "username": args.pg_user,
            "password": args.pg_password,
            "sslmode": "disable" if host in {"127.0.0.1", "localhost", "::1"} else "require",
            "queue_schema": "queue",
            "table_prefix": "metadata_queue",
            "topic_defaults": {
                "partition_count": 1,
                "visibility_timeout_seconds": args.visibility_seconds,
                "retention_max_age_seconds": 604800,
                "max_rows_per_topic": 0,
                "max_total_payload_bytes_per_topic": 0,
                "aggressive_retention": False,
                "default_content_type_mime": "application/avro",
            },
        }
    )


def _initialize_pgqueue_schema(queue: PgQueueConnectionConfig) -> None:
    ddl_path = Path(__file__).with_name("datahub_pgqueue_v001_compat.sql")
    ddl = ddl_path.read_text(encoding="utf-8")
    conn = create_pgqueue_connection(queue)
    try:
        conn.autocommit = True
        with conn.cursor() as cursor:
            cursor.execute(ddl)
    finally:
        conn.close()


def _capture_gms_mcl(
    graph: DataHubGraph,
    *,
    bootstrap: str,
    schema_registry_url: str,
    material_schema: Any,
    timeout_seconds: float,
) -> CapturedMcl:
    group = f"glassbox-pgqueue-origin-{uuid.uuid4().hex}"
    source = KafkaEventSource.create(
        {
            "connection": {
                "bootstrap": bootstrap,
                "schema_registry_url": schema_registry_url,
                "consumer_config": {"auto.offset.reset": "latest"},
            },
            "async_commit_enabled": False,
            "commit_retry_count": 3,
            "commit_retry_backoff": 0.25,
        },
        PipelineContext(group, None),
    )
    captured: list[CapturedMcl] = []
    errors: list[BaseException] = []
    ready = threading.Event()

    def event_schema_hash(envelope: EventEnvelope) -> str | None:
        if (
            envelope.event_type != METADATA_CHANGE_LOG_EVENT_V1_TYPE
            or envelope.event.entityUrn != ORDERS_URN
            or envelope.event.aspectName != "schemaMetadata"
            or envelope.event.aspect is None
        ):
            return None
        value = envelope.event.aspect.value
        payload = json.loads(value.decode("utf-8") if isinstance(value, bytes) else value)
        observed_hash = payload.get("hash")
        return observed_hash if isinstance(observed_hash, str) else None

    def run() -> None:
        try:
            for envelope in source.events():
                matching = False
                schema_hash = event_schema_hash(envelope)
                if schema_hash is not None:
                    ready.set()
                if schema_hash == material_schema.hash:
                    matching = any(
                        change.kind is ChangeKind.SCHEMA_FIELD_TYPE_CHANGED
                        and change.entity_urn == ORDERS_URN
                        and change.schema_field_urn == FIELD_URN
                        for change in normalize_metadata_change_log(envelope.event)
                    )
                source.ack(envelope, True)
                if matching:
                    captured.append(
                        CapturedMcl(
                            event=envelope.event,
                            delivery=Delivery.from_envelope(envelope),
                        )
                    )
                    source.running = False
                    return
        except BaseException as exc:  # pragma: no cover - live proof failure surfacing
            errors.append(exc)

    thread = threading.Thread(target=run, name=f"{group}-capture", daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if any(partition.topic == TOPIC for partition in source.consumer.assignment()):
                break
            time.sleep(0.05)
        else:
            raise TimeoutError("Kafka origin consumer did not receive the MCL topic assignment")

        readiness_schema = _schema(
            native_type="VARCHAR",
            numeric=False,
            time_ms=BASELINE_TIME_MS + 20_000,
            include_unrelated=True,
            unrelated_field_path="pgqueue_ready_note",
        )
        readiness_attempt = 0
        while time.monotonic() < deadline and not ready.is_set():
            _emit_schema(
                graph,
                readiness_schema
                if readiness_attempt % 2 == 0
                else _schema(
                    native_type="VARCHAR",
                    numeric=False,
                    time_ms=BASELINE_TIME_MS,
                ),
            )
            readiness_attempt += 1
            ready.wait(min(1.0, max(0.0, deadline - time.monotonic())))
        if not ready.is_set():
            raise TimeoutError("Kafka origin consumer did not observe an MCL readiness event")

        _emit_schema(
            graph,
            _schema(native_type="VARCHAR", numeric=False, time_ms=BASELINE_TIME_MS),
        )
        _emit_schema(graph, material_schema)
        thread.join(timeout_seconds)
        if thread.is_alive():
            source.running = False
            thread.join(3.0)
            raise TimeoutError("GMS material MCL was not observed on Kafka")
        if errors:
            raise RuntimeError("Kafka origin capture failed") from errors[0]
        if len(captured) != 1:
            raise RuntimeError("Kafka origin capture did not produce exactly one target MCL")
        return captured[0]
    finally:
        source.running = False
        source.close()


def _enqueue_mcl(
    queue: PgQueueConnectionConfig,
    *,
    schema_registry_url: str,
    event: MetadataChangeLogClass,
) -> PgQueueMessageHandle:
    serializer = AvroSerializer(
        schema_registry_client=SchemaRegistryClient({"url": schema_registry_url}),
        schema_str=str(MetadataChangeLogClass.RECORD_SCHEMA),
        to_dict=lambda value, context: value.to_obj(tuples=True),
    )
    serialized = serializer(event, SerializationContext(TOPIC, MessageField.VALUE))
    if serialized is None:
        raise RuntimeError("MCL Avro serialization returned no bytes")
    repository = PgQueueRepository(queue.queue_schema, queue.table_prefix)
    conn = create_pgqueue_connection(queue)
    try:
        defaults = queue.merged_topic_defaults_for(TOPIC)
        return repository.enqueue(
            conn,
            topic_name=TOPIC,
            routing_key=ORDERS_URN,
            partition_count=defaults.partition_count,
            retention_max_age_seconds=defaults.retention_max_age_seconds,
            max_rows_per_topic=defaults.max_rows_per_topic,
            max_total_payload_bytes=defaults.max_total_payload_bytes_per_topic,
            default_content_type_mime=defaults.default_content_type_mime,
            aggressive_retention=defaults.aggressive_retention,
            priority=5,
            payload=encode_inner(serialized, PgQueuePayloadCompression.NONE),
            content_type="application/avro",
            headers=(),
            payload_compression=int(PgQueuePayloadCompression.NONE),
        )
    finally:
        conn.close()


def _pgqueue_pipeline_config(
    base: dict[str, Any],
    *,
    queue: PgQueueConnectionConfig,
    schema_registry_url: str,
    visibility_seconds: int,
) -> dict[str, Any]:
    config = dict(base)
    config["source"] = {
        "type": "pg_queue",
        "config": {
            "queue": queue.model_dump(mode="python"),
            "schema_registry_url": schema_registry_url,
            "topic_routes": {"mcl": TOPIC},
            "payload_kind_by_route_key": {"mcl": "mcl"},
            "visibility_timeout_seconds": visibility_seconds,
            "poll_interval_seconds": 0.1,
            "batch_size": 1,
        },
    }
    return config


def _start_pgqueue_pipeline(
    config: dict[str, Any],
    *,
    inject_ack_failure: bool,
) -> tuple[
    Pipeline,
    PgQueueProbeAction,
    OneShotPgQueueAckFailure | None,
    threading.Thread,
    list[BaseException],
]:
    pipeline = Pipeline.create(config)
    if not isinstance(pipeline.action, GlassBoxInvalidationAction):
        raise RuntimeError("Actions registry did not create the GlassBox plugin")
    fault: OneShotPgQueueAckFailure | None = None
    if inject_ack_failure:
        consumer = pipeline.source._consumer  # type: ignore[attr-defined]
        if consumer is None:
            raise RuntimeError("pgQueue source did not initialize its official consumer")
        fault = OneShotPgQueueAckFailure(consumer)
        pipeline.source._consumer = fault  # type: ignore[attr-defined]
    probe = PgQueueProbeAction(
        pipeline.action,
        pipeline.source,
        on_target_success=fault.arm if fault is not None else None,
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
    return pipeline, probe, fault, thread, errors


def _finish_pgqueue_pipeline(
    pipeline: Pipeline,
    probe: PgQueueProbeAction,
    thread: threading.Thread,
    errors: list[BaseException],
    *,
    timeout_seconds: float,
) -> None:
    try:
        thread.join(timeout_seconds)
        if thread.is_alive():
            pipeline.source.running = False  # type: ignore[attr-defined]
            thread.join(3.0)
            raise TimeoutError("pgQueue pipeline did not receive the target event")
        if errors:
            raise RuntimeError("pgQueue DataHub Actions pipeline failed") from errors[0]
        if probe.delivery is None:
            raise RuntimeError("pgQueue pipeline exited without the target delivery")
    finally:
        if thread.is_alive():
            pipeline.source.running = False  # type: ignore[attr-defined]
            thread.join(3.0)
        pipeline.stop()


def _queue_observation(
    queue: PgQueueConnectionConfig,
    *,
    consumer_group: str,
    delivery: QueueDelivery,
) -> dict[str, Any]:
    conn = create_pgqueue_connection(queue)
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT COALESCE(
                    (
                        SELECT offset_value
                        FROM queue.metadata_queue_consumer_offset
                        WHERE consumer_group = %s
                          AND topic_id = (
                              SELECT id FROM queue.metadata_queue_topic WHERE topic_name = %s
                          )
                          AND partition_id = %s
                    ),
                    0
                )
                """,
                (consumer_group, delivery.topic, delivery.partition),
            )
            offset = int(cursor.fetchone()[0])
            cursor.execute(
                """
                SELECT lock_owner, locked_until > NOW()
                FROM queue.metadata_queue_message_group_lease
                WHERE message_id = %s
                  AND message_enqueued_at = %s::timestamptz
                  AND consumer_group = %s
                """,
                (delivery.message_id, delivery.enqueued_at, consumer_group),
            )
            lease = cursor.fetchone()
    finally:
        conn.close()
    return {
        "offset": offset,
        "lease_present": lease is not None,
        "lease_active": bool(lease[1]) if lease is not None else False,
        "acked_marker": bool(lease[0] == ACKED_LOCK_OWNER) if lease is not None else False,
    }


def _fresh_restart_is_empty(
    queue: PgQueueConnectionConfig,
    *,
    consumer_group: str,
    schema_registry_url: str,
) -> bool:
    consumer = DatahubPgQueueConsumer(
        PgQueueConsumerConfig(
            queue=queue,
            schema_registry_url=schema_registry_url,
            topic_routes={"mcl": TOPIC},
            consumer_group=consumer_group,
            visibility_timeout_seconds=queue.topic_defaults.visibility_timeout_seconds,
            payload_kind_by_route_key={"mcl": "mcl"},
        )
    )
    try:
        return not consumer.poll_route_key("mcl", max_messages=1)
    finally:
        consumer.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    if args.visibility_seconds < 3:
        raise ValueError("--visibility-seconds must be at least 3 for the pre-expiry control")
    queue = _queue_connection(args)
    if args.initialize_schema:
        _initialize_pgqueue_schema(queue)

    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=args.token))
    graph.test_connection()
    baseline = _schema(native_type="VARCHAR", numeric=False, time_ms=BASELINE_TIME_MS)
    material = _schema(
        native_type="DECIMAL(18,2)",
        numeric=True,
        time_ms=MATERIAL_TIME_MS + 10_000,
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
    pipeline_name = f"glassbox-pgqueue-proof-{uuid.uuid4().hex}"

    with (
        TemporaryDirectory(prefix="glassbox-pgqueue-proof-") as directory,
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
        captured = _capture_gms_mcl(
            graph,
            bootstrap=args.bootstrap,
            schema_registry_url=args.schema_registry_url,
            material_schema=material,
            timeout_seconds=args.timeout_seconds,
        )
        queued = _enqueue_mcl(
            queue,
            schema_registry_url=args.schema_registry_url,
            event=captured.event,
        )

        base_config = _pipeline_config(
            name=pipeline_name,
            server=server,
            token=args.token,
            bootstrap=args.bootstrap,
            schema_registry_url=args.schema_registry_url,
            state_dir=state_dir,
            owner_webhook_url=owner_webhook.url,
            signer_trust_policy_path=policy_path,
        )
        config = _pgqueue_pipeline_config(
            base_config,
            queue=queue,
            schema_registry_url=args.schema_registry_url,
            visibility_seconds=args.visibility_seconds,
        )
        first_pipeline, first, fault, first_thread, first_errors = _start_pgqueue_pipeline(
            config,
            inject_ack_failure=True,
        )
        _finish_pgqueue_pipeline(
            first_pipeline,
            first,
            first_thread,
            first_errors,
            timeout_seconds=args.timeout_seconds,
        )
        assert first.delivery is not None
        assert fault is not None
        after_failure = _queue_observation(
            queue,
            consumer_group=pipeline_name,
            delivery=first.delivery,
        )

        recovery_pipeline, recovery, no_fault, recovery_thread, recovery_errors = (
            _start_pgqueue_pipeline(config, inject_ack_failure=False)
        )
        assert no_fault is None
        pre_expiry_wait = min(1.0, args.visibility_seconds / 3)
        time.sleep(pre_expiry_wait)
        blocked_while_lease_active = recovery.delivery is None
        _finish_pgqueue_pipeline(
            recovery_pipeline,
            recovery,
            recovery_thread,
            recovery_errors,
            timeout_seconds=args.timeout_seconds + args.visibility_seconds,
        )
        assert recovery.delivery is not None
        after_recovery = _queue_observation(
            queue,
            consumer_group=pipeline_name,
            delivery=recovery.delivery,
        )
        fresh_restart_empty = _fresh_restart_is_empty(
            queue,
            consumer_group=pipeline_name,
            schema_registry_url=args.schema_registry_url,
        )

        state = SQLiteInvalidationStore(
            state_dir / "invalidation.sqlite3",
            signer_trust_policy=trust_policy,
        )
        integrity = state.verify_integrity()
        publication_task = state.get_receipt_publication_task(receipt["receipt_id"])
        first_report = first.reports[0]
        recovery_report = recovery.reports[0]
        queued_delivery = QueueDelivery(
            topic=TOPIC,
            partition=queued.partition_id,
            enqueue_seq=queued.enqueue_seq,
            message_id=queued.id,
            enqueued_at=queued.enqueued_at.isoformat(),
        )
        valid = (
            first.delivery == queued_delivery
            and first.attempts == 1
            and first_report.valid
            and first_report.campaign.quarantined[0].state.value == "STALE"
            and first_report.write_evidence.valid
            and fault.injected_failures == 1
            and _action_stats(first_pipeline)["failed_ack_count"] == 1
            and after_failure["offset"] < first.delivery.enqueue_seq
            and after_failure["lease_present"]
            and after_failure["lease_active"]
            and not after_failure["acked_marker"]
            and blocked_while_lease_active
            and recovery.delivery == first.delivery
            and recovery.attempts == 1
            and recovery_report.valid
            and recovery_report.reused_completion
            and recovery_report.emissions == 0
            and recovery_report.write_evidence.valid
            and recovery_report.campaign.campaign_id == first_report.campaign.campaign_id
            and recovery_report.reused_routing
            and after_recovery["offset"] >= recovery.delivery.enqueue_seq
            and after_recovery["acked_marker"]
            and fresh_restart_empty
            and len(owner_webhook.requests) == 1
            and publication_task is not None
            and publication_task.status is OutboxStatus.COMPLETED
        )
        report = {
            "contract": "glassbox.datahub-pgqueue-invalidation-live-proof.v1",
            "raw_content_returned": False,
            "valid": valid,
            "transport": {
                "source": "datahub-actions-pg-queue",
                "topic": TOPIC,
                "consumer_group": pipeline_name,
                "visibility_timeout_seconds": args.visibility_seconds,
                "scope": {
                    "gms_event_origin": "PROVEN_VIA_KAFKA_CAPTURE",
                    "pgqueue_delivery": "PROVEN",
                    "pgqueue_acknowledgement": "PROVEN",
                    "visibility_timeout_redelivery": "PROVEN",
                    "same_group_restart": "PROVEN",
                    "kafka_ack_failure_recovery": "OUT_OF_SCOPE_SEPARATE_PROOF",
                },
                "fault_injection": {
                    "origin": "TEST_HARNESS_BEFORE_PGQUEUE_COMMIT",
                    "boundary": "DatahubPgQueueConsumer.ack",
                    "queue_offset_advanced_during_failure": False,
                    "physical_database_outage": False,
                },
            },
            "event_origin": {
                "producer": "datahub-gms",
                "kafka_delivery": captured.delivery.__dict__,
                "kind": ChangeKind.SCHEMA_FIELD_TYPE_CHANGED.value,
                "entity_urn": ORDERS_URN,
                "field_urn": FIELD_URN,
            },
            "first_process": {
                "delivery": first.delivery.__dict__,
                "pipeline_action_stats": _action_stats(first_pipeline),
                "classification": first_report.campaign.quarantined[0].state.value,
                "campaign_id": first_report.campaign.campaign_id,
                "direct_writeback_verified": first_report.write_evidence.valid,
                "queue_offset_after_failed_ack": after_failure["offset"],
                "lease_present": after_failure["lease_present"],
                "lease_active": after_failure["lease_active"],
            },
            "same_event_recovery": {
                "delivery": recovery.delivery.__dict__,
                "same_queue_handle": recovery.delivery == first.delivery,
                "restart_blocked_before_visibility_expiry": blocked_while_lease_active,
                "pipeline_action_stats": _action_stats(recovery_pipeline),
                "campaign_id": recovery_report.campaign.campaign_id,
                "reused_completion": recovery_report.reused_completion,
                "emissions": recovery_report.emissions,
                "fresh_direct_readback": recovery_report.write_evidence.valid,
                "queue_offset_after_ack": after_recovery["offset"],
                "ack_marker_persisted": after_recovery["acked_marker"],
                "fresh_restart_empty": fresh_restart_empty,
            },
            "database_contract": {
                "engine": "PostgreSQL 16",
                "upstream_v001_commit": PGQUEUE_DDL_COMMIT,
                "logical_schema": "queue.metadata_queue_*",
                "partitioning": "proof-only DEFAULT partition replacing pg_partman time partitions",
                "pg_partman_maintenance": "UNVERIFIED",
                "lease_and_contiguous_offset_transactions": "PROVEN",
            },
            "receipt": {
                "receipt_id": receipt["receipt_id"],
                "document_urn": receipt_publication.datahub.document_urn,
                "publication": receipt_publication.to_dict()["publication"],
            },
            "transactional_state": {
                "profile": "sqlite-wal-single-host-multiprocess",
                "receipts": integrity.receipts,
                "dependencies": integrity.dependencies,
                "campaigns": integrity.campaigns,
                "audit_records": integrity.audit_records,
                "owner_webhook_requests": len(owner_webhook.requests),
            },
            "versions": {
                "datahub_core": "1.6.0",
                "datahub_sdk": "1.6.0.15",
                "datahub_actions": "1.6.0.15",
                "postgresql": "16",
            },
        }

    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
