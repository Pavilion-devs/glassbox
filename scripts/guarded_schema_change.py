"""Apply the single allowlisted Devpost schema change to the hosted GlassBox estate.

This is deliberately not a general mutation client. It accepts no server, token,
URN, field, type, payload, or timestamp argument. Credentials come from the
existing encrypted control store and the only permitted effect is changing the
synthetic ``commerce.orders.average_order_value`` field from decimal to string,
followed by the real transactional GlassBox invalidation Action.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path

from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from datahub.metadata.schema_classes import (
    AuditStampClass,
    GenericAspectClass,
    MetadataChangeLogClass,
    OtherSchemaClass,
    SchemaFieldDataTypeClass,
    SchemaMetadataClass,
    StringTypeClass,
)
from datahub.metadata.urns import SchemaFieldUrn

from glassbox_control.crypto import SecretBox
from glassbox_control.store import ControlStore
from glassbox_datahub import DataHubInvalidationBackend
from glassbox_dbom import load_signer_trust_policy
from glassbox_invalidation.mcl import normalize_metadata_change_log
from glassbox_invalidation.postgres_store import PostgresInvalidationStore
from glassbox_invalidation.transactional_action import TransactionalInvalidationAction
from glassbox_invalidation.transactional_store import OutboxStatus, OutboxTask
from glassbox_policy import ChangeKind, NormalizedChange

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD_PATH = "average_order_value"
EXPECTED_BEFORE_TYPE = "decimal(18,2)"
DEMO_AFTER_TYPE = "varchar(64)"
ACTOR_URN = "urn:li:corpuser:glassbox-demo-operator"
CONTROL_DB = Path("/var/lib/glassbox-control/control.sqlite3")
SCHEMA_FIELD_URN = str(SchemaFieldUrn(DATASET_URN, FIELD_PATH))


class GuardedChangeError(RuntimeError):
    """Bounded, raw-free operator failure."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-guarded-schema-change")
    parser.add_argument(
        "command",
        choices=("apply",),
        help="apply the fixed Devpost schema change and run the invalidation Action",
    )
    return parser


def _generic(aspect: SchemaMetadataClass) -> GenericAspectClass:
    body = json.dumps(aspect.to_obj(), sort_keys=True, separators=(",", ":")).encode()
    return GenericAspectClass(value=body, contentType="application/json")


def _changed_schema(
    current: SchemaMetadataClass,
    *,
    changed_at_ms: int,
) -> SchemaMetadataClass:
    changed = copy.deepcopy(current)
    matches = [field for field in changed.fields if field.fieldPath == FIELD_PATH]
    if len(matches) != 1:
        raise GuardedChangeError("the allowlisted field is missing or ambiguous")
    field = matches[0]
    if field.nativeDataType.lower() != EXPECTED_BEFORE_TYPE:
        raise GuardedChangeError("the allowlisted field is not in the expected pre-change state")
    field.nativeDataType = DEMO_AFTER_TYPE
    field.type = SchemaFieldDataTypeClass(type=StringTypeClass())  # type: ignore[no-untyped-call]
    audit = AuditStampClass(time=changed_at_ms, actor=ACTOR_URN)
    changed.lastModified = audit

    if isinstance(changed.platformSchema, OtherSchemaClass):
        raw = changed.platformSchema.rawSchema
        try:
            raw_schema = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise GuardedChangeError("the allowlisted raw schema is invalid") from exc
        raw_fields = raw_schema.get("fields") if isinstance(raw_schema, Mapping) else None
        if not isinstance(raw_fields, list):
            raise GuardedChangeError("the allowlisted raw schema has no field list")
        raw_matches = [
            item for item in raw_fields if isinstance(item, dict) and item.get("name") == FIELD_PATH
        ]
        if len(raw_matches) != 1:
            raise GuardedChangeError("the allowlisted raw-schema field is missing or ambiguous")
        raw_matches[0]["type"] = DEMO_AFTER_TYPE
        encoded_raw = json.dumps(raw_schema, sort_keys=True, separators=(",", ":"))
        changed.platformSchema.rawSchema = encoded_raw
        changed.hash = hashlib.sha256(encoded_raw.encode()).hexdigest()
    else:
        material = json.dumps(
            [item.to_obj() for item in changed.fields],
            sort_keys=True,
            separators=(",", ":"),
        )
        changed.hash = hashlib.sha256(material.encode()).hexdigest()
    return changed


def _connection() -> tuple[str, str]:
    encoded_key = os.getenv("GLASSBOX_CONTROL_MASTER_KEY", "")
    if not encoded_key:
        raise GuardedChangeError("the deployment control key is unavailable")
    box = SecretBox.from_base64url(
        encoded_key,
        key_id=os.getenv("GLASSBOX_CONTROL_MASTER_KEY_ID", "control-v1"),
    )
    store = ControlStore(
        Path(os.getenv("GLASSBOX_CONTROL_DB_PATH", str(CONTROL_DB))),
        box,
        organization=os.getenv("GLASSBOX_ORGANIZATION", "default"),
    )
    connection = store.load_datahub_connection()
    if connection is None:
        raise GuardedChangeError("the verified DataHub connection is unavailable")
    return connection.server_url, connection.token


def _operator_graph(server: str) -> DataHubGraph:
    client_id = os.getenv("GLASSBOX_DATAHUB_OPERATOR_CLIENT_ID", "")
    client_secret = os.getenv("GLASSBOX_DATAHUB_OPERATOR_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        raise GuardedChangeError("the one-shot DataHub operator credential is unavailable")
    return DataHubGraph(
        config=DatahubClientConfig(
            server=server,
            extra_headers={"Authorization": f"Basic {client_id}:{client_secret}"},
        )
    )


def _state() -> PostgresInvalidationStore:
    dsn = os.getenv("GLASSBOX_STATE_POSTGRES_DSN", "")
    trust_path = os.getenv("GLASSBOX_SIGNER_TRUST_POLICY_PATH", "")
    if not dsn or not trust_path:
        raise GuardedChangeError("the transactional Action state is unavailable")
    trust = load_signer_trust_policy(Path(trust_path))
    return PostgresInvalidationStore(
        dsn,
        schema=os.getenv("GLASSBOX_STATE_POSTGRES_SCHEMA", "glassbox"),
        signer_trust_policy=trust,
        initialize_schema=False,
    )


def _allowlisted_change(change: NormalizedChange) -> bool:
    return (
        change.entity_urn == DATASET_URN
        and change.aspect_name == "schemaMetadata"
        and change.kind is ChangeKind.SCHEMA_FIELD_TYPE_CHANGED
        and change.schema_field_urn == SCHEMA_FIELD_URN
        and change.before_digest is not None
        and change.after_digest is not None
    )


def _resumable_change(tasks: Sequence[OutboxTask]) -> NormalizedChange:
    matches = [
        task
        for task in tasks
        if task.status is OutboxStatus.READY
        and task.attempt_count > 0
        and task.last_error_type is not None
        and task.write_evidence is None
        and task.campaign.quarantined
        and _allowlisted_change(task.campaign.change)
    ]
    if len(matches) != 1:
        raise GuardedChangeError("the durable allowlisted campaign is missing or ambiguous")
    return matches[0].campaign.change


def _native_type(schema: SchemaMetadataClass) -> str:
    matches = [field for field in schema.fields if field.fieldPath == FIELD_PATH]
    if len(matches) != 1:
        raise GuardedChangeError("the allowlisted field is missing or ambiguous")
    return matches[0].nativeDataType.lower()


def apply_change() -> dict[str, object]:
    server, token = _connection()
    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=token))
    graph.test_connection()
    current = graph.get_aspect(DATASET_URN, SchemaMetadataClass)
    if current is None:
        raise GuardedChangeError("the allowlisted dataset has no schemaMetadata aspect")

    operator_graph = _operator_graph(server)
    operator_graph.test_connection()
    state = _state()
    current_type = _native_type(current)
    resumed = current_type == DEMO_AFTER_TYPE
    if current_type == EXPECTED_BEFORE_TYPE:
        changed_at_ms = datetime.now(UTC).replace(microsecond=0).timestamp()
        after = _changed_schema(current, changed_at_ms=int(changed_at_ms * 1000))
        operator_graph.emit(MetadataChangeProposalWrapper(entityUrn=DATASET_URN, aspect=after))
        persisted = graph.get_aspect(DATASET_URN, SchemaMetadataClass)
        if persisted is None or persisted.hash != after.hash:
            raise GuardedChangeError("DataHub did not directly read back the changed schema")

        event = MetadataChangeLogClass(
            entityType="dataset",
            entityUrn=DATASET_URN,
            aspectName="schemaMetadata",
            changeType="UPSERT",
            previousAspectValue=_generic(current),
            aspect=_generic(after),
            created=AuditStampClass(time=int(changed_at_ms * 1000), actor=ACTOR_URN),
        )
        changes = normalize_metadata_change_log(event)
        selected = [change for change in changes if _allowlisted_change(change)]
        if len(changes) != 1 or len(selected) != 1:
            raise GuardedChangeError("the schema mutation did not normalize to one allowed change")
        change = selected[0]
    elif resumed:
        change = _resumable_change(state.list_tasks())
    else:
        raise GuardedChangeError("the allowlisted field is in an unexpected schema state")

    candidates = state.candidates(change)
    if not candidates:
        raise GuardedChangeError("the change has no recorded decision dependencies")
    backend = DataHubInvalidationBackend.from_graph(operator_graph)
    backend.test_connection()
    report = TransactionalInvalidationAction(
        backend,
        state,
        worker_id="glassbox-devpost-guarded-change",
    ).process(change, candidates)
    if not report.valid or report.write_evidence is None:
        raise GuardedChangeError("the invalidation Action did not return verified writeback")
    task = state.get_task(report.campaign.campaign_id)
    if task is None or task.status.value != "COMPLETED":
        raise GuardedChangeError("the campaign was not durably completed")
    classifications: dict[str, int] = {}
    for assessment in report.campaign.assessments:
        classifications[assessment.state.value] = classifications.get(assessment.state.value, 0) + 1
    return {
        "change_event_id": change.event_id,
        "campaign_id": report.campaign.campaign_id,
        "incident_urn": report.campaign.incident_urn,
        "candidate_receipts": len(candidates),
        "review_receipts": len(report.campaign.quarantined),
        "classifications": classifications,
        "attempt_count": task.attempt_count,
        "writeback_verified": report.write_evidence.valid,
        "incident_aspect_count": len(report.write_evidence.incident_aspects),
        "resumed": resumed,
    }


def render(report: Mapping[str, object]) -> str:
    classifications = report["classifications"]
    class_text = (
        ", ".join(f"{key}={value}" for key, value in sorted(classifications.items()))
        if isinstance(classifications, Mapping)
        else "UNKNOWN"
    )
    lines = (
        ("GlassBox", "guarded DataHub schema change"),
        ("Dataset", "postgres · commerce.orders · PROD"),
        ("Field", FIELD_PATH),
        ("Schema", f"{EXPECTED_BEFORE_TYPE} → {DEMO_AFTER_TYPE}"),
        ("DataHub", "CHANGED · direct readback verified"),
        ("Change", str(report["change_event_id"])),
        ("Campaign", str(report["campaign_id"])),
        ("Incident", str(report["incident_urn"])),
        (
            "Blast radius",
            f"{report['review_receipts']} of {report['candidate_receipts']} receipts",
        ),
        ("Assessment", class_text),
        ("PostgreSQL", f"COMPLETED · attempt {report['attempt_count']}"),
        (
            "Writeback",
            f"VERIFIED · {report['incident_aspect_count']} incident aspects",
        ),
        ("Raw content", "NOT RETURNED"),
    )
    return "\n".join(f"{label:<13} {value}" for label, value in lines)


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    del args
    try:
        report = apply_change()
    except Exception as exc:
        safe = exc if isinstance(exc, GuardedChangeError) else type(exc).__name__
        print(f"GlassBox guarded change failed: {safe}", file=sys.stderr)
        return 1
    print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
