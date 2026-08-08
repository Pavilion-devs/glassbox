"""Live proof: DataHub MCL to incident, receipt quarantine, audit, and retry."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from datahub.emitter.mcp import MetadataChangeProposalWrapper
from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from datahub.metadata.schema_classes import (
    AuditStampClass,
    GenericAspectClass,
    MetadataChangeLogClass,
    NumberTypeClass,
    OtherSchemaClass,
    SchemaFieldClass,
    SchemaFieldDataTypeClass,
    SchemaMetadataClass,
    StringTypeClass,
)
from datahub.metadata.urns import SchemaFieldUrn
from datahub_actions.event.event_envelope import EventEnvelope
from datahub_actions.event.event_registry import (
    METADATA_CHANGE_LOG_EVENT_V1_TYPE,
    MetadataChangeLogEvent,
)
from examples.deterministic_pricing_agent import ORDERS_URN
from examples.end_to_end_receipt import (
    build_signed_receipt,
    demo_signer_trust_policy,
    demo_signing_key,
)

from glassbox_compiler import VerifiedURNResolver
from glassbox_datahub import DataHubInvalidationBackend, DataHubReceiptBackend, ReceiptEmitter
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_invalidation import (
    AppendOnlyCampaignAuditLog,
    InvalidationAction,
    VerifiedReceiptStore,
)
from glassbox_invalidation.datahub_action import (
    GlassBoxInvalidationAction,
    GlassBoxInvalidationActionConfig,
)
from glassbox_policy import FieldCoverage, FieldLineageProof

FIELD_PATH = "average_order_value"
FIELD_URN = str(SchemaFieldUrn(ORDERS_URN, FIELD_PATH))
ACTOR_URN = "urn:li:corpuser:datahub"
BEFORE_TIME_MS = 1786017600000
UNRELATED_TIME_MS = 1786082400000
CHANGE_TIME_MS = 1786104000000


def _schema(
    *,
    native_type: str,
    numeric: bool,
    time_ms: int,
    include_unrelated: bool = False,
    unrelated_field_path: str = "internal_note",
) -> SchemaMetadataClass:
    field_type = (
        NumberTypeClass() if numeric else StringTypeClass()  # type: ignore[no-untyped-call]
    )
    audit = AuditStampClass(time=time_ms, actor=ACTOR_URN)
    raw_fields = [{"name": FIELD_PATH, "type": native_type}]
    schema_fields = [
        SchemaFieldClass(
            fieldPath=FIELD_PATH,
            type=SchemaFieldDataTypeClass(type=field_type),
            nativeDataType=native_type,
            nullable=False,
            description="Synthetic field used by the GlassBox invalidation proof.",
        )
    ]
    if include_unrelated:
        raw_fields.append({"name": unrelated_field_path, "type": "VARCHAR"})
        schema_fields.append(
            SchemaFieldClass(
                fieldPath=unrelated_field_path,
                type=SchemaFieldDataTypeClass(
                    type=StringTypeClass()  # type: ignore[no-untyped-call]
                ),
                nativeDataType="VARCHAR",
                nullable=True,
                description="Synthetic negative-control field.",
            )
        )
    raw_schema = json.dumps(
        {"fields": raw_fields},
        sort_keys=True,
        separators=(",", ":"),
    )
    return SchemaMetadataClass(
        schemaName="commerce.orders",
        platform="urn:li:dataPlatform:postgres",
        version=0,
        hash=hashlib.sha256(raw_schema.encode()).hexdigest(),
        platformSchema=OtherSchemaClass(rawSchema=raw_schema),
        fields=schema_fields,
        created=audit,
        lastModified=audit,
    )


def _generic_aspect(aspect: SchemaMetadataClass) -> GenericAspectClass:
    value = json.dumps(aspect.to_obj(), sort_keys=True, separators=(",", ":")).encode()
    return GenericAspectClass(value=value, contentType="application/json")


def _emit_schema(graph: DataHubGraph, aspect: SchemaMetadataClass) -> None:
    graph.emit(MetadataChangeProposalWrapper(entityUrn=ORDERS_URN, aspect=aspect))
    persisted = graph.get_aspect(ORDERS_URN, SchemaMetadataClass)
    if persisted is None or persisted.hash != aspect.hash:
        raise RuntimeError("schemaMetadata direct readback did not match the emitted version")


def _mcl(
    before: SchemaMetadataClass,
    after: SchemaMetadataClass,
    *,
    event_time_ms: int,
) -> EventEnvelope:
    event = MetadataChangeLogClass(
        entityType="dataset",
        entityUrn=ORDERS_URN,
        aspectName="schemaMetadata",
        changeType="UPSERT",
        previousAspectValue=_generic_aspect(before),
        aspect=_generic_aspect(after),
        created=AuditStampClass(time=event_time_ms, actor=ACTOR_URN),
    )
    return EventEnvelope(
        event_type=METADATA_CHANGE_LOG_EVENT_V1_TYPE,
        event=MetadataChangeLogEvent.from_class(event),
        meta={"source": "glassbox-live-contract-proof"},
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-invalidation")
    parser.add_argument("--server", default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    return parser


def _report(
    *,
    negative_first_reports: tuple[Any, ...],
    negative_second_reports: tuple[Any, ...],
    used_first_reports: tuple[Any, ...],
    used_second_reports: tuple[Any, ...],
    audit: AppendOnlyCampaignAuditLog,
    receipt_id: str,
    document_urn: str,
    field_aspects: tuple[str, ...],
) -> dict[str, Any]:
    negative_first = negative_first_reports[0]
    negative_second = negative_second_reports[0]
    used_first = used_first_reports[0]
    used_second = used_second_reports[0]
    evidence = used_second.write_evidence
    assert evidence is not None
    same_campaign = used_first.campaign.campaign_id == used_second.campaign.campaign_id
    negative_same_campaign = (
        negative_first.campaign.campaign_id == negative_second.campaign.campaign_id
    )
    return {
        "valid": (
            negative_first.valid
            and negative_second.valid
            and negative_first.no_op
            and negative_second.no_op
            and negative_same_campaign
            and used_first.valid
            and used_second.valid
            and same_campaign
        ),
        "datahub": {
            "server_version": "1.6.0",
            "sdk_version": "1.6.0.15",
            "actions_version": "1.6.0.15",
            "schema_field_urn": FIELD_URN,
            "schema_field_aspects": list(field_aspects),
            "incident_aspects": list(evidence.incident_aspects),
            "target_summary_verified": evidence.target_summary_verified,
            "quarantined_documents": list(evidence.quarantined_documents),
        },
        "receipt": {"receipt_id": receipt_id, "document_urn": document_urn},
        "change": {
            "event_id": used_first.campaign.change.event_id,
            "kind": used_first.campaign.change.kind.value,
            "field_urn": used_first.campaign.change.schema_field_urn,
        },
        "campaign": {
            "campaign_id": used_first.campaign.campaign_id,
            "incident_urn": used_first.campaign.incident_urn,
            "classification": used_first.campaign.quarantined[0].state.value,
            "reason_code": used_first.campaign.quarantined[0].reason_code,
            "policy_version": used_first.campaign.policy_version,
            "deliveries": 2,
            "emissions_per_delivery": used_first.emissions,
            "same_campaign_on_redelivery": same_campaign,
        },
        "negative_control": {
            "change_kind": negative_first.campaign.change.kind.value,
            "field_urn": negative_first.campaign.change.schema_field_urn,
            "classification": negative_first.campaign.assessments[0].state.value,
            "reason_code": negative_first.campaign.assessments[0].reason_code,
            "no_op": negative_first.no_op,
            "emissions_per_delivery": negative_first.emissions,
            "same_campaign_on_redelivery": negative_same_campaign,
        },
        "audit": {
            "record_count": len(audit.read_records()),
            "phases": [item.phase.value for item in audit.read_records()],
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=args.token))
    graph.test_connection()
    before = _schema(native_type="VARCHAR", numeric=False, time_ms=BEFORE_TIME_MS)
    after_unrelated = _schema(
        native_type="VARCHAR",
        numeric=False,
        time_ms=UNRELATED_TIME_MS,
        include_unrelated=True,
    )
    after = _schema(
        native_type="DECIMAL(18,2)",
        numeric=True,
        time_ms=CHANGE_TIME_MS,
        include_unrelated=True,
    )

    _emit_schema(graph, before)
    receipt_backend = DataHubReceiptBackend(server=server, token=args.token)
    receipt_backend.test_connection()
    signing_key = demo_signing_key()
    trust_policy = demo_signer_trust_policy(signing_key)
    receipt = build_signed_receipt(
        urn_resolver=VerifiedURNResolver(receipt_backend),
        schema_field_urn=FIELD_URN,
        signing_key=signing_key,
    )
    receipt_emission = ReceiptEmitter(
        receipt_backend,
        signer_trust_policy=trust_policy,
    ).emit_verified(receipt)

    with TemporaryDirectory(prefix="glassbox-invalidation-") as directory:
        state_dir = Path(directory)
        policy_path = state_dir / "trusted-signers.json"
        policy_path.write_text(json.dumps(trust_policy.to_dict()), encoding="utf-8")
        store = VerifiedReceiptStore(
            state_dir / "receipts.jsonl",
            signer_trust_policy=trust_policy,
        )
        store.register(
            receipt,
            field_lineage=FieldLineageProof(
                coverage=FieldCoverage.COMPLETE,
                rule_id="glassbox.runtime-field-observation.v1",
                wildcard_query=False,
            ),
        )
        audit = AppendOnlyCampaignAuditLog(state_dir / "audit.jsonl")
        backend = DataHubInvalidationBackend.from_graph(graph)
        backend.test_connection()
        plugin = GlassBoxInvalidationAction(
            GlassBoxInvalidationActionConfig(
                receipt_store_path=store.path,
                audit_log_path=audit.path,
                signer_trust_policy_path=policy_path,
            ),
            InvalidationAction(backend, audit),
            store,
        )
        _emit_schema(graph, after_unrelated)
        negative_envelope = _mcl(
            before,
            after_unrelated,
            event_time_ms=UNRELATED_TIME_MS,
        )
        if not plugin.act(negative_envelope):
            raise RuntimeError("first negative-control delivery was not acknowledged")
        negative_first_reports = plugin.last_reports
        if not plugin.act(negative_envelope):
            raise RuntimeError("second negative-control delivery was not acknowledged")
        negative_second_reports = plugin.last_reports

        _emit_schema(graph, after)
        used_envelope = _mcl(
            after_unrelated,
            after,
            event_time_ms=CHANGE_TIME_MS,
        )
        if not plugin.act(used_envelope):
            raise RuntimeError("first Actions delivery was not acknowledged")
        used_first_reports = plugin.last_reports
        if not plugin.act(used_envelope):
            raise RuntimeError("second Actions delivery was not acknowledged")
        used_second_reports = plugin.last_reports

        field_raw = graph.get_entity_raw(FIELD_URN)
        raw_aspects = field_raw.get("aspects")
        field_aspects = (
            tuple(sorted(key for key, value in raw_aspects.items() if value is not None))
            if isinstance(raw_aspects, dict)
            else ()
        )
        report = _report(
            negative_first_reports=negative_first_reports,
            negative_second_reports=negative_second_reports,
            used_first_reports=used_first_reports,
            used_second_reports=used_second_reports,
            audit=audit,
            receipt_id=receipt["receipt_id"],
            document_urn=receipt_emission.document_urn,
            field_aspects=field_aspects,
        )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
