"""Pinned DataHub Actions MCL normalization and plugin contract tests."""

from __future__ import annotations

import json
from importlib.metadata import entry_points
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datahub.metadata.schema_classes import (
    AuditStampClass,
    GenericAspectClass,
    MetadataChangeLogClass,
)
from datahub.metadata.urns import SchemaFieldUrn
from datahub_actions.action.action_registry import action_registry
from datahub_actions.event.event import PlaceholderEvent
from datahub_actions.event.event_envelope import EventEnvelope
from datahub_actions.event.event_registry import (
    METADATA_CHANGE_LOG_EVENT_V1_TYPE,
    MetadataChangeLogEvent,
)

from glassbox_dbom import SigningKey, seal_receipt
from glassbox_invalidation import (
    AppendOnlyCampaignAuditLog,
    InvalidationAction,
    MCLNormalizationError,
    ReceiptStoreError,
    VerifiedReceiptStore,
    normalize_metadata_change_log,
)
from glassbox_invalidation.datahub_action import (
    GlassBoxInvalidationAction,
    GlassBoxInvalidationActionConfig,
)
from glassbox_policy import (
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    InvalidationCampaign,
    InvalidationWriteEvidence,
)
from tests.helpers import receipt_payload

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
OTHER_DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.customers,PROD)"
FIELD = str(SchemaFieldUrn(DATASET, "revenue"))
EVENT_TIME_MS = 1786060800000


def _aspect(
    value: dict[str, object], *, content_type: str = "application/json"
) -> GenericAspectClass:
    return GenericAspectClass(
        value=json.dumps(value, sort_keys=True, separators=(",", ":")).encode(),
        contentType=content_type,
    )


def _mcl(
    *,
    aspect_name: str,
    before: dict[str, object] | None,
    after: dict[str, object] | None,
    entity_urn: str = DATASET,
    change_type: str = "UPSERT",
    with_time: bool = True,
) -> MetadataChangeLogClass:
    return MetadataChangeLogClass(
        entityType="dataset",
        entityUrn=entity_urn,
        aspectName=aspect_name,
        changeType=change_type,
        previousAspectValue=_aspect(before) if before is not None else None,
        aspect=_aspect(after) if after is not None else None,
        created=(
            AuditStampClass(time=EVENT_TIME_MS, actor="urn:li:corpuser:datahub")
            if with_time
            else None
        ),
    )


def _schema(field_path: str, native_type: str) -> dict[str, object]:
    return {
        "schemaName": "orders",
        "fields": [
            {
                "fieldPath": field_path,
                "nativeDataType": native_type,
                "type": {"type": {"stringType": {}}},
            }
        ],
    }


def _signed_receipt(*, datahub_urn: str | None = DATASET, field_urn: str | None = FIELD) -> dict:
    payload = receipt_payload()
    evidence = payload["evidence"][0]
    evidence["datahub_urn"] = datahub_urn
    evidence["schema_field_urn"] = field_urn
    if datahub_urn is None:
        evidence["state"] = "UNKNOWN"
        evidence["source_span_id"] = None
        evidence["observed_at"] = None
        evidence["provenance"] = {
            "capture_method": "UNAVAILABLE",
            "rule_id": None,
            "confidence": None,
        }
    key = SigningKey("mcl-plugin-test", Ed25519PrivateKey.generate())
    return seal_receipt(payload, signing_keys=(key,))


class FakeCampaignBackend:
    def __init__(self) -> None:
        self.campaigns: list[InvalidationCampaign] = []

    def upsert_campaign(self, campaign: InvalidationCampaign) -> None:
        self.campaigns.append(campaign)

    def direct_verify(self, campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
        return InvalidationWriteEvidence(
            incident_aspects=("incidentInfo", "incidentKey"),
            target_summary_verified=True,
            quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
        )


def test_schema_metadata_mcl_emits_precise_added_removed_and_type_changes() -> None:
    removed = normalize_metadata_change_log(
        _mcl(aspect_name="schemaMetadata", before=_schema("legacy", "TEXT"), after={"fields": []})
    )
    added = normalize_metadata_change_log(
        _mcl(aspect_name="schemaMetadata", before={"fields": []}, after=_schema("new", "TEXT"))
    )
    changed = normalize_metadata_change_log(
        _mcl(
            aspect_name="schemaMetadata",
            before=_schema("revenue", "TEXT"),
            after=_schema("revenue", "DECIMAL"),
        )
    )

    assert removed[0].kind is ChangeKind.SCHEMA_FIELD_REMOVED
    assert removed[0].schema_field_urn == str(SchemaFieldUrn(DATASET, "legacy"))
    assert added[0].kind is ChangeKind.SCHEMA_FIELD_ADDED
    assert changed[0].kind is ChangeKind.SCHEMA_FIELD_TYPE_CHANGED
    assert changed[0].schema_field_urn == FIELD
    assert changed[0].occurred_at == "2026-08-07T00:00:00Z"
    assert changed == normalize_metadata_change_log(
        _mcl(
            aspect_name="schemaMetadata",
            before=_schema("revenue", "TEXT"),
            after=_schema("revenue", "DECIMAL"),
        )
    )


def test_non_type_schema_edit_is_dataset_wide_and_restate_is_ignored() -> None:
    before = _schema("revenue", "DECIMAL")
    after = {**before, "platformSchema": {"otherSchema": {"rawSchema": "changed"}}}

    changes = normalize_metadata_change_log(
        _mcl(aspect_name="schemaMetadata", before=before, after=after)
    )
    restate = normalize_metadata_change_log(
        _mcl(
            aspect_name="schemaMetadata",
            before=before,
            after=after,
            change_type="RESTATE",
        )
    )

    assert [item.kind for item in changes] == [ChangeKind.SCHEMA_CHANGED]
    assert restate == ()


def test_incident_normalization_targets_assets_and_guards_glassbox_feedback_loop() -> None:
    freshness = {
        "type": "FRESHNESS",
        "entities": [FIELD],
        "status": {"state": "ACTIVE", "stage": "TRIAGE"},
    }
    glassbox = {
        "type": "CUSTOM",
        "customType": "GLASSBOX_INVALIDATION",
        "entities": [DATASET],
        "status": {"state": "ACTIVE", "stage": "TRIAGE"},
    }
    resolved = {
        "type": "FIELD",
        "entities": [DATASET],
        "status": {"state": "RESOLVED", "stage": "FIXED"},
    }

    changes = normalize_metadata_change_log(
        _mcl(
            aspect_name="incidentInfo",
            before=None,
            after=freshness,
            entity_urn="urn:li:incident:synthetic.freshness",
        )
    )

    assert len(changes) == 1
    assert changes[0].kind is ChangeKind.FRESHNESS_INCIDENT
    assert changes[0].entity_urn == DATASET
    assert changes[0].schema_field_urn == FIELD
    assert (
        normalize_metadata_change_log(
            _mcl(
                aspect_name="incidentInfo",
                before=None,
                after=glassbox,
                entity_urn="urn:li:incident:glassbox.invalidation.synthetic",
            )
        )
        == ()
    )
    assert (
        normalize_metadata_change_log(
            _mcl(
                aspect_name="incidentInfo",
                before=None,
                after=resolved,
                entity_urn="urn:li:incident:synthetic.resolved",
            )
        )
        == ()
    )


def test_governance_deprecation_and_supersession_triggers_are_closed() -> None:
    deprecated = normalize_metadata_change_log(
        _mcl(aspect_name="status", before={"removed": False}, after={"removed": True})
    )
    ownership = normalize_metadata_change_log(
        _mcl(aspect_name="ownership", before={"owners": []}, after={"owners": ["synthetic"]})
    )
    superseded = normalize_metadata_change_log(
        _mcl(
            aspect_name="documentInfo",
            before={"customProperties": {}},
            after={
                "customProperties": {"glassbox.superseded_by": "gbx:receipt:sha256:" + "f" * 64}
            },
            entity_urn="urn:li:document:synthetic.receipt",
        )
    )

    assert deprecated[0].kind is ChangeKind.ASSET_DEPRECATED
    assert ownership[0].kind is ChangeKind.OWNERSHIP_CHANGED
    assert superseded[0].kind is ChangeKind.DOCUMENT_SUPERSEDED


def test_malformed_supported_mcl_fails_for_framework_retry() -> None:
    duplicate_fields = {
        "fields": [
            {"fieldPath": "id", "nativeDataType": "TEXT"},
            {"fieldPath": "id", "nativeDataType": "TEXT"},
        ]
    }
    with pytest.raises(MCLNormalizationError, match="duplicates fieldPath"):
        normalize_metadata_change_log(
            _mcl(aspect_name="schemaMetadata", before={"fields": []}, after=duplicate_fields)
        )
    with pytest.raises(MCLNormalizationError, match="authoritative event time"):
        normalize_metadata_change_log(
            _mcl(
                aspect_name="schemaMetadata",
                before={"fields": []},
                after=_schema("id", "TEXT"),
                with_time=False,
            )
        )
    event = _mcl(aspect_name="schemaMetadata", before={"fields": []}, after=None)
    event.aspect = _aspect({}, content_type="text/plain")
    with pytest.raises(MCLNormalizationError, match="content type"):
        normalize_metadata_change_log(event)


def test_verified_receipt_store_is_idempotent_and_indexes_unresolved_evidence(
    tmp_path: Path,
) -> None:
    path = tmp_path / "receipts.jsonl"
    store = VerifiedReceiptStore(path, sync=False)
    receipt = _signed_receipt()
    lineage = FieldLineageProof(
        coverage=FieldCoverage.COMPLETE,
        rule_id="glassbox.sql-column-lineage.v1",
        wildcard_query=False,
    )

    assert store.register(receipt, field_lineage=lineage)
    assert not store.register(receipt, field_lineage=lineage)
    reloaded = VerifiedReceiptStore(path, sync=False)
    assert reloaded.all_profiles()[0].field_lineage == lineage

    exact_change = normalize_metadata_change_log(
        _mcl(
            aspect_name="schemaMetadata",
            before=_schema("revenue", "TEXT"),
            after=_schema("revenue", "DECIMAL"),
        )
    )[0]
    unrelated_change = normalize_metadata_change_log(
        _mcl(
            aspect_name="schemaMetadata",
            before=_schema("id", "TEXT"),
            after=_schema("id", "BIGINT"),
            entity_urn=OTHER_DATASET,
        )
    )[0]
    assert len(reloaded.candidates(exact_change)) == 1
    assert reloaded.candidates(unrelated_change) == ()

    unresolved_path = tmp_path / "unresolved.jsonl"
    unresolved = VerifiedReceiptStore(unresolved_path, sync=False)
    unresolved.register(_signed_receipt(datahub_urn=None, field_urn=None))
    assert len(unresolved.candidates(unrelated_change)) == 1

    with pytest.raises(ReceiptStoreError, match="conflicting dependency metadata"):
        store.register(receipt, field_lineage=FieldLineageProof())


def test_receipt_store_detects_truncation_and_tampering(tmp_path: Path) -> None:
    path = tmp_path / "receipts.jsonl"
    store = VerifiedReceiptStore(path, sync=False)
    store.register(_signed_receipt())
    original = path.read_bytes()

    path.write_bytes(original[:-1])
    with pytest.raises(ReceiptStoreError, match="truncated"):
        VerifiedReceiptStore(path, sync=False)

    path.write_bytes(original.replace(b"commerce.orders", b"commerce.poison", 1))
    with pytest.raises(ReceiptStoreError, match="checksum"):
        VerifiedReceiptStore(path, sync=False)


def test_real_actions_envelope_drives_end_to_end_campaign_and_acknowledges(tmp_path: Path) -> None:
    store = VerifiedReceiptStore(tmp_path / "receipts.jsonl", sync=False)
    store.register(_signed_receipt())
    backend = FakeCampaignBackend()
    audit = AppendOnlyCampaignAuditLog(tmp_path / "audit.jsonl", sync=False)
    action = GlassBoxInvalidationAction(
        GlassBoxInvalidationActionConfig(
            receipt_store_path=store.path,
            audit_log_path=audit.path,
            sync_audit=False,
            require_trusted_receipt_signer=False,
        ),
        InvalidationAction(backend, audit),
        store,
    )
    mcl = _mcl(
        aspect_name="schemaMetadata",
        before=_schema("revenue", "TEXT"),
        after=_schema("revenue", "DECIMAL"),
    )
    envelope = EventEnvelope(
        event_type=METADATA_CHANGE_LOG_EVENT_V1_TYPE,
        event=MetadataChangeLogEvent.from_class(mcl),
        meta={"topic": "MetadataChangeLog_Versioned_v1"},
    )

    assert action.act(envelope)
    assert len(action.last_reports) == 1
    assert action.last_reports[0].valid
    assert action.last_reports[0].campaign.quarantined[0].state.value == "STALE"
    assert len(backend.campaigns) == 2

    ignored = EventEnvelope(event_type="Unsupported_v1", event=PlaceholderEvent(), meta={})
    assert action.act(ignored)
    assert action.last_reports == ()
    action.close()


def test_plugin_is_discoverable_through_the_real_actions_entry_point_registry() -> None:
    matching = [
        entry_point
        for entry_point in entry_points(group="datahub_actions.action.plugins")
        if entry_point.name == "glassbox_invalidation"
    ]

    assert [item.value for item in matching] == [
        "glassbox_invalidation.datahub_action:GlassBoxInvalidationAction"
    ]
    assert action_registry.get("glassbox_invalidation") is GlassBoxInvalidationAction
