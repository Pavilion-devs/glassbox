"""Closed-surface tests for the filmed production schema-change helper."""

from __future__ import annotations

import json

import pytest
from datahub.metadata.schema_classes import (
    AuditStampClass,
    NumberTypeClass,
    OtherSchemaClass,
    SchemaFieldClass,
    SchemaFieldDataTypeClass,
    SchemaMetadataClass,
)

from glassbox_policy import ChangeKind, NormalizedChange
from scripts.guarded_schema_change import (
    ACTOR_URN,
    DEMO_AFTER_TYPE,
    FIELD_PATH,
    SCHEMA_FIELD_URN,
    GuardedChangeError,
    _allowlisted_change,
    _changed_schema,
    _operator_graph,
    _parser,
)
from scripts.remote_guarded_schema_change import REMOTE_COMMAND
from scripts.remote_guarded_schema_change import main as remote_main


def _schema(native_type: str = "decimal(18,2)") -> SchemaMetadataClass:
    raw = json.dumps(
        {
            "fields": [
                {"name": "order_id", "type": "varchar(64)"},
                {"name": FIELD_PATH, "type": native_type},
            ]
        }
    )
    audit = AuditStampClass(time=1, actor=ACTOR_URN)
    return SchemaMetadataClass(
        schemaName="commerce.orders",
        platform="urn:li:dataPlatform:postgres",
        version=0,
        hash="a" * 64,
        platformSchema=OtherSchemaClass(rawSchema=raw),
        fields=[
            SchemaFieldClass(
                fieldPath=FIELD_PATH,
                type=SchemaFieldDataTypeClass(type=NumberTypeClass()),  # type: ignore[no-untyped-call]
                nativeDataType=native_type,
                nullable=False,
            )
        ],
        created=audit,
        lastModified=audit,
    )


def test_change_is_fixed_consistent_and_does_not_mutate_source() -> None:
    source = _schema()
    changed = _changed_schema(source, changed_at_ms=1000)

    assert source.fields[0].nativeDataType == "decimal(18,2)"
    assert changed.fields[0].nativeDataType == DEMO_AFTER_TYPE
    assert changed.fields[0].type.type.__class__.__name__ == "StringTypeClass"
    assert json.loads(changed.platformSchema.rawSchema)["fields"][1]["type"] == DEMO_AFTER_TYPE
    assert changed.hash != source.hash


def test_change_rejects_drift_and_cli_accepts_no_mutation_parameters() -> None:
    with pytest.raises(GuardedChangeError, match="expected pre-change"):
        _changed_schema(_schema("varchar(64)"), changed_at_ms=1000)
    with pytest.raises(SystemExit):
        _parser().parse_args(["apply", "--server", "https://example.com"])
    assert remote_main(["--server", "https://example.com"]) == 2
    assert "guarded_schema_change.py apply" in REMOTE_COMMAND
    assert "DATAHUB_GMS_TOKEN" not in REMOTE_COMMAND
    assert "DATAHUB_SYSTEM_CLIENT_SECRET" in REMOTE_COMMAND
    assert 'GLASSBOX_DATAHUB_OPERATOR_CLIENT_SECRET="$datahub_operator_secret"' in REMOTE_COMMAND


def test_operator_graph_requires_a_separate_one_shot_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GLASSBOX_DATAHUB_OPERATOR_CLIENT_ID", raising=False)
    monkeypatch.delenv("GLASSBOX_DATAHUB_OPERATOR_CLIENT_SECRET", raising=False)
    with pytest.raises(GuardedChangeError, match="one-shot DataHub operator credential"):
        _operator_graph("http://datahub-gms:8080")


def test_resume_filter_accepts_only_the_fixed_schema_field_change() -> None:
    change = NormalizedChange(
        event_id="datahub:mcl:sha256:" + "1" * 64,
        entity_urn="urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)",
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-10T20:00:00Z",
        schema_field_urn=SCHEMA_FIELD_URN,
        before_digest="2" * 64,
        after_digest="3" * 64,
    )
    assert _allowlisted_change(change)

    drifted = NormalizedChange(
        event_id=change.event_id,
        entity_urn=change.entity_urn,
        aspect_name=change.aspect_name,
        kind=change.kind,
        occurred_at=change.occurred_at,
        schema_field_urn=str(SCHEMA_FIELD_URN).replace("average_order_value", "customer_email"),
        before_digest=change.before_digest,
        after_digest=change.after_digest,
    )
    assert not _allowlisted_change(drifted)
