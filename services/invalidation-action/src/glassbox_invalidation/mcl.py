"""Strict DataHub MetadataChangeLog normalization for materiality policy v1."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from glassbox_dbom.canonical import canonicalize
from glassbox_policy import ChangeKind, NormalizedChange

_SUPPORTED_CONTENT_TYPE = "application/json"


class MCLNormalizationError(ValueError):
    """Raised when a supported MCL cannot be normalized without invention."""


def normalize_metadata_change_log(event: Any) -> tuple[NormalizedChange, ...]:
    """Convert a pinned DataHub MCL into zero or more closed policy changes."""

    if event.changeType == "RESTATE":
        return ()
    entity_urn = event.entityUrn
    aspect_name = event.aspectName
    if not isinstance(entity_urn, str) or not entity_urn.startswith("urn:li:"):
        raise MCLNormalizationError("MCL entityUrn must be a DataHub URN")
    if not isinstance(aspect_name, str) or not aspect_name:
        raise MCLNormalizationError("MCL aspectName must be non-empty")
    occurred_at = _occurred_at(event)
    before = _parse_aspect(event.previousAspectValue)
    after = _parse_aspect(event.aspect)
    before_digest = _aspect_digest(event.previousAspectValue)
    after_digest = _aspect_digest(event.aspect)

    candidates: list[tuple[ChangeKind, str, str | None, str | None, str | None]] = []
    if aspect_name == "schemaMetadata":
        candidates.extend(_schema_changes(entity_urn, before, after))
    elif aspect_name in {"status", "deprecation"} and _became_deprecated(after, before):
        candidates.append(
            (ChangeKind.ASSET_DEPRECATED, entity_urn, None, before_digest, after_digest)
        )
    elif aspect_name == "ownership" and before != after:
        candidates.append(
            (ChangeKind.OWNERSHIP_CHANGED, entity_urn, None, before_digest, after_digest)
        )
    elif aspect_name == "glossaryTermInfo" and before.get("definition") != after.get("definition"):
        candidates.append(
            (
                ChangeKind.GLOSSARY_DEFINITION_CHANGED,
                entity_urn,
                None,
                before_digest,
                after_digest,
            )
        )
    elif aspect_name == "incidentInfo":
        candidates.extend(_incident_changes(before, after, before_digest, after_digest))
    elif aspect_name == "documentInfo" and _superseding_receipt(before) != _superseding_receipt(
        after
    ):
        if _superseding_receipt(after) is not None:
            candidates.append(
                (
                    ChangeKind.DOCUMENT_SUPERSEDED,
                    entity_urn,
                    None,
                    before_digest,
                    after_digest,
                )
            )

    return tuple(
        _change(
            event=event,
            target_urn=target_urn,
            aspect_name=aspect_name,
            kind=kind,
            occurred_at=occurred_at,
            schema_field_urn=field_urn,
            before_digest=candidate_before,
            after_digest=candidate_after,
        )
        for kind, target_urn, field_urn, candidate_before, candidate_after in candidates
    )


def _schema_changes(
    dataset_urn: str,
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> list[tuple[ChangeKind, str, str | None, str | None, str | None]]:
    from datahub.metadata.urns import SchemaFieldUrn

    before_fields = _field_map(before)
    after_fields = _field_map(after)
    changes: list[tuple[ChangeKind, str, str | None, str | None, str | None]] = []
    for field_path in sorted(before_fields.keys() - after_fields.keys()):
        changes.append(
            (
                ChangeKind.SCHEMA_FIELD_REMOVED,
                dataset_urn,
                str(SchemaFieldUrn(dataset_urn, field_path)),
                _mapping_digest(before_fields[field_path]),
                None,
            )
        )
    for field_path in sorted(after_fields.keys() - before_fields.keys()):
        changes.append(
            (
                ChangeKind.SCHEMA_FIELD_ADDED,
                dataset_urn,
                str(SchemaFieldUrn(dataset_urn, field_path)),
                None,
                _mapping_digest(after_fields[field_path]),
            )
        )
    for field_path in sorted(before_fields.keys() & after_fields.keys()):
        old_field = before_fields[field_path]
        new_field = after_fields[field_path]
        if _field_type_material(old_field) != _field_type_material(new_field):
            changes.append(
                (
                    ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
                    dataset_urn,
                    str(SchemaFieldUrn(dataset_urn, field_path)),
                    _mapping_digest(old_field),
                    _mapping_digest(new_field),
                )
            )
    if not changes and before != after:
        changes.append(
            (
                ChangeKind.SCHEMA_CHANGED,
                dataset_urn,
                None,
                _mapping_digest(before),
                _mapping_digest(after),
            )
        )
    return changes


def _field_map(aspect: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    raw_fields = aspect.get("fields", [])
    if raw_fields is None:
        return {}
    if not isinstance(raw_fields, list):
        raise MCLNormalizationError("schemaMetadata fields must be an array")
    fields: dict[str, Mapping[str, Any]] = {}
    for raw_field in raw_fields:
        if not isinstance(raw_field, Mapping):
            raise MCLNormalizationError("schemaMetadata field entries must be objects")
        field_path = raw_field.get("fieldPath")
        if not isinstance(field_path, str) or not field_path:
            raise MCLNormalizationError("schemaMetadata fieldPath must be non-empty")
        if field_path in fields:
            raise MCLNormalizationError(f"schemaMetadata duplicates fieldPath {field_path!r}")
        fields[field_path] = raw_field
    return fields


def _field_type_material(field: Mapping[str, Any]) -> bytes:
    return canonicalize(
        {
            "nativeDataType": field.get("nativeDataType"),
            "type": field.get("type"),
        }
    )


def _incident_changes(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    before_digest: str | None,
    after_digest: str | None,
) -> list[tuple[ChangeKind, str, str | None, str | None, str | None]]:
    del before
    if after.get("customType") == "GLASSBOX_INVALIDATION":
        return []
    status = after.get("status")
    if isinstance(status, Mapping) and status.get("state") == "RESOLVED":
        return []
    raw_entities = after.get("entities", [])
    if not isinstance(raw_entities, list):
        raise MCLNormalizationError("incidentInfo entities must be an array")
    kind = (
        ChangeKind.FRESHNESS_INCIDENT
        if after.get("type") == "FRESHNESS"
        else ChangeKind.ASSERTION_FAILED
    )
    entity_urns: list[str] = []
    for raw_urn in raw_entities:
        if not isinstance(raw_urn, str) or not raw_urn.startswith("urn:li:"):
            raise MCLNormalizationError("incidentInfo entities must contain DataHub URNs")
        entity_urns.append(raw_urn)
    changes = []
    for raw_urn in sorted(entity_urns):
        target_urn, field_urn = _incident_target(raw_urn)
        changes.append((kind, target_urn, field_urn, before_digest, after_digest))
    return changes


def _incident_target(urn: str) -> tuple[str, str | None]:
    if not urn.startswith("urn:li:schemaField:"):
        return urn, None
    from datahub.metadata.urns import SchemaFieldUrn

    parsed = SchemaFieldUrn.from_string(urn)
    return str(parsed.parent), urn


def _became_deprecated(after: Mapping[str, Any], before: Mapping[str, Any]) -> bool:
    after_value = after.get("removed") is True or after.get("deprecated") is True
    before_value = before.get("removed") is True or before.get("deprecated") is True
    return after_value and not before_value


def _superseding_receipt(aspect: Mapping[str, Any]) -> str | None:
    properties = aspect.get("customProperties")
    if not isinstance(properties, Mapping):
        return None
    value = properties.get("glassbox.superseded_by")
    return value if isinstance(value, str) and value else None


def _parse_aspect(value: Any) -> Mapping[str, Any]:
    if value is None:
        return {}
    if value.contentType != _SUPPORTED_CONTENT_TYPE:
        raise MCLNormalizationError(f"unsupported MCL aspect content type: {value.contentType}")
    try:
        parsed = json.loads(value.value)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCLNormalizationError("MCL aspect is not valid JSON") from exc
    if not isinstance(parsed, Mapping):
        raise MCLNormalizationError("MCL aspect JSON must be an object")
    return parsed


def _aspect_digest(value: Any) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(bytes(value.value)).hexdigest()


def _mapping_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonicalize(value)).hexdigest()


def _occurred_at(event: Any) -> str:
    milliseconds: int | None = None
    if event.created is not None:
        milliseconds = event.created.time
    elif event.systemMetadata is not None and event.systemMetadata.aspectModified is not None:
        milliseconds = event.systemMetadata.aspectModified.time
    elif event.auditHeader is not None:
        milliseconds = event.auditHeader.time
    if isinstance(milliseconds, bool) or not isinstance(milliseconds, int) or milliseconds < 0:
        raise MCLNormalizationError("MCL has no valid authoritative event time")
    from datetime import UTC, datetime

    return datetime.fromtimestamp(milliseconds / 1000, tz=UTC).isoformat().replace("+00:00", "Z")


def _change(
    *,
    event: Any,
    target_urn: str,
    aspect_name: str,
    kind: ChangeKind,
    occurred_at: str,
    schema_field_urn: str | None,
    before_digest: str | None,
    after_digest: str | None,
) -> NormalizedChange:
    material = {
        "entity_urn": target_urn,
        "source_entity_urn": event.entityUrn,
        "aspect_name": aspect_name,
        "change_type": event.changeType,
        "kind": kind.value,
        "occurred_at": occurred_at,
        "schema_field_urn": schema_field_urn,
        "before_digest": before_digest,
        "after_digest": after_digest,
    }
    digest = hashlib.sha256(canonicalize(material)).hexdigest()
    return NormalizedChange(
        event_id=f"datahub:mcl:sha256:{digest}",
        entity_urn=target_urn,
        aspect_name=aspect_name,
        kind=kind,
        occurred_at=occurred_at,
        schema_field_urn=schema_field_urn,
        before_digest=before_digest,
        after_digest=after_digest,
    )
