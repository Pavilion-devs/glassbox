"""Strict OTLP/HTTP JSON ingestion for the GlassBox OpenTelemetry profile."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

from glassbox.models import (
    EventKind,
    JSONScalar,
    JSONValue,
    RunContext,
    RuntimeEvent,
)
from glassbox.otel import (
    GENAI_SEMCONV_SCHEMA_URL,
    OTelSpanEvent,
    OTelSpanKind,
    OTelSpanRecord,
    OTelSpanStatus,
)
from glassbox_compiler.compiler import CompilationProfile, compile_events
from glassbox_compiler.errors import CompilationError

_HEX_PATTERN = re.compile(r"^[0-9a-f]+$")
_EVIDENCE_ID_DOMAIN = b"glassbox.otlp.evidence-event.v1\0"


class OTLPIngestionError(CompilationError):
    """Raised when OTLP input is malformed, ambiguous, or loses required evidence."""


def compile_otlp_json(
    payload: Mapping[str, Any],
    *,
    profile: CompilationProfile,
    run_span_id: str | None = None,
    max_spans: int = 10_000,
) -> dict[str, Any]:
    """Parse an OTLP/HTTP JSON export and compile exactly one selected agent run."""

    spans = parse_otlp_json(payload, max_spans=max_spans)
    events = normalize_otel_spans(spans, run_span_id=run_span_id)
    return compile_events(events, profile=profile)


def parse_otlp_json(
    payload: Mapping[str, Any], *, max_spans: int = 10_000
) -> tuple[OTelSpanRecord, ...]:
    """Decode the official protobuf-JSON OTLP trace envelope into closed span records."""

    if max_spans < 1:
        raise ValueError("max_spans must be positive")
    resource_spans = _required_list(payload, "resourceSpans")
    records: list[OTelSpanRecord] = []
    for resource_index, resource in enumerate(resource_spans):
        resource_map = _mapping(resource, f"resourceSpans[{resource_index}]")
        resource_schema = _optional_text(resource_map.get("schemaUrl"))
        scope_spans = _required_list(resource_map, "scopeSpans")
        for scope_index, scope in enumerate(scope_spans):
            scope_map = _mapping(
                scope,
                f"resourceSpans[{resource_index}].scopeSpans[{scope_index}]",
            )
            schema_url = _optional_text(scope_map.get("schemaUrl")) or resource_schema
            if schema_url is None:
                raise OTLPIngestionError("OTLP scope is missing its semantic schemaUrl")
            raw_spans = _required_list(scope_map, "spans")
            for span_index, span in enumerate(raw_spans):
                if len(records) >= max_spans:
                    raise OTLPIngestionError(f"OTLP payload exceeds max_spans={max_spans}")
                path = (
                    f"resourceSpans[{resource_index}].scopeSpans[{scope_index}].spans[{span_index}]"
                )
                records.append(_parse_span(_mapping(span, path), schema_url=schema_url, path=path))
    if not records:
        raise OTLPIngestionError("OTLP payload contains no spans")
    return tuple(records)


def normalize_otel_spans(
    spans: Sequence[OTelSpanRecord], *, run_span_id: str | None = None
) -> tuple[RuntimeEvent, ...]:
    """Normalize one selected `invoke_agent` span and its direct tool children."""

    if not spans:
        raise OTLPIngestionError("at least one completed OpenTelemetry span is required")
    seen = {(span.trace_id, span.span_id) for span in spans}
    if len(seen) != len(spans):
        raise OTLPIngestionError("OpenTelemetry trace contains duplicate span identities")
    for span in spans:
        if span.schema_url != GENAI_SEMCONV_SCHEMA_URL:
            raise OTLPIngestionError(
                f"unsupported OpenTelemetry schema URL {span.schema_url!r}; "
                f"expected {GENAI_SEMCONV_SCHEMA_URL!r}"
            )

    candidates = [
        span
        for span in spans
        if span.attributes.get("gen_ai.operation.name") == "invoke_agent"
        and (run_span_id is None or span.span_id == run_span_id)
    ]
    if len(candidates) != 1:
        selection = "selected" if run_span_id is not None else "available"
        raise OTLPIngestionError(
            f"expected exactly one {selection} invoke_agent span, found {len(candidates)}"
        )
    run_span = candidates[0]
    context = _run_context(run_span)
    run_start = _parse_timestamp(run_span.start_time)
    run_end = _parse_timestamp(run_span.end_time)
    if run_end < run_start:
        raise OTLPIngestionError("invoke_agent span ends before it starts")
    run_status = _attribute_text(run_span.attributes, "glassbox.run.status")
    if (run_status == "FAILED") != (run_span.status is OTelSpanStatus.ERROR):
        raise OTLPIngestionError("invoke_agent span status conflicts with glassbox.run.status")
    drafts: list[tuple[datetime, int, int, RuntimeEvent]] = []
    ordinal = 0

    drafts.append(
        (
            run_start,
            0,
            ordinal,
            RuntimeEvent(
                sequence=1,
                occurred_at=run_span.start_time,
                kind=EventKind.RUN_STARTED,
                run=context,
                span_id=run_span.span_id,
                parent_span_id=run_span.parent_span_id,
                attributes={"run.status": "STARTED"},
            ),
        )
    )
    ordinal += 1

    occupied_ids = {span.span_id for span in spans if span.trace_id == run_span.trace_id}
    for event_index, event in enumerate(run_span.events):
        if event.name != EventKind.EVIDENCE_OBSERVED.value:
            continue
        source_span_id = (
            _optional_attribute_text(event.attributes, "glassbox.evidence.source_span_id")
            or run_span.span_id
        )
        evidence_span_id = _evidence_event_id(run_span, event, event_index, occupied_ids)
        occupied_ids.add(evidence_span_id)
        evidence_time = _parse_timestamp(event.occurred_at)
        if not run_start <= evidence_time <= run_end:
            raise OTLPIngestionError("evidence event occurred outside its invoke_agent span")
        attributes: dict[str, JSONValue] = {
            "evidence.entity_type": _attribute(event.attributes, "glassbox.evidence.entity_type"),
            "datahub.urn": event.attributes.get("glassbox.datahub.urn"),
            "datahub.schema_field_urn": event.attributes.get("glassbox.datahub.schema_field_urn"),
            "evidence.state": _attribute(event.attributes, "glassbox.evidence.state"),
            "evidence.role": _attribute(event.attributes, "glassbox.evidence.role"),
            "evidence.representation_digest": event.attributes.get(
                "glassbox.evidence.representation_digest"
            ),
            "evidence.capture_method": (
                event.attributes.get("glassbox.evidence.capture_method") or "OTEL_SPAN"
            ),
            "evidence.rule_id": event.attributes.get("glassbox.evidence.rule_id"),
            "evidence.confidence": event.attributes.get("glassbox.evidence.confidence"),
            "evidence.source_span_id": source_span_id,
            "metadata": {},
        }
        drafts.append(
            (
                evidence_time,
                1,
                ordinal,
                RuntimeEvent(
                    sequence=1,
                    occurred_at=event.occurred_at,
                    kind=EventKind.EVIDENCE_OBSERVED,
                    run=context,
                    span_id=evidence_span_id,
                    parent_span_id=run_span.span_id,
                    attributes=attributes,
                ),
            )
        )
        ordinal += 1

    action_spans = sorted(
        (
            span
            for span in spans
            if span.trace_id == run_span.trace_id
            and span.parent_span_id == run_span.span_id
            and span.attributes.get("gen_ai.operation.name") == "execute_tool"
            and span.attributes.get("glassbox.run.id") == context.run_id
        ),
        key=lambda span: (_parse_timestamp(span.end_time), span.span_id),
    )
    for span in action_spans:
        occupied_ids.add(span.span_id)
        action_start = _parse_timestamp(span.start_time)
        action_end = _parse_timestamp(span.end_time)
        if action_end < action_start:
            raise OTLPIngestionError(f"execute_tool span {span.span_id} ends before it starts")
        if action_start < run_start or action_end > run_end:
            raise OTLPIngestionError(
                f"execute_tool span {span.span_id} falls outside its invoke_agent span"
            )
        action_status = _attribute_text(span.attributes, "glassbox.action.status")
        action_error = action_status in {"FAILED", "BLOCKED"}
        if action_error != (span.status is OTelSpanStatus.ERROR):
            raise OTLPIngestionError(
                f"execute_tool span {span.span_id} status conflicts with glassbox.action.status"
            )
        action_attributes: dict[str, JSONValue] = {
            "tool.id": _attribute(span.attributes, "gen_ai.tool.name"),
            "action.effect": _attribute(span.attributes, "glassbox.action.effect"),
            "action.status": action_status,
            "action.input_digest": _attribute(span.attributes, "glassbox.action.input_digest"),
            "action.output_digest": span.attributes.get("glassbox.action.output_digest"),
            "action.idempotency_key": span.attributes.get("glassbox.action.idempotency_key"),
            "action.approval_id": span.attributes.get("glassbox.approval.receipt_id"),
            "error.type": span.attributes.get("error.type"),
            "metadata": {},
        }
        drafts.append(
            (
                action_end,
                2,
                ordinal,
                RuntimeEvent(
                    sequence=1,
                    occurred_at=span.end_time,
                    kind=EventKind.ACTION_FINISHED,
                    run=context,
                    span_id=span.span_id,
                    parent_span_id=run_span.span_id,
                    attributes=action_attributes,
                ),
            )
        )
        ordinal += 1

    finish_attributes: dict[str, JSONValue] = {
        "run.status": _attribute(run_span.attributes, "glassbox.run.status"),
        "output.digest": run_span.attributes.get("glassbox.output.digest"),
        "error.type": run_span.attributes.get("error.type"),
    }
    drafts.append(
        (
            run_end,
            3,
            ordinal,
            RuntimeEvent(
                sequence=1,
                occurred_at=run_span.end_time,
                kind=EventKind.RUN_FINISHED,
                run=context,
                span_id=run_span.span_id,
                parent_span_id=run_span.parent_span_id,
                attributes=finish_attributes,
            ),
        )
    )
    ordered = sorted(drafts, key=lambda item: (item[0], item[1], item[2]))
    return tuple(
        RuntimeEvent(
            sequence=index,
            occurred_at=event.occurred_at,
            kind=event.kind,
            run=event.run,
            span_id=event.span_id,
            parent_span_id=event.parent_span_id,
            attributes=event.attributes,
        )
        for index, (_, _, _, event) in enumerate(ordered, start=1)
    )


def _parse_span(span: Mapping[str, Any], *, schema_url: str, path: str) -> OTelSpanRecord:
    if _integer(span.get("droppedAttributesCount", 0), f"{path}.droppedAttributesCount"):
        raise OTLPIngestionError(f"{path} dropped attributes required for provenance")
    if _integer(span.get("droppedEventsCount", 0), f"{path}.droppedEventsCount"):
        raise OTLPIngestionError(f"{path} dropped events required for provenance")
    kind = span.get("kind")
    if kind not in {1, "SPAN_KIND_INTERNAL"}:
        raise OTLPIngestionError(f"{path}.kind must be SPAN_KIND_INTERNAL")
    status_map = _mapping(span.get("status", {}), f"{path}.status")
    status_code = status_map.get("code", "STATUS_CODE_UNSET")
    if status_code in {0, "STATUS_CODE_UNSET", "STATUS_CODE_OK", 1}:
        status = OTelSpanStatus.UNSET
    elif status_code in {2, "STATUS_CODE_ERROR"}:
        status = OTelSpanStatus.ERROR
    else:
        raise OTLPIngestionError(f"{path}.status.code is unsupported")

    events: list[OTelSpanEvent] = []
    for index, raw_event in enumerate(_optional_list(span, "events")):
        event_path = f"{path}.events[{index}]"
        event = _mapping(raw_event, event_path)
        if _integer(event.get("droppedAttributesCount", 0), f"{event_path}.droppedAttributesCount"):
            raise OTLPIngestionError(f"{event_path} dropped attributes required for provenance")
        events.append(
            OTelSpanEvent(
                name=_text(event.get("name"), f"{event_path}.name"),
                occurred_at=_nanos_to_timestamp(
                    _integer(event.get("timeUnixNano"), f"{event_path}.timeUnixNano")
                ),
                attributes=_parse_attributes(
                    _optional_list(event, "attributes"), f"{event_path}.attributes"
                ),
            )
        )

    parent_value = span.get("parentSpanId")
    parent_span_id = (
        None
        if parent_value is None or parent_value == ""
        else _decode_identifier(parent_value, byte_length=8, path=f"{path}.parentSpanId")
    )
    return OTelSpanRecord(
        schema_url=schema_url,
        trace_id=_decode_identifier(span.get("traceId"), byte_length=16, path=f"{path}.traceId"),
        span_id=_decode_identifier(span.get("spanId"), byte_length=8, path=f"{path}.spanId"),
        parent_span_id=parent_span_id,
        name=_text(span.get("name"), f"{path}.name"),
        kind=OTelSpanKind.INTERNAL,
        start_time=_nanos_to_timestamp(
            _integer(span.get("startTimeUnixNano"), f"{path}.startTimeUnixNano")
        ),
        end_time=_nanos_to_timestamp(
            _integer(span.get("endTimeUnixNano"), f"{path}.endTimeUnixNano")
        ),
        status=status,
        attributes=_parse_attributes(_optional_list(span, "attributes"), f"{path}.attributes"),
        events=tuple(events),
    )


def _run_context(span: OTelSpanRecord) -> RunContext:
    return RunContext(
        run_id=_attribute_text(span.attributes, "glassbox.run.id"),
        trace_id=span.trace_id,
        span_id=span.span_id,
        parent_run_id=_optional_attribute_text(span.attributes, "glassbox.parent_run.id"),
        parent_span_id=span.parent_span_id,
        agent_id=_attribute_text(span.attributes, "gen_ai.agent.id"),
        agent_version=_optional_attribute_text(span.attributes, "gen_ai.agent.version"),
        workflow_id=_attribute_text(span.attributes, "gen_ai.workflow.name"),
        workflow_version=_optional_attribute_text(span.attributes, "glassbox.workflow.version"),
    )


def _evidence_event_id(
    span: OTelSpanRecord,
    event: OTelSpanEvent,
    index: int,
    occupied: set[str],
) -> str:
    nonce = 0
    while True:
        material = (
            f"{span.trace_id}\0{span.span_id}\0{index}\0{event.occurred_at}\0{nonce}".encode()
        )
        candidate = hashlib.sha256(_EVIDENCE_ID_DOMAIN + material).hexdigest()[:16]
        if candidate not in occupied:
            return candidate
        nonce += 1


def _parse_attributes(values: list[Any], path: str) -> dict[str, JSONScalar]:
    attributes: dict[str, JSONScalar] = {}
    for index, raw_attribute in enumerate(values):
        attribute_path = f"{path}[{index}]"
        attribute = _mapping(raw_attribute, attribute_path)
        key = _text(attribute.get("key"), f"{attribute_path}.key")
        if key in attributes:
            raise OTLPIngestionError(f"{attribute_path} duplicates attribute key {key!r}")
        value = _mapping(attribute.get("value"), f"{attribute_path}.value")
        attributes[key] = _parse_any_value(value, f"{attribute_path}.value")
    return attributes


def _parse_any_value(value: Mapping[str, Any], path: str) -> JSONScalar:
    populated = [
        key for key in ("stringValue", "boolValue", "intValue", "doubleValue") if key in value
    ]
    if len(populated) != 1:
        raise OTLPIngestionError(f"{path} must contain exactly one scalar OTLP AnyValue")
    key = populated[0]
    raw = value[key]
    if key == "stringValue":
        return _text(raw, f"{path}.stringValue", allow_empty=True)
    if key == "boolValue":
        if not isinstance(raw, bool):
            raise OTLPIngestionError(f"{path}.boolValue must be a boolean")
        return raw
    if key == "intValue":
        return _integer(raw, f"{path}.intValue")
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        raise OTLPIngestionError(f"{path}.doubleValue must be a number")
    return float(raw)


def _decode_identifier(value: object, *, byte_length: int, path: str) -> str:
    text_value = _text(value, path)
    if len(text_value) == byte_length * 2 and _HEX_PATTERN.fullmatch(text_value):
        return text_value
    try:
        decoded = base64.b64decode(text_value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise OTLPIngestionError(f"{path} must be hex or protobuf-JSON base64") from exc
    if len(decoded) != byte_length:
        raise OTLPIngestionError(f"{path} must decode to exactly {byte_length} bytes")
    return decoded.hex()


def _nanos_to_timestamp(nanoseconds: int) -> str:
    if nanoseconds < 0:
        raise OTLPIngestionError("OTLP timestamps must not be negative")
    seconds, remainder = divmod(nanoseconds, 1_000_000_000)
    try:
        prefix = datetime.fromtimestamp(seconds, tz=UTC).strftime("%Y-%m-%dT%H:%M:%S")
    except (OSError, OverflowError, ValueError) as exc:
        raise OTLPIngestionError("OTLP timestamp is outside the supported UTC range") from exc
    return f"{prefix}.{remainder:09d}Z"


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise OTLPIngestionError(f"invalid OpenTelemetry timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise OTLPIngestionError("OpenTelemetry timestamps must include a timezone")
    return parsed.astimezone(UTC)


def _attribute(attributes: Mapping[str, JSONScalar], key: str) -> JSONScalar:
    if key not in attributes:
        raise OTLPIngestionError(f"required OpenTelemetry attribute {key!r} is missing")
    return attributes[key]


def _attribute_text(attributes: Mapping[str, JSONScalar], key: str) -> str:
    return _text(_attribute(attributes, key), f"attribute {key!r}")


def _optional_attribute_text(attributes: Mapping[str, JSONScalar], key: str) -> str | None:
    value = attributes.get(key)
    return None if value is None else _text(value, f"attribute {key!r}")


def _mapping(value: object, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OTLPIngestionError(f"{path} must be an object")
    return value


def _required_list(value: Mapping[str, Any], key: str) -> list[Any]:
    child = value.get(key)
    if not isinstance(child, list):
        raise OTLPIngestionError(f"{key} must be an array")
    return child


def _optional_list(value: Mapping[str, Any], key: str) -> list[Any]:
    child = value.get(key, [])
    if not isinstance(child, list):
        raise OTLPIngestionError(f"{key} must be an array")
    return child


def _text(value: object, path: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise OTLPIngestionError(f"{path} must be {qualifier}")
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return _text(value, "schemaUrl")


def _integer(value: object, path: str) -> int:
    if isinstance(value, bool):
        raise OTLPIngestionError(f"{path} must be an integer")
    if not isinstance(value, str | int | float):
        raise OTLPIngestionError(f"{path} must be an integer")
    try:
        parsed = int(value)  # protobuf JSON encodes 64-bit integers as decimal strings
    except (TypeError, ValueError) as exc:
        raise OTLPIngestionError(f"{path} must be an integer") from exc
    if isinstance(value, float) and not value.is_integer():
        raise OTLPIngestionError(f"{path} must be an integer")
    return parsed
