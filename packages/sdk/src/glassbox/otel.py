"""OpenTelemetry GenAI semantic mapping for normalized GlassBox runtime events."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from threading import Lock

from glassbox.models import RUNTIME_EVENT_SPEC_VERSION, EventKind, JSONScalar, RuntimeEvent

GENAI_SEMCONV_SCHEMA_URL = "https://opentelemetry.io/schemas/gen-ai/1.42.0"


class OTelSpanKind(StrEnum):
    """Span kinds used by the local agent and tool conventions."""

    INTERNAL = "INTERNAL"


class OTelSpanStatus(StrEnum):
    """Portable subset of OpenTelemetry span status codes."""

    UNSET = "UNSET"
    ERROR = "ERROR"


@dataclass(frozen=True)
class OTelSpanEvent:
    """One point-in-time event attached to an OpenTelemetry span."""

    name: str
    occurred_at: str
    attributes: dict[str, JSONScalar]


@dataclass(frozen=True)
class OTelSpanRecord:
    """Exporter-neutral completed span following the pinned GenAI conventions."""

    schema_url: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    kind: OTelSpanKind
    start_time: str
    end_time: str
    status: OTelSpanStatus
    attributes: dict[str, JSONScalar]
    events: tuple[OTelSpanEvent, ...] = ()


@dataclass
class _PendingSpan:
    trace_id: str
    span_id: str
    parent_span_id: str | None
    name: str
    start_time: str
    attributes: dict[str, JSONScalar]
    events: list[OTelSpanEvent] = field(default_factory=list)


class OpenTelemetryMappingError(ValueError):
    """Raised when an invalid runtime lifecycle cannot become a truthful span."""


class OpenTelemetrySpanSink:
    """Reduce normalized runtime events to completed OpenTelemetry span records.

    This adapter deliberately stops at the exporter boundary. A collector/exporter
    can serialize the completed records to OTLP without making the GlassBox runtime
    depend on one OpenTelemetry SDK release.
    """

    def __init__(self, emit_span: Callable[[OTelSpanRecord], None]) -> None:
        self._emit_span = emit_span
        self._pending: dict[tuple[str, str], _PendingSpan] = {}
        self._lock = Lock()

    @property
    def pending_count(self) -> int:
        """Return the number of run or action spans without a terminal event."""

        with self._lock:
            return len(self._pending)

    def emit(self, event: RuntimeEvent) -> None:
        """Consume one GlassBox runtime event and emit a span when it completes."""

        completed: OTelSpanRecord | None = None
        with self._lock:
            if event.kind is EventKind.RUN_STARTED:
                self._start(event, self._run_span(event))
            elif event.kind is EventKind.ACTION_ATTEMPTED:
                self._start(event, self._action_span(event))
            elif event.kind is EventKind.EVIDENCE_OBSERVED:
                self._attach_evidence(event)
            elif event.kind is EventKind.RUN_FINISHED:
                completed = self._finish_run(event)
            elif event.kind is EventKind.ACTION_FINISHED:
                completed = self._finish_action(event)
            else:  # pragma: no cover - exhaustive over the current closed enum
                raise OpenTelemetryMappingError(f"unsupported runtime event kind: {event.kind}")
        if completed is not None:
            self._emit_span(completed)

    def _start(self, event: RuntimeEvent, pending: _PendingSpan) -> None:
        key = (event.run.trace_id, event.span_id)
        if key in self._pending:
            raise OpenTelemetryMappingError(
                f"duplicate start for trace {event.run.trace_id} span {event.span_id}"
            )
        self._pending[key] = pending

    def _attach_evidence(self, event: RuntimeEvent) -> None:
        if event.parent_span_id is None:
            raise OpenTelemetryMappingError("evidence event requires a parent run span")
        key = (event.run.trace_id, event.parent_span_id)
        pending = self._pending.get(key)
        if pending is None:
            raise OpenTelemetryMappingError(
                "evidence event referenced a run span that is not active"
            )
        pending.events.append(
            OTelSpanEvent(
                name=event.kind.value,
                occurred_at=event.occurred_at,
                attributes=_evidence_attributes(event),
            )
        )

    def _finish_run(self, event: RuntimeEvent) -> OTelSpanRecord:
        pending = self._take(event)
        pending.attributes.update(_run_terminal_attributes(event))
        return _complete(
            pending,
            event.occurred_at,
            error=event.attributes.get("run.status") == "FAILED",
        )

    def _finish_action(self, event: RuntimeEvent) -> OTelSpanRecord:
        key = (event.run.trace_id, event.span_id)
        pending = self._pending.pop(key, None)
        if pending is None:
            pending = self._action_span(event)
        pending.attributes.update(_action_attributes(event))
        return _complete(
            pending,
            event.occurred_at,
            error=event.attributes.get("action.status") in {"FAILED", "BLOCKED"},
        )

    def _take(self, event: RuntimeEvent) -> _PendingSpan:
        key = (event.run.trace_id, event.span_id)
        try:
            return self._pending.pop(key)
        except KeyError as exc:
            raise OpenTelemetryMappingError(
                f"terminal event has no start for trace {event.run.trace_id} span {event.span_id}"
            ) from exc

    @staticmethod
    def _run_span(event: RuntimeEvent) -> _PendingSpan:
        attributes: dict[str, JSONScalar] = {
            "gen_ai.operation.name": "invoke_agent",
            "gen_ai.agent.name": event.run.agent_id,
            "gen_ai.agent.id": event.run.agent_id,
            "gen_ai.agent.version": event.run.agent_version,
            "gen_ai.workflow.name": event.run.workflow_id,
            "glassbox.workflow.version": event.run.workflow_version,
            "glassbox.run.id": event.run.run_id,
            "glassbox.parent_run.id": event.run.parent_run_id,
            "glassbox.runtime.spec_version": RUNTIME_EVENT_SPEC_VERSION,
        }
        return _PendingSpan(
            trace_id=event.run.trace_id,
            span_id=event.span_id,
            parent_span_id=event.parent_span_id,
            name=f"invoke_agent {event.run.agent_id}",
            start_time=event.occurred_at,
            attributes=_without_none(attributes),
        )

    @staticmethod
    def _action_span(event: RuntimeEvent) -> _PendingSpan:
        tool_id = event.attributes.get("tool.id")
        if not isinstance(tool_id, str) or not tool_id:
            raise OpenTelemetryMappingError("action event requires a non-empty tool.id")
        attributes: dict[str, JSONScalar] = {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": tool_id,
            "gen_ai.tool.call.id": event.span_id,
            "glassbox.run.id": event.run.run_id,
            "glassbox.runtime.spec_version": RUNTIME_EVENT_SPEC_VERSION,
        }
        attributes.update(_action_attributes(event))
        return _PendingSpan(
            trace_id=event.run.trace_id,
            span_id=event.span_id,
            parent_span_id=event.parent_span_id,
            name=f"execute_tool {tool_id}",
            start_time=event.occurred_at,
            attributes=_without_none(attributes),
        )


def _complete(pending: _PendingSpan, end_time: str, *, error: bool) -> OTelSpanRecord:
    return OTelSpanRecord(
        schema_url=GENAI_SEMCONV_SCHEMA_URL,
        trace_id=pending.trace_id,
        span_id=pending.span_id,
        parent_span_id=pending.parent_span_id,
        name=pending.name,
        kind=OTelSpanKind.INTERNAL,
        start_time=pending.start_time,
        end_time=end_time,
        status=OTelSpanStatus.ERROR if error else OTelSpanStatus.UNSET,
        attributes=pending.attributes,
        events=tuple(pending.events),
    )


def _run_terminal_attributes(event: RuntimeEvent) -> dict[str, JSONScalar]:
    return _without_none(
        {
            "glassbox.run.status": _scalar(event.attributes.get("run.status")),
            "glassbox.output.digest": _scalar(event.attributes.get("output.digest")),
            "error.type": _scalar(event.attributes.get("error.type")),
        }
    )


def _action_attributes(event: RuntimeEvent) -> dict[str, JSONScalar]:
    return _without_none(
        {
            "glassbox.action.effect": _scalar(event.attributes.get("action.effect")),
            "glassbox.action.status": _scalar(event.attributes.get("action.status")),
            "glassbox.action.input_digest": _scalar(event.attributes.get("action.input_digest")),
            "glassbox.action.output_digest": _scalar(event.attributes.get("action.output_digest")),
            "glassbox.action.idempotency_key": _scalar(
                event.attributes.get("action.idempotency_key")
            ),
            "glassbox.approval.receipt_id": _scalar(event.attributes.get("action.approval_id")),
            "error.type": _scalar(event.attributes.get("error.type")),
        }
    )


def _evidence_attributes(event: RuntimeEvent) -> dict[str, JSONScalar]:
    return _without_none(
        {
            "glassbox.evidence.entity_type": _scalar(event.attributes.get("evidence.entity_type")),
            "glassbox.evidence.source_span_id": event.span_id,
            "glassbox.datahub.urn": _scalar(event.attributes.get("datahub.urn")),
            "glassbox.datahub.schema_field_urn": _scalar(
                event.attributes.get("datahub.schema_field_urn")
            ),
            "glassbox.evidence.state": _scalar(event.attributes.get("evidence.state")),
            "glassbox.evidence.role": _scalar(event.attributes.get("evidence.role")),
            "glassbox.evidence.representation_digest": _scalar(
                event.attributes.get("evidence.representation_digest")
            ),
            "glassbox.evidence.capture_method": _scalar(
                event.attributes.get("evidence.capture_method")
            ),
            "glassbox.evidence.rule_id": _scalar(event.attributes.get("evidence.rule_id")),
            "glassbox.evidence.confidence": _scalar(event.attributes.get("evidence.confidence")),
        }
    )


def _scalar(value: object) -> JSONScalar:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    return None


def _without_none(attributes: dict[str, JSONScalar]) -> dict[str, JSONScalar]:
    return {key: value for key, value in attributes.items() if value is not None}
