"""Framework-neutral runtime instrumentation with risk-aware failure semantics."""

from __future__ import annotations

import inspect
import re
import secrets
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import wraps
from threading import Lock
from typing import Any, ParamSpec, Protocol, TypeVar, cast

from glassbox.errors import (
    EvidenceValidationError,
    NoActiveRunError,
    PolicyViolationError,
    TelemetryExportError,
)
from glassbox.models import (
    ActionEffect,
    ActionObservation,
    ActionStatus,
    ActionToken,
    EventKind,
    EvidenceObservation,
    EvidenceRole,
    EvidenceState,
    JSONValue,
    RunContext,
    RunStatus,
    RuntimeEvent,
)
from glassbox.redaction import RedactionPolicy, digest_value

P = ParamSpec("P")
R = TypeVar("R")
_UNSET = object()
_TRACE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID_PATTERN = re.compile(r"^[0-9a-f]{16}$")


class EventSink(Protocol):
    """Destination for normalized runtime events."""

    def emit(self, event: RuntimeEvent) -> None:
        """Persist or export one immutable event."""


class IdGenerator(Protocol):
    """Injectable correlation-ID source for deterministic tests."""

    def trace_id(self) -> str:
        """Return 16 random bytes encoded as lowercase hex."""

    def span_id(self) -> str:
        """Return 8 random bytes encoded as lowercase hex."""

    def run_id(self) -> str:
        """Return a non-secret externally stable run identifier."""


class RandomIdGenerator:
    """Cryptographically strong default correlation-ID generator."""

    def trace_id(self) -> str:
        return secrets.token_hex(16)

    def span_id(self) -> str:
        return secrets.token_hex(8)

    def run_id(self) -> str:
        return f"run-{secrets.token_hex(12)}"


class InMemorySink:
    """Thread-safe sink for tests, demos, and embedded collection."""

    def __init__(self) -> None:
        self._events: list[RuntimeEvent] = []
        self._lock = Lock()

    def emit(self, event: RuntimeEvent) -> None:
        with self._lock:
            self._events.append(event)

    @property
    def events(self) -> tuple[RuntimeEvent, ...]:
        with self._lock:
            return tuple(self._events)


@dataclass(frozen=True)
class ExportFailure:
    """Sanitized diagnostic for a fail-open sink error."""

    event_kind: EventKind
    error_type: str


@dataclass
class RunHandle:
    """Mutable result state scoped to an otherwise immutable run context."""

    context: RunContext
    output_digest: str | None = None
    terminal_status: RunStatus = RunStatus.SUCCEEDED

    def record_output(self, value: Any, *, policy: RedactionPolicy | None = None) -> None:
        """Commit an output digest without retaining the output itself."""

        self.output_digest = digest_value(value, policy=policy)

    def abstain(self) -> None:
        """Mark a successful execution as an explicit abstention."""

        self.terminal_status = RunStatus.ABSTAINED

    def cancel(self) -> None:
        """Mark a successful execution as cancelled."""

        self.terminal_status = RunStatus.CANCELLED


class GlassBox:
    """Capture normalized runtime provenance without retaining raw payloads."""

    def __init__(
        self,
        sink: EventSink | None = None,
        *,
        redaction_policy: RedactionPolicy | None = None,
        id_generator: IdGenerator | None = None,
        clock: Callable[[], datetime] | None = None,
        fail_closed_effects: frozenset[ActionEffect] | None = None,
    ) -> None:
        self.sink = sink or InMemorySink()
        self.redaction_policy = redaction_policy or RedactionPolicy()
        self._ids = id_generator or RandomIdGenerator()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._fail_closed_effects = fail_closed_effects or frozenset(
            {ActionEffect.IRREVERSIBLE, ActionEffect.UNKNOWN_EFFECT}
        )
        self._contexts: ContextVar[tuple[RunContext, ...]] = ContextVar(
            f"glassbox_contexts_{id(self)}", default=()
        )
        self._sequence = 0
        self._sequence_lock = Lock()
        self._diagnostics: list[ExportFailure] = []
        self._diagnostics_lock = Lock()

    @property
    def current_run(self) -> RunContext | None:
        """Return the current task-local run without leaking across coroutines."""

        contexts = self._contexts.get()
        return contexts[-1] if contexts else None

    @property
    def export_failures(self) -> tuple[ExportFailure, ...]:
        """Return sanitized failures that were allowed to fail open."""

        with self._diagnostics_lock:
            return tuple(self._diagnostics)

    @contextmanager
    def run(
        self,
        *,
        agent_id: str,
        workflow_id: str,
        agent_version: str | None = None,
        workflow_version: str | None = None,
        run_id: str | None = None,
    ) -> Iterator[RunHandle]:
        """Open a correlated run; nested runs inherit the trace identifier."""

        if not agent_id or not workflow_id:
            raise ValueError("agent_id and workflow_id must not be empty")
        if run_id is not None and not run_id:
            raise ValueError("run_id must not be empty when provided")

        parent = self.current_run
        context = RunContext(
            run_id=run_id or self._ids.run_id(),
            trace_id=parent.trace_id if parent else self._ids.trace_id(),
            span_id=self._ids.span_id(),
            parent_run_id=parent.run_id if parent else None,
            parent_span_id=parent.span_id if parent else None,
            agent_id=agent_id,
            agent_version=agent_version,
            workflow_id=workflow_id,
            workflow_version=workflow_version,
        )
        handle = RunHandle(context=context)
        token = self._contexts.set((*self._contexts.get(), context))
        try:
            self._emit(
                self._event(
                    EventKind.RUN_STARTED,
                    context,
                    context.span_id,
                    context.parent_span_id,
                    {"run.status": "STARTED"},
                )
            )
            try:
                yield handle
            except BaseException as exc:
                handle.terminal_status = RunStatus.FAILED
                self._emit(
                    self._event(
                        EventKind.RUN_FINISHED,
                        context,
                        context.span_id,
                        context.parent_span_id,
                        {
                            "run.status": handle.terminal_status.value,
                            "output.digest": handle.output_digest,
                            "error.type": type(exc).__name__,
                        },
                    )
                )
                raise
            else:
                self._emit(
                    self._event(
                        EventKind.RUN_FINISHED,
                        context,
                        context.span_id,
                        context.parent_span_id,
                        {
                            "run.status": handle.terminal_status.value,
                            "output.digest": handle.output_digest,
                            "error.type": None,
                        },
                    )
                )
        finally:
            self._contexts.reset(token)

    def consequential(
        self,
        *,
        agent_id: str,
        workflow_id: str,
        agent_version: str | None = None,
        workflow_version: str | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorate a sync or async function as a consequential agent run."""

        def decorate(function: Callable[P, R]) -> Callable[P, R]:
            if inspect.iscoroutinefunction(function):

                @wraps(function)
                async def async_wrapper(*args: P.args, **kwargs: P.kwargs) -> Any:
                    with self.run(
                        agent_id=agent_id,
                        workflow_id=workflow_id,
                        agent_version=agent_version,
                        workflow_version=workflow_version,
                    ) as handle:
                        result = await function(*args, **kwargs)
                        handle.record_output(result, policy=self.redaction_policy)
                        return result

                return cast(Callable[P, R], async_wrapper)

            @wraps(function)
            def sync_wrapper(*args: P.args, **kwargs: P.kwargs) -> R:
                with self.run(
                    agent_id=agent_id,
                    workflow_id=workflow_id,
                    agent_version=agent_version,
                    workflow_version=workflow_version,
                ) as handle:
                    result = function(*args, **kwargs)
                    handle.record_output(result, policy=self.redaction_policy)
                    return result

            return sync_wrapper

        return decorate

    def observe_evidence(
        self,
        *,
        entity_type: str,
        state: EvidenceState,
        role: EvidenceRole,
        representation: Any = _UNSET,
        datahub_urn: str | None = None,
        schema_field_urn: str | None = None,
        capture_method: str = "SDK_EVENT",
        rule_id: str | None = None,
        confidence: float | None = None,
        metadata: Any = None,
    ) -> EvidenceObservation:
        """Record evidence while making observed and inferred proof requirements explicit."""

        context = self._require_run()
        if not entity_type:
            raise EvidenceValidationError("entity_type must not be empty")
        if state is EvidenceState.OBSERVED and representation is _UNSET:
            raise EvidenceValidationError("OBSERVED evidence requires a captured representation")
        if state is EvidenceState.INFERRED and (rule_id is None or confidence is None):
            raise EvidenceValidationError("INFERRED evidence requires rule_id and confidence")
        if confidence is not None and not 0 <= confidence <= 1:
            raise EvidenceValidationError("confidence must be between 0 and 1")

        observation = EvidenceObservation(
            entity_type=entity_type,
            datahub_urn=datahub_urn,
            schema_field_urn=schema_field_urn,
            state=state,
            role=role,
            representation_digest=(
                None
                if representation is _UNSET
                else digest_value(representation, policy=self.redaction_policy)
            ),
            capture_method=capture_method,
            rule_id=rule_id,
            confidence=confidence,
            metadata=self._safe_metadata(metadata),
        )
        span_id = self._ids.span_id()
        self._emit(
            self._event(
                EventKind.EVIDENCE_OBSERVED,
                context,
                span_id,
                context.span_id,
                observation.attributes(),
            )
        )
        return observation

    def call_tool(
        self,
        tool_id: str,
        function: Callable[..., R],
        *args: Any,
        effect: ActionEffect = ActionEffect.UNKNOWN_EFFECT,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        metadata: Any = None,
        **kwargs: Any,
    ) -> R:
        """Invoke a synchronous tool and record exactly one terminal observation."""

        input_value = {"args": args, "kwargs": kwargs}
        token = self.begin_action(
            tool_id=tool_id,
            input_value=input_value,
            effect=effect,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            metadata=metadata,
        )
        try:
            output = function(*args, **kwargs)
        except BaseException as exc:
            self.finish_action(
                token,
                status=ActionStatus.FAILED,
                output_value=_UNSET,
                error_type=type(exc).__name__,
            )
            raise
        self.finish_action(
            token,
            status=ActionStatus.SUCCEEDED,
            output_value=output,
        )
        return output

    async def call_tool_async(
        self,
        tool_id: str,
        function: Callable[..., Awaitable[R]],
        *args: Any,
        effect: ActionEffect = ActionEffect.UNKNOWN_EFFECT,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        metadata: Any = None,
        **kwargs: Any,
    ) -> R:
        """Invoke an asynchronous tool and record exactly one terminal observation."""

        input_value = {"args": args, "kwargs": kwargs}
        token = self.begin_action(
            tool_id=tool_id,
            input_value=input_value,
            effect=effect,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            metadata=metadata,
        )
        try:
            output = await function(*args, **kwargs)
        except BaseException as exc:
            self.finish_action(
                token,
                status=ActionStatus.FAILED,
                output_value=_UNSET,
                error_type=type(exc).__name__,
            )
            raise
        self.finish_action(
            token,
            status=ActionStatus.SUCCEEDED,
            output_value=output,
        )
        return output

    def begin_action(
        self,
        *,
        tool_id: str,
        input_value: Any,
        effect: ActionEffect = ActionEffect.UNKNOWN_EFFECT,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        metadata: Any = None,
    ) -> ActionToken:
        """Preflight an action and emit its attempt before executing side effects."""

        context = self._require_run()
        if not tool_id:
            raise ValueError("tool_id must not be empty")
        span_id = self._ids.span_id()
        self._enforce_action_policy(
            context=context,
            span_id=span_id,
            tool_id=tool_id,
            input_value=input_value,
            effect=effect,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            metadata=metadata,
        )
        token = ActionToken(
            run=context,
            span_id=span_id,
            tool_id=tool_id,
            effect=effect,
            input_digest=digest_value(input_value, policy=self.redaction_policy),
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            metadata=self._safe_metadata(metadata),
        )
        observation = ActionObservation(
            tool_id=token.tool_id,
            effect=token.effect,
            status=ActionStatus.ATTEMPTED,
            input_digest=token.input_digest,
            output_digest=None,
            idempotency_key=token.idempotency_key,
            approval_id=token.approval_id,
            metadata=token.metadata,
        )
        self._emit(
            self._event(
                EventKind.ACTION_ATTEMPTED,
                token.run,
                token.span_id,
                token.run.span_id,
                observation.attributes(),
            ),
            effect=token.effect,
        )
        return token

    def finish_action(
        self,
        token: ActionToken,
        *,
        status: ActionStatus,
        output_value: Any = _UNSET,
        error_type: str | None = None,
    ) -> ActionObservation:
        """Complete a preflighted action without retaining its original input."""

        self._validate_action_completion(status, output_value, error_type)
        observation = ActionObservation(
            tool_id=token.tool_id,
            effect=token.effect,
            status=status,
            input_digest=token.input_digest,
            output_digest=(
                None
                if output_value is _UNSET
                else digest_value(output_value, policy=self.redaction_policy)
            ),
            idempotency_key=token.idempotency_key,
            approval_id=token.approval_id,
            error_type=error_type,
            metadata=token.metadata,
        )
        self._emit(
            self._event(
                EventKind.ACTION_FINISHED,
                token.run,
                token.span_id,
                token.run.span_id,
                observation.attributes(),
            ),
            effect=token.effect,
        )
        return observation

    def record_action(
        self,
        *,
        tool_id: str,
        input_value: Any,
        effect: ActionEffect,
        status: ActionStatus,
        output_value: Any = _UNSET,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        error_type: str | None = None,
        metadata: Any = None,
        span_id: str | None = None,
    ) -> ActionObservation:
        """Normalize an already-observed action from a framework callback."""

        context = self._require_run()
        if not tool_id:
            raise ValueError("tool_id must not be empty")
        self._validate_action_completion(status, output_value, error_type, allow_blocked=True)
        observation = ActionObservation(
            tool_id=tool_id,
            effect=effect,
            status=status,
            input_digest=digest_value(input_value, policy=self.redaction_policy),
            output_digest=(
                None
                if output_value is _UNSET
                else digest_value(output_value, policy=self.redaction_policy)
            ),
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            error_type=error_type,
            metadata=self._safe_metadata(metadata),
        )
        self._emit(
            self._event(
                EventKind.ACTION_FINISHED,
                context,
                span_id or self._ids.span_id(),
                context.span_id,
                observation.attributes(),
            ),
            effect=effect,
        )
        return observation

    @staticmethod
    def _validate_action_completion(
        status: ActionStatus,
        output_value: Any,
        error_type: str | None,
        *,
        allow_blocked: bool = False,
    ) -> None:
        allowed = {ActionStatus.SUCCEEDED, ActionStatus.FAILED}
        if allow_blocked:
            allowed.add(ActionStatus.BLOCKED)
        if status not in allowed:
            names = ", ".join(sorted(item.value for item in allowed))
            raise ValueError(f"terminal action status must be one of: {names}")
        if status is ActionStatus.SUCCEEDED and output_value is _UNSET:
            raise ValueError("SUCCEEDED actions require an output value; pass None explicitly")
        if status is ActionStatus.SUCCEEDED and error_type is not None:
            raise ValueError("SUCCEEDED actions cannot include error_type")
        if status is ActionStatus.FAILED and not error_type:
            raise ValueError("FAILED actions require error_type")
        if status is ActionStatus.BLOCKED and output_value is not _UNSET:
            raise ValueError("BLOCKED actions cannot include an output value")

    def _enforce_action_policy(
        self,
        *,
        context: RunContext,
        span_id: str,
        tool_id: str,
        input_value: Any,
        effect: ActionEffect,
        idempotency_key: str | None,
        approval_id: str | None,
        metadata: Any,
    ) -> None:
        reason: str | None = None
        if effect in {ActionEffect.REVERSIBLE, ActionEffect.IRREVERSIBLE} and not idempotency_key:
            reason = "mutating actions require an idempotency_key"
        if effect is ActionEffect.IRREVERSIBLE and not approval_id:
            reason = "irreversible actions require an approval_id"
        if reason is None:
            return

        observation = ActionObservation(
            tool_id=tool_id,
            effect=effect,
            status=ActionStatus.BLOCKED,
            input_digest=digest_value(input_value, policy=self.redaction_policy),
            output_digest=None,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            error_type=PolicyViolationError.__name__,
            metadata=self._safe_metadata(metadata),
        )
        self._emit(
            self._event(
                EventKind.ACTION_FINISHED,
                context,
                span_id,
                context.span_id,
                observation.attributes(),
            ),
            effect=effect,
        )
        raise PolicyViolationError(reason)

    def _require_run(self) -> RunContext:
        context = self.current_run
        if context is None:
            raise NoActiveRunError("runtime evidence and actions require an active GlassBox run")
        return context

    def _safe_metadata(self, metadata: Any) -> dict[str, JSONValue]:
        safe = self.redaction_policy.sanitize({} if metadata is None else metadata)
        if not isinstance(safe, dict):
            return {"value": safe}
        return safe

    def _event(
        self,
        kind: EventKind,
        context: RunContext,
        span_id: str,
        parent_span_id: str | None,
        attributes: dict[str, JSONValue],
    ) -> RuntimeEvent:
        if not _TRACE_ID_PATTERN.fullmatch(context.trace_id):
            raise ValueError("trace_id must contain exactly 32 lowercase hexadecimal characters")
        if not _SPAN_ID_PATTERN.fullmatch(span_id):
            raise ValueError("span_id must contain exactly 16 lowercase hexadecimal characters")
        if parent_span_id is not None and not _SPAN_ID_PATTERN.fullmatch(parent_span_id):
            raise ValueError(
                "parent_span_id must contain exactly 16 lowercase hexadecimal characters"
            )
        with self._sequence_lock:
            self._sequence += 1
            sequence = self._sequence
        timestamp = self._clock()
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("clock must return a timezone-aware datetime")
        occurred_at = timestamp.astimezone(UTC).isoformat().replace("+00:00", "Z")
        return RuntimeEvent(
            sequence=sequence,
            occurred_at=occurred_at,
            kind=kind,
            run=context,
            span_id=span_id,
            parent_span_id=parent_span_id,
            attributes=attributes,
        )

    def _emit(self, event: RuntimeEvent, *, effect: ActionEffect | None = None) -> None:
        try:
            self.sink.emit(event)
        except Exception as exc:
            failure = ExportFailure(event_kind=event.kind, error_type=type(exc).__name__)
            with self._diagnostics_lock:
                self._diagnostics.append(failure)
            if effect in self._fail_closed_effects:
                raise TelemetryExportError(
                    f"telemetry export failed closed for {effect.value} action"
                ) from exc
