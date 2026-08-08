"""Append-only operational persistence for normalized runtime events."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from threading import Lock
from typing import Any

from glassbox.models import (
    RUNTIME_EVENT_SPEC_VERSION,
    EventKind,
    JSONValue,
    RunContext,
    RuntimeEvent,
)
from glassbox_compiler.errors import CompilationError
from glassbox_dbom.canonical import canonicalize

_EVENT_DOMAIN = b"glassbox.runtime-event-log.v1\0"


class EventLogError(CompilationError):
    """Raised when an operational event log is corrupt or cannot be decoded."""


class AppendOnlyEventLog:
    """Single-process sink with checksummed JSONL records and optional fsync."""

    def __init__(self, path: Path, *, sync: bool = True) -> None:
        if not path.parent.is_dir():
            raise EventLogError(f"event-log parent directory does not exist: {path.parent}")
        if path.exists() and not path.is_file():
            raise EventLogError(f"event-log path is not a regular file: {path}")
        self.path = path
        self.sync = sync
        self._lock = Lock()

    def emit(self, event: RuntimeEvent) -> None:
        """Append one complete, content-checked record without rewriting prior bytes."""

        event_value = event.to_dict()
        run_context = {
            "span_id": event.run.span_id,
            "parent_span_id": event.run.parent_span_id,
        }
        material = {"event": event_value, "run_context": run_context}
        envelope = {
            **material,
            "sha256": hashlib.sha256(_EVENT_DOMAIN + canonicalize(material)).hexdigest(),
        }
        record = canonicalize(envelope) + b"\n"
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        with self._lock:
            descriptor = os.open(self.path, flags, 0o600)
            try:
                _write_all(descriptor, record)
                if self.sync:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)

    def read_events(self) -> tuple[RuntimeEvent, ...]:
        """Read and verify every complete record; truncated tails fail visibly."""

        if not self.path.exists():
            return ()
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            raise EventLogError("event log has a truncated trailing record")
        events: list[RuntimeEvent] = []
        for line_number, line in enumerate(data.splitlines(), start=1):
            try:
                raw = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise EventLogError(f"event log line {line_number} is not valid JSON") from exc
            if not isinstance(raw, dict):
                raise EventLogError(f"event log line {line_number} must be an object")
            event_value = raw.get("event")
            run_context = raw.get("run_context")
            digest = raw.get("sha256")
            if (
                not isinstance(event_value, dict)
                or not isinstance(run_context, dict)
                or not isinstance(digest, str)
            ):
                raise EventLogError(f"event log line {line_number} has an invalid envelope")
            material = {"event": event_value, "run_context": run_context}
            expected = hashlib.sha256(_EVENT_DOMAIN + canonicalize(material)).hexdigest()
            if digest != expected:
                raise EventLogError(f"event log line {line_number} failed its checksum")
            events.append(
                _decode_event(event_value, run_context=run_context, line_number=line_number)
            )
        return tuple(events)


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - defensive OS contract check
            raise EventLogError("event log append made no forward progress")
        remaining = remaining[written:]


def _decode_event(
    value: dict[str, Any], *, run_context: dict[str, Any], line_number: int
) -> RuntimeEvent:
    if value.get("spec_version") != RUNTIME_EVENT_SPEC_VERSION:
        raise EventLogError(f"event log line {line_number} has an unsupported spec_version")
    sequence = value.get("sequence")
    if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence < 1:
        raise EventLogError(f"event log line {line_number} has an invalid sequence")
    try:
        kind = EventKind(_required_text(value, "kind", line_number))
    except ValueError as exc:
        raise EventLogError(f"event log line {line_number} has an unsupported event kind") from exc
    attributes = value.get("attributes")
    if not isinstance(attributes, dict):
        raise EventLogError(f"event log line {line_number} attributes must be an object")
    event_span_id = _required_text(value, "span_id", line_number)
    parent_span_id = _optional_text(value, "parent_span_id", line_number)
    run_span_id = _required_text(run_context, "span_id", line_number)
    run_parent_span_id = _optional_text(run_context, "parent_span_id", line_number)
    context = RunContext(
        run_id=_required_text(value, "run_id", line_number),
        trace_id=_required_text(value, "trace_id", line_number),
        span_id=run_span_id,
        parent_run_id=_optional_text(value, "parent_run_id", line_number),
        parent_span_id=run_parent_span_id,
        agent_id=_required_text(value, "agent.id", line_number),
        agent_version=_optional_text(value, "agent.version", line_number),
        workflow_id=_required_text(value, "workflow.id", line_number),
        workflow_version=_optional_text(value, "workflow.version", line_number),
    )
    return RuntimeEvent(
        sequence=sequence,
        occurred_at=_required_text(value, "occurred_at", line_number),
        kind=kind,
        run=context,
        span_id=event_span_id,
        parent_span_id=parent_span_id,
        attributes=_json_object(attributes, line_number=line_number),
    )


def _json_object(value: dict[str, Any], *, line_number: int) -> dict[str, JSONValue]:
    if not _is_json_value(value):
        raise EventLogError(f"event log line {line_number} attributes are not JSON-safe")
    return value


def _is_json_value(value: object) -> bool:
    if value is None or isinstance(value, str | bool | int | float):
        return True
    if isinstance(value, list):
        return all(_is_json_value(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_value(item) for key, item in value.items())
    return False


def _required_text(value: dict[str, Any], key: str, line_number: int) -> str:
    child = value.get(key)
    if not isinstance(child, str) or not child:
        raise EventLogError(f"event log line {line_number} field {key!r} must be non-empty")
    return child


def _optional_text(value: dict[str, Any], key: str, line_number: int) -> str | None:
    child = value.get(key)
    if child is not None and (not isinstance(child, str) or not child):
        raise EventLogError(f"event log line {line_number} field {key!r} must be non-empty or null")
    return child
