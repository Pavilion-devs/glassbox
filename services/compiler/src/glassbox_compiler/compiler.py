"""Deterministic compiler from normalized runtime events to sealed DBOM receipts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from glassbox.models import (
    RUNTIME_EVENT_SPEC_VERSION,
    ActionEffect,
    ActionStatus,
    EventKind,
    RunStatus,
    RuntimeEvent,
)
from glassbox_compiler.errors import CompilationError
from glassbox_compiler.urns import (
    URNCandidate,
    URNResolution,
    URNSource,
    VerifiedURNResolver,
)
from glassbox_dbom import SigningKey, seal_receipt

COMPILER_VERSION = "0.1.0"
_DBOM_VERSION = "0.1.0"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_CAPTURE_METHODS = frozenset(
    {
        "OTEL_SPAN",
        "TOOL_RESULT",
        "SDK_EVENT",
        "OWNER_DECLARATION",
        "QUERY_PARSE",
        "LINEAGE_TRAVERSAL",
        "CONFIGURATION",
        "UNAVAILABLE",
    }
)


class Environment(StrEnum):
    """Deployment environment recorded in a DBOM run."""

    DEV = "DEV"
    STAGING = "STAGING"
    PROD = "PROD"


@dataclass(frozen=True)
class ComponentDeclaration:
    """Owner-supplied component identity; omitted facts remain unknown."""

    id: str
    version: str | None = None
    datahub_urn: str | None = None
    source_digest: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.id, "component id")
        _optional_nonempty(self.version, "component version")
        _optional_nonempty(self.datahub_urn, "component DataHub URN")
        _optional_digest(self.source_digest, "component source digest")


@dataclass(frozen=True)
class ToolDeclaration(ComponentDeclaration):
    """Owner-supplied tool identity and optional input/output schema commitment."""

    schema_digest: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        _optional_digest(self.schema_digest, "tool schema digest")


@dataclass(frozen=True)
class CompilationProfile:
    """Versioned facts that cannot be inferred honestly from runtime events alone."""

    environment: Environment
    output_kind: str
    output_mime_type: str
    redaction_policy_id: str = "glassbox.default-deny-v1"
    agent: ComponentDeclaration | None = None
    models: tuple[ComponentDeclaration, ...] = ()
    skills: tuple[ComponentDeclaration, ...] = ()
    tools: tuple[ToolDeclaration, ...] = ()
    signing_keys: tuple[SigningKey, ...] = ()
    urn_resolver: VerifiedURNResolver | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.output_kind, "output kind")
        _require_nonempty(self.output_mime_type, "output MIME type")
        _require_nonempty(self.redaction_policy_id, "redaction policy id")
        _require_unique_ids(self.models, "model")
        _require_unique_ids(self.skills, "skill")
        _require_unique_ids(self.tools, "tool")


def compile_events(
    events: Sequence[RuntimeEvent], *, profile: CompilationProfile
) -> dict[str, Any]:
    """Compile exactly one completed run into a canonical, optionally signed DBOM."""

    ordered = _validate_and_order_events(events)
    started = _only_event(ordered, EventKind.RUN_STARTED)
    finished = _only_event(ordered, EventKind.RUN_FINISHED)
    context = started.run

    if started.span_id != context.span_id or finished.span_id != context.span_id:
        raise CompilationError("run lifecycle events must use the run span_id")
    if started.attributes.get("run.status") != "STARTED":
        raise CompilationError("run start event must have status STARTED")

    status = _required_string(finished.attributes, "run.status")
    try:
        run_status = RunStatus(status)
    except ValueError as exc:
        raise CompilationError(f"unsupported terminal run status: {status!r}") from exc
    output_digest = _required_digest(finished.attributes, "output.digest")

    agent = _compile_agent(context.agent_id, context.agent_version, profile.agent)
    compiled_evidence = [
        _compile_evidence(
            event,
            policy_id=profile.redaction_policy_id,
            urn_resolver=profile.urn_resolver,
        )
        for event in ordered
        if event.kind is EventKind.EVIDENCE_OBSERVED
    ]
    evidence = [item for item, _ in compiled_evidence]
    urn_resolutions = [
        {
            "evidence_id": item["evidence_id"],
            "status": resolution.status.value,
            "source": resolution.source.value if resolution.source is not None else None,
            "attempt_count": len(resolution.attempts),
        }
        for item, resolution in compiled_evidence
        if resolution is not None
    ]
    actions = _compile_actions(ordered)
    tools = _compile_tools(actions, profile.tools)
    replay = _classify_replay(actions)
    unresolved_approvals = sorted(
        {action["approval_id"] for action in actions if isinstance(action["approval_id"], str)}
    )
    partial_action_count = sum(
        action["status"] == ActionStatus.ATTEMPTED.value for action in actions
    )

    payload: dict[str, Any] = {
        "spec_version": _DBOM_VERSION,
        "run": {
            "run_id": context.run_id,
            "status": run_status.value,
            "started_at": started.occurred_at,
            "ended_at": finished.occurred_at,
            "trace_id": context.trace_id,
            "parent_run_id": context.parent_run_id,
            "environment": profile.environment.value,
        },
        "agent": agent,
        "workflow": {"id": context.workflow_id, "version": context.workflow_version},
        "models": [_component(item) for item in sorted(profile.models, key=lambda item: item.id)],
        "skills": [_component(item) for item in sorted(profile.skills, key=lambda item: item.id)],
        "tools": tools,
        "evidence": evidence,
        "queries": [],
        "actions": actions,
        "approvals": [],
        "evaluations": [],
        "output": {
            "kind": profile.output_kind,
            "mime_type": profile.output_mime_type,
            "digest": _digest(output_digest),
            "redacted": True,
            "redaction_reason": "Raw consequential output is excluded from the DBOM receipt.",
        },
        "replay": replay,
        "extensions": {
            "glassbox.compiler.version": COMPILER_VERSION,
            "glassbox.runtime_event.spec_version": RUNTIME_EVENT_SPEC_VERSION,
            "glassbox.compiler.partial_action_count": partial_action_count,
            "glassbox.compiler.unresolved_approval_ids": unresolved_approvals,
            "glassbox.compiler.urn_resolutions": urn_resolutions,
        },
    }
    return seal_receipt(payload, signing_keys=profile.signing_keys)


def _validate_and_order_events(events: Sequence[RuntimeEvent]) -> tuple[RuntimeEvent, ...]:
    if not events:
        raise CompilationError("at least one runtime event is required")
    sequences = [event.sequence for event in events]
    if len(sequences) != len(set(sequences)):
        raise CompilationError("runtime event sequences must be unique")
    ordered = tuple(sorted(events, key=lambda event: event.sequence))
    context = ordered[0].run
    if any(event.run != context for event in ordered[1:]):
        raise CompilationError("compiler input must contain exactly one run context")
    return ordered


def _only_event(events: Sequence[RuntimeEvent], kind: EventKind) -> RuntimeEvent:
    matching = [event for event in events if event.kind is kind]
    if len(matching) != 1:
        raise CompilationError(f"expected exactly one {kind.value} event, found {len(matching)}")
    return matching[0]


def _compile_agent(
    runtime_id: str,
    runtime_version: str | None,
    declaration: ComponentDeclaration | None,
) -> dict[str, Any]:
    if declaration is None:
        return {
            "id": runtime_id,
            "version": runtime_version,
            "datahub_urn": None,
            "source_digest": None,
        }
    if declaration.id != runtime_id:
        raise CompilationError(
            f"declared agent id {declaration.id!r} does not match runtime id {runtime_id!r}"
        )
    if (
        declaration.version is not None
        and runtime_version is not None
        and declaration.version != runtime_version
    ):
        raise CompilationError("declared agent version conflicts with the runtime version")
    return {
        "id": runtime_id,
        "version": declaration.version if declaration.version is not None else runtime_version,
        "datahub_urn": declaration.datahub_urn,
        "source_digest": _optional_digest_object(declaration.source_digest),
    }


def _compile_evidence(
    event: RuntimeEvent,
    *,
    policy_id: str,
    urn_resolver: VerifiedURNResolver | None,
) -> tuple[dict[str, Any], URNResolution | None]:
    attributes = event.attributes
    state = _required_string(attributes, "evidence.state")
    role = _required_string(attributes, "evidence.role")
    entity_type = _required_string(attributes, "evidence.entity_type")
    capture_method = _required_string(attributes, "evidence.capture_method")
    if capture_method not in _CAPTURE_METHODS:
        raise CompilationError(f"unsupported evidence capture method: {capture_method!r}")
    representation = _optional_digest_value(attributes, "evidence.representation_digest")
    confidence = attributes.get("evidence.confidence")
    if confidence is not None and (
        isinstance(confidence, bool) or not isinstance(confidence, (int, float))
    ):
        raise CompilationError("evidence.confidence must be a number or null")

    runtime_urn = _optional_string(attributes, "datahub.urn")
    resolution = None
    if urn_resolver is not None:
        candidates = (
            (URNCandidate(runtime_urn, URNSource.EXPLICIT_INSTRUMENTATION),)
            if runtime_urn is not None
            else ()
        )
        resolution = urn_resolver.resolve(candidates)
        runtime_urn = resolution.urn

    return {
        "evidence_id": f"gbx:evidence:{event.span_id}",
        "entity_type": entity_type,
        "datahub_urn": runtime_urn,
        "schema_field_urn": _optional_string(attributes, "datahub.schema_field_urn"),
        "state": state,
        "role": role,
        "source_span_id": (
            _optional_string(attributes, "evidence.source_span_id") or event.span_id
        ),
        "representation_digest": _optional_digest_object(representation),
        "observed_at": event.occurred_at,
        "redaction": {
            "status": "DIGEST_ONLY" if representation is not None else "NOT_CAPTURED",
            "policy_id": policy_id,
            "reason": (
                "Raw evidence representation is excluded from the DBOM receipt."
                if representation is not None
                else "No evidence representation was captured by the runtime event."
            ),
        },
        "provenance": {
            "capture_method": capture_method,
            "rule_id": _optional_string(attributes, "evidence.rule_id"),
            "confidence": confidence,
        },
    }, resolution


def _compile_actions(events: Sequence[RuntimeEvent]) -> list[dict[str, Any]]:
    grouped: dict[str, list[RuntimeEvent]] = {}
    for event in events:
        if event.kind in {EventKind.ACTION_ATTEMPTED, EventKind.ACTION_FINISHED}:
            grouped.setdefault(event.span_id, []).append(event)

    compiled: list[tuple[int, dict[str, Any]]] = []
    for span_id, action_events in grouped.items():
        attempts = [event for event in action_events if event.kind is EventKind.ACTION_ATTEMPTED]
        terminals = [event for event in action_events if event.kind is EventKind.ACTION_FINISHED]
        if len(attempts) > 1:
            raise CompilationError(f"action span {span_id} has duplicate attempt events")
        if len(terminals) > 1:
            raise CompilationError(f"action span {span_id} has duplicate terminal events")
        if not attempts and not terminals:
            raise CompilationError(f"action span {span_id} has no usable event")
        if attempts and attempts[0].attributes.get("action.status") != ActionStatus.ATTEMPTED.value:
            raise CompilationError(f"action span {span_id} attempt has a non-attempt status")
        if attempts and terminals:
            _require_matching_action_identity(attempts[0], terminals[0])
        source = terminals[0] if terminals else attempts[0]
        status = _required_string(source.attributes, "action.status")
        try:
            ActionStatus(status)
        except ValueError as exc:
            raise CompilationError(f"unsupported action status: {status!r}") from exc
        if terminals and status == ActionStatus.ATTEMPTED.value:
            raise CompilationError(f"action span {span_id} terminal event cannot be ATTEMPTED")

        input_digest = _required_digest(source.attributes, "action.input_digest")
        output_digest = _optional_digest_value(source.attributes, "action.output_digest")
        first_sequence = min(event.sequence for event in action_events)
        compiled.append(
            (
                first_sequence,
                {
                    "action_id": f"gbx:action:{span_id}",
                    "tool_id": _required_string(source.attributes, "tool.id"),
                    "effect": _required_string(source.attributes, "action.effect"),
                    "status": status,
                    "idempotency_key": _optional_string(
                        source.attributes, "action.idempotency_key"
                    ),
                    "input_digest": _digest(input_digest),
                    "output_digest": _optional_digest_object(output_digest),
                    "approval_id": _optional_string(source.attributes, "action.approval_id"),
                },
            )
        )
    return [action for _, action in sorted(compiled, key=lambda item: item[0])]


def _require_matching_action_identity(attempt: RuntimeEvent, terminal: RuntimeEvent) -> None:
    keys = (
        "tool.id",
        "action.effect",
        "action.input_digest",
        "action.idempotency_key",
        "action.approval_id",
    )
    mismatches = [
        key for key in keys if attempt.attributes.get(key) != terminal.attributes.get(key)
    ]
    if mismatches:
        raise CompilationError(
            f"action span {attempt.span_id} changed identity fields: {', '.join(mismatches)}"
        )


def _compile_tools(
    actions: Sequence[Mapping[str, Any]], declarations: Sequence[ToolDeclaration]
) -> list[dict[str, Any]]:
    declared = {item.id: item for item in declarations}
    tool_ids = sorted({str(action["tool_id"]) for action in actions} | set(declared))
    result: list[dict[str, Any]] = []
    for tool_id in tool_ids:
        declaration = declared.get(tool_id)
        if declaration is None:
            result.append(
                {
                    "id": tool_id,
                    "version": None,
                    "datahub_urn": None,
                    "source_digest": None,
                    "schema_digest": None,
                }
            )
        else:
            result.append(
                {
                    **_component(declaration),
                    "schema_digest": _optional_digest_object(declaration.schema_digest),
                }
            )
    return result


def _classify_replay(actions: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    statuses = {str(action["status"]) for action in actions}
    effects = {str(action["effect"]) for action in actions}
    if ActionStatus.ATTEMPTED.value in statuses:
        eligibility = "UNREPLAYABLE"
        reason = "At least one action lacks a terminal observation; its outcome is uncertain."
    elif statuses & {ActionStatus.FAILED.value, ActionStatus.BLOCKED.value}:
        eligibility = "UNREPLAYABLE"
        reason = "At least one recorded action failed or was blocked."
    elif ActionEffect.IRREVERSIBLE.value in effects:
        eligibility = "UNREPLAYABLE"
        reason = "At least one recorded action is irreversible."
    elif ActionEffect.UNKNOWN_EFFECT.value in effects:
        eligibility = "NOT_EVALUATED"
        reason = "At least one action has unknown side-effect semantics."
    elif ActionEffect.REVERSIBLE.value in effects:
        eligibility = "REQUIRES_APPROVAL"
        reason = "Replay contains a reversible mutation and requires fresh approval."
    else:
        eligibility = "ELIGIBLE"
        reason = (
            "All recorded actions are read-only." if actions else "No tool actions were recorded."
        )
    return {"eligibility": eligibility, "reason": reason, "prior_receipt_digest": None}


def _component(declaration: ComponentDeclaration) -> dict[str, Any]:
    return {
        "id": declaration.id,
        "version": declaration.version,
        "datahub_urn": declaration.datahub_urn,
        "source_digest": _optional_digest_object(declaration.source_digest),
    }


def _digest(value: str) -> dict[str, str]:
    return {"algorithm": "sha256", "value": value}


def _optional_digest_object(value: str | None) -> dict[str, str] | None:
    return None if value is None else _digest(value)


def _required_digest(attributes: Mapping[str, Any], key: str) -> str:
    value = _required_string(attributes, key)
    if not _SHA256_PATTERN.fullmatch(value):
        raise CompilationError(f"{key} must be a lowercase SHA-256 digest")
    return value


def _optional_digest_value(attributes: Mapping[str, Any], key: str) -> str | None:
    value = _optional_string(attributes, key)
    if value is not None and not _SHA256_PATTERN.fullmatch(value):
        raise CompilationError(f"{key} must be a lowercase SHA-256 digest or null")
    return value


def _required_string(attributes: Mapping[str, Any], key: str) -> str:
    value = attributes.get(key)
    if not isinstance(value, str) or not value:
        raise CompilationError(f"{key} must be a non-empty string")
    return value


def _optional_string(attributes: Mapping[str, Any], key: str) -> str | None:
    value = attributes.get(key)
    if value is not None and (not isinstance(value, str) or not value):
        raise CompilationError(f"{key} must be a non-empty string or null")
    return value


def _require_nonempty(value: str, label: str) -> None:
    if not value:
        raise ValueError(f"{label} must not be empty")


def _optional_nonempty(value: str | None, label: str) -> None:
    if value is not None and not value:
        raise ValueError(f"{label} must not be empty when provided")


def _optional_digest(value: str | None, label: str) -> None:
    if value is not None and not _SHA256_PATTERN.fullmatch(value):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")


def _require_unique_ids(items: Sequence[ComponentDeclaration], label: str) -> None:
    identifiers = [item.id for item in items]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError(f"{label} declarations must have unique ids")
