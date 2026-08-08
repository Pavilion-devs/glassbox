"""Capability-scoped read-only replay execution and replay DBOM emission."""

from __future__ import annotations

import copy
import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from glassbox.redaction import digest_value
from glassbox_dbom import SigningKey, seal_receipt, verify_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_replay.bundle import verify_replay_bundle
from glassbox_replay.isolation import IsolatedCapabilityOutput, IsolationAttestation
from glassbox_replay.models import ReplayDecision, ResourceInventory
from glassbox_replay.planner import ReplayPlan, plan_replay

_EXECUTION_DOMAIN = b"glassbox.replay.execution.v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TRACE_ID = re.compile(r"^[0-9a-f]{32}$")
_SPAN_ID = re.compile(r"^[0-9a-f]{16}$")


class ReplayExecutionError(RuntimeError):
    """Raised when a replay cannot enter the read-only execution boundary."""


class ReadOnlyHandler(Protocol):
    """One explicitly injected capability; arbitrary ambient tools are unavailable."""

    def __call__(self, action_input: object) -> object: ...


class OutputProjector(Protocol):
    """Derive the consequential output from verified input and action outputs."""

    def __call__(
        self,
        replay_input: object,
        action_outputs: Mapping[str, object],
    ) -> object: ...


@dataclass(frozen=True)
class ReadOnlyCapability:
    """Exact tool pin plus the only callable exposed for that replay tool."""

    tool_id: str
    version: str
    source_digest: str
    schema_digest: str
    authority: str
    handler: ReadOnlyHandler = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _nonempty(self.tool_id, "tool_id")
        _nonempty(self.version, "version")
        _digest(self.source_digest, "source_digest")
        _digest(self.schema_digest, "schema_digest")
        _nonempty(self.authority, "authority")
        if not callable(self.handler):
            raise ReplayExecutionError("read-only capability handler must be callable")


@dataclass(frozen=True)
class ReplayActionInput:
    """Transient action input; its raw value is excluded from every projection."""

    action_id: str
    value: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        _nonempty(self.action_id, "action_id")

    @property
    def digest(self) -> str:
        return digest_value(self.value)


@dataclass(frozen=True)
class ReplayContextObservation:
    """Runtime proof for one explicitly replaced context representation."""

    evidence_id: str
    representation_digest: str
    verification_authority: str
    source_span_id: str
    observed_at: str
    capture_method: str = "SDK_EVENT"

    def __post_init__(self) -> None:
        _nonempty(self.evidence_id, "evidence_id")
        _digest(self.representation_digest, "representation_digest")
        _nonempty(self.verification_authority, "verification_authority")
        if not _SPAN_ID.fullmatch(self.source_span_id):
            raise ReplayExecutionError("source_span_id must contain 16 lowercase hex characters")
        _timestamp(self.observed_at, "observed_at")
        if self.capture_method not in {"OTEL_SPAN", "TOOL_RESULT", "SDK_EVENT"}:
            raise ReplayExecutionError("replacement capture_method must be runtime-observed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "representation_digest": _digest_object(self.representation_digest),
            "verification_authority": self.verification_authority,
            "source_span_id": self.source_span_id,
            "observed_at": self.observed_at,
            "capture_method": self.capture_method,
        }


@dataclass(frozen=True)
class ReplayExecutionInputs:
    """Transient values resolved from digest-bound artifact references."""

    replay_input: object = field(repr=False, compare=False)
    action_inputs: tuple[ReplayActionInput, ...] = ()
    context_observations: tuple[ReplayContextObservation, ...] = ()

    def __post_init__(self) -> None:
        _unique((item.action_id for item in self.action_inputs), "action input IDs")
        _unique(
            (item.evidence_id for item in self.context_observations),
            "context observation IDs",
        )

    @property
    def replay_input_digest(self) -> str:
        return digest_value(self.replay_input)


@dataclass(frozen=True)
class ExecutedAction:
    """Digest-only projection plus a transient output used to derive the final output."""

    action_id: str
    tool_id: str
    status: str
    input_digest: str
    output_digest: str | None
    capability_authority: str
    output: object | None = field(default=None, repr=False, compare=False)
    isolation_attestation: IsolationAttestation | None = None

    @property
    def valid(self) -> bool:
        if self.status == "SUCCEEDED":
            return (
                self.output_digest is not None
                and digest_value(self.output) == self.output_digest
                and (self.isolation_attestation is None or self.isolation_attestation.valid)
            )
        return (
            self.output is None
            and self.output_digest is None
            and self.isolation_attestation is None
        )

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "action_id": self.action_id,
            "tool_id": self.tool_id,
            "status": self.status,
            "input_digest": _digest_object(self.input_digest),
            "output_digest": (
                _digest_object(self.output_digest) if self.output_digest is not None else None
            ),
            "capability_authority": self.capability_authority,
        }
        if self.isolation_attestation is not None:
            value["isolation"] = self.isolation_attestation.to_dict()
        return value


@dataclass(frozen=True)
class ReadOnlyReplayExecution:
    """Content-addressed outcome; raw values are transient and never serialized."""

    execution_id: str
    plan_id: str
    bundle_id: str
    source_receipt_id: str
    run_id: str
    trace_id: str
    started_at: str
    ended_at: str
    status: str
    actions: tuple[ExecutedAction, ...]
    context_observations: tuple[ReplayContextObservation, ...]
    output_digest: str
    failure_type: str | None
    source_history_mutations: int
    output: object = field(repr=False, compare=False)

    @property
    def valid(self) -> bool:
        return (
            self.execution_id == _execution_id(self._material())
            and self.source_history_mutations == 0
            and all(item.valid for item in self.actions)
            and digest_value(self.output) == self.output_digest
            and (self.status == "SUCCEEDED") == (self.failure_type is None)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "plan_id": self.plan_id,
            "bundle_id": self.bundle_id,
            "source_receipt_id": self.source_receipt_id,
            "run_id": self.run_id,
            "trace_id": self.trace_id,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "status": self.status,
            "actions": [item.to_dict() for item in self.actions],
            "context_observations": [item.to_dict() for item in self.context_observations],
            "output_digest": _digest_object(self.output_digest),
            "failure_type": self.failure_type,
            "source_history_mutations": self.source_history_mutations,
        }

    def _material(self) -> dict[str, Any]:
        value = self.to_dict()
        value.pop("execution_id")
        return value


class ReadOnlyReplayExecutor:
    """Re-authorize and invoke only exact, explicitly registered read-only tools.

    This boundary removes ambient tool lookup and mutation-capable action types. The
    injected Python handlers remain trusted code; OS/network sandboxing is a separate
    deployment responsibility and is not claimed by this class.
    """

    def __init__(self, capabilities: Iterable[ReadOnlyCapability]) -> None:
        selected = tuple(capabilities)
        _unique((item.tool_id for item in selected), "capability tool IDs")
        self._capabilities = {item.tool_id: item for item in selected}

    def execute(
        self,
        bundle: Mapping[str, Any],
        plan: ReplayPlan,
        *,
        source_receipt: Mapping[str, Any],
        inventory: ResourceInventory,
        inputs: ReplayExecutionInputs,
        output_projector: OutputProjector,
        run_id: str,
        trace_id: str,
        started_at: str,
        ended_at: str,
        require_bundle_signature: bool = True,
        require_source_signature: bool = True,
    ) -> ReadOnlyReplayExecution:
        """Execute the exact authorized read-only recipe and retain only commitments."""

        _nonempty(run_id, "run_id")
        if not _TRACE_ID.fullmatch(trace_id):
            raise ReplayExecutionError("trace_id must contain 32 lowercase hex characters")
        start = _timestamp(started_at, "started_at")
        end = _timestamp(ended_at, "ended_at")
        if end < start:
            raise ReplayExecutionError("ended_at must not precede started_at")
        if not plan.valid:
            raise ReplayExecutionError("replay plan content address is invalid")
        if plan.decision is not ReplayDecision.ALLOW or not plan.execution_permitted:
            raise ReplayExecutionError("read-only executor requires an ALLOW plan")

        source_snapshot = copy.deepcopy(dict(source_receipt))
        verification = verify_replay_bundle(
            bundle,
            require_signature=require_bundle_signature,
            source_receipt=source_receipt,
            require_source_signature=require_source_signature,
        )
        if not verification.valid:
            raise ReplayExecutionError(
                "replay bundle verification failed: " + "; ".join(verification.errors)
            )
        recomputed = plan_replay(
            bundle,
            source_receipt=source_receipt,
            inventory=inventory,
            evaluated_at=plan.evaluated_at,
            require_bundle_signature=require_bundle_signature,
            require_source_signature=require_source_signature,
        )
        if recomputed != plan:
            raise ReplayExecutionError("replay plan does not match fresh policy evaluation")

        recipe = _mapping(bundle, "recipe")
        execution = _mapping(bundle, "execution")
        recorded_input = _nested_digest(execution, "input_digest")
        if recorded_input is None or inputs.replay_input_digest != recorded_input:
            raise ReplayExecutionError("resolved replay input does not match the bundle digest")
        action_inputs = {item.action_id: item for item in inputs.action_inputs}
        actions = _list_of_mappings(recipe, "actions")
        expected_ids = {_text(item, "action_id") for item in actions}
        if set(action_inputs) != expected_ids:
            raise ReplayExecutionError("resolved action inputs must exactly match replay actions")
        _verify_context_observations(bundle, inputs.context_observations)

        tools = {_text(item, "id"): item for item in _list_of_mappings(recipe, "tools")}
        executed: list[ExecutedAction] = []
        raw_outputs: dict[str, object] = {}
        failure_type: str | None = None
        for action in actions:
            action_id = _text(action, "action_id")
            tool_id = _text(action, "tool_id")
            if _text(action, "effect") != "READ_ONLY":
                raise ReplayExecutionError("read-only executor refuses non-read-only actions")
            action_input = action_inputs[action_id]
            expected_input = _required_nested_digest(action, "input_digest")
            if action_input.digest != expected_input:
                raise ReplayExecutionError(f"action input digest mismatch for {action_id}")
            tool = tools.get(tool_id)
            capability = self._capabilities.get(tool_id)
            if tool is None or capability is None or not _capability_matches(capability, tool):
                raise ReplayExecutionError(f"exact read-only capability unavailable for {tool_id}")
            try:
                result = capability.handler(copy.deepcopy(action_input.value))
            except Exception as exc:
                failure_type = type(exc).__qualname__
                executed.append(
                    ExecutedAction(
                        action_id,
                        tool_id,
                        "FAILED",
                        action_input.digest,
                        None,
                        capability.authority,
                    )
                )
                break
            isolation_attestation = None
            if isinstance(result, IsolatedCapabilityOutput):
                output = result.output
                isolation_attestation = result.attestation
                if (
                    isolation_attestation.capability_source_digest != capability.source_digest
                    or isolation_attestation.capability_schema_digest != capability.schema_digest
                ):
                    raise ReplayExecutionError(f"isolated capability pin mismatch for {tool_id}")
            else:
                output = result
            output_digest = digest_value(output)
            raw_outputs[action_id] = output
            executed.append(
                ExecutedAction(
                    action_id,
                    tool_id,
                    "SUCCEEDED",
                    action_input.digest,
                    output_digest,
                    capability.authority,
                    output,
                    isolation_attestation,
                )
            )

        if failure_type is None:
            try:
                final_output = output_projector(
                    copy.deepcopy(inputs.replay_input),
                    copy.deepcopy(raw_outputs),
                )
            except Exception as exc:
                failure_type = type(exc).__qualname__
                final_output = {
                    "status": "FAILED",
                    "stage": "OUTPUT_PROJECTION",
                    "error_type": failure_type,
                }
        else:
            final_output = {
                "status": "FAILED",
                "stage": "ACTION_EXECUTION",
                "error_type": failure_type,
            }

        executed_ids = {item.action_id for item in executed}
        for action in actions:
            action_id = _text(action, "action_id")
            if action_id not in executed_ids:
                executed.append(
                    ExecutedAction(
                        action_id,
                        _text(action, "tool_id"),
                        "BLOCKED",
                        _required_nested_digest(action, "input_digest"),
                        None,
                        "not-invoked-after-failure",
                    )
                )

        if dict(source_receipt) != source_snapshot:
            raise ReplayExecutionError("source receipt mutated during replay execution")
        status = "SUCCEEDED" if failure_type is None else "FAILED"
        material: dict[str, Any] = {
            "plan_id": plan.plan_id,
            "bundle_id": plan.bundle_id,
            "source_receipt_id": plan.source_receipt_id,
            "run_id": run_id,
            "trace_id": trace_id,
            "started_at": started_at,
            "ended_at": ended_at,
            "status": status,
            "actions": [item.to_dict() for item in executed],
            "context_observations": [item.to_dict() for item in inputs.context_observations],
            "output_digest": _digest_object(digest_value(final_output)),
            "failure_type": failure_type,
            "source_history_mutations": 0,
        }
        return ReadOnlyReplayExecution(
            execution_id=_execution_id(material),
            plan_id=plan.plan_id,
            bundle_id=plan.bundle_id,
            source_receipt_id=plan.source_receipt_id,
            run_id=run_id,
            trace_id=trace_id,
            started_at=started_at,
            ended_at=ended_at,
            status=status,
            actions=tuple(executed),
            context_observations=inputs.context_observations,
            output_digest=digest_value(final_output),
            failure_type=failure_type,
            source_history_mutations=0,
            output=final_output,
        )


def build_replay_receipt(
    execution: ReadOnlyReplayExecution,
    bundle: Mapping[str, Any],
    plan: ReplayPlan,
    *,
    source_receipt: Mapping[str, Any],
    inputs: ReplayExecutionInputs,
    signing_keys: Iterable[SigningKey],
    require_bundle_signature: bool = True,
    require_source_signature: bool = True,
) -> dict[str, Any]:
    """Emit a new signed DBOM linked to, but never overwriting, its source DBOM."""

    if not execution.valid:
        raise ReplayExecutionError("replay execution content address is invalid")
    if not plan.valid or execution.plan_id != plan.plan_id:
        raise ReplayExecutionError("execution is not bound to the supplied replay plan")
    verification = verify_replay_bundle(
        bundle,
        require_signature=require_bundle_signature,
        source_receipt=source_receipt,
        require_source_signature=require_source_signature,
    )
    if not verification.valid:
        raise ReplayExecutionError(
            "replay bundle verification failed: " + "; ".join(verification.errors)
        )
    if execution.bundle_id != bundle.get("bundle_id"):
        raise ReplayExecutionError("execution is not bound to the supplied replay bundle")
    if execution.context_observations != inputs.context_observations:
        raise ReplayExecutionError("execution is not bound to supplied context observations")
    _verify_context_observations(bundle, inputs.context_observations)
    source_report = verify_receipt(source_receipt, require_signature=require_source_signature)
    if not source_report.valid:
        raise ReplayExecutionError("source receipt verification failed")
    keys = tuple(signing_keys)
    if not keys:
        raise ReplayExecutionError("replay receipt requires at least one signing key")

    source = copy.deepcopy(dict(source_receipt))
    source_snapshot = copy.deepcopy(source)
    source_integrity = _mapping(source, "integrity")
    source_payload_digest = _required_nested_digest(source_integrity, "payload_digest")
    action_results = {item.action_id: item for item in execution.actions}
    actions: list[dict[str, Any]] = []
    for original in _list_of_mappings(source, "actions"):
        action_id = _text(original, "action_id")
        result = action_results.get(action_id)
        if result is None:
            raise ReplayExecutionError(f"execution omitted action {action_id}")
        actions.append(
            {
                "action_id": action_id,
                "tool_id": _text(original, "tool_id"),
                "effect": "READ_ONLY",
                "status": result.status,
                "idempotency_key": original.get("idempotency_key"),
                "input_digest": _digest_object(result.input_digest),
                "output_digest": (
                    _digest_object(result.output_digest)
                    if result.output_digest is not None
                    else None
                ),
                "approval_id": plan.approval_id,
            }
        )

    evidence = _replay_evidence(source, bundle, inputs.context_observations)
    output = _mapping(source, "output")
    payload: dict[str, Any] = {
        "spec_version": _text(source, "spec_version"),
        "run": {
            "run_id": execution.run_id,
            "status": execution.status,
            "started_at": execution.started_at,
            "ended_at": execution.ended_at,
            "trace_id": execution.trace_id,
            "parent_run_id": _text(_mapping(source, "run"), "run_id"),
            "environment": plan.environment,
        },
        "agent": copy.deepcopy(_mapping(source, "agent")),
        "workflow": copy.deepcopy(_mapping(source, "workflow")),
        "models": copy.deepcopy(list(_list_of_mappings(source, "models"))),
        "skills": copy.deepcopy(list(_list_of_mappings(source, "skills"))),
        "tools": copy.deepcopy(list(_list_of_mappings(source, "tools"))),
        "evidence": evidence,
        "queries": copy.deepcopy(list(_list_of_mappings(source, "queries"))),
        "actions": actions,
        "approvals": [],
        "evaluations": [],
        "output": {
            "kind": _text(output, "kind") if execution.status == "SUCCEEDED" else "replay_failure",
            "mime_type": (
                _text(output, "mime_type")
                if execution.status == "SUCCEEDED"
                else "application/json"
            ),
            "digest": _digest_object(execution.output_digest),
            "redacted": True,
            "redaction_reason": "Raw replay output is excluded from the DBOM receipt.",
        },
        "replay": {
            "eligibility": "ELIGIBLE" if execution.status == "SUCCEEDED" else "UNREPLAYABLE",
            "reason": (
                "Read-only replay completed under an exact verified plan."
                if execution.status == "SUCCEEDED"
                else "Read-only replay failed; no later action was invoked."
            ),
            "prior_receipt_digest": _digest_object(source_payload_digest),
        },
        "extensions": {
            "glassbox.replay.bundle_id": execution.bundle_id,
            "glassbox.replay.plan_id": execution.plan_id,
            "glassbox.replay.execution_id": execution.execution_id,
            "glassbox.replay.source_receipt_id": execution.source_receipt_id,
            "glassbox.replay.mode": _text(bundle, "mode"),
            "glassbox.replay.policy_version": plan.policy_version,
            "glassbox.replay.isolation_attestation_ids": [
                item.isolation_attestation.attestation_id
                for item in execution.actions
                if item.isolation_attestation is not None
            ],
        },
    }
    receipt = seal_receipt(payload, signing_keys=keys)
    if source != source_snapshot:
        raise ReplayExecutionError("source receipt changed while deriving replay receipt")
    if receipt["receipt_id"] == source.get("receipt_id"):
        raise ReplayExecutionError("replay receipt must not reuse the source receipt ID")
    return receipt


def _verify_context_observations(
    bundle: Mapping[str, Any], observations: tuple[ReplayContextObservation, ...]
) -> None:
    expected = {
        _text(item, "evidence_id"): item
        for item in _list_of_mappings(bundle, "context")
        if item.get("origin") == "CONTEXT_REPLACEMENT"
    }
    supplied = {item.evidence_id: item for item in observations}
    if set(expected) != set(supplied):
        raise ReplayExecutionError(
            "runtime context observations must exactly match context replacements"
        )
    for evidence_id, context in expected.items():
        observation = supplied[evidence_id]
        if observation.representation_digest != _required_nested_digest(
            context, "active_representation_digest"
        ) or observation.verification_authority != context.get("verification_authority"):
            raise ReplayExecutionError(f"context observation mismatch for {evidence_id}")


def _replay_evidence(
    source_receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
    observations: tuple[ReplayContextObservation, ...],
) -> list[dict[str, Any]]:
    context = {_text(item, "evidence_id"): item for item in _list_of_mappings(bundle, "context")}
    observed = {item.evidence_id: item for item in observations}
    result: list[dict[str, Any]] = []
    for original in _list_of_mappings(source_receipt, "evidence"):
        evidence = copy.deepcopy(dict(original))
        evidence_id = _text(evidence, "evidence_id")
        selected = context.get(evidence_id)
        if selected is None:
            raise ReplayExecutionError(f"bundle context omitted evidence {evidence_id}")
        evidence["representation_digest"] = copy.deepcopy(
            _mapping(selected, "active_representation_digest")
        )
        observation = observed.get(evidence_id)
        if observation is not None:
            evidence["source_span_id"] = observation.source_span_id
            evidence["observed_at"] = observation.observed_at
            state = _text(evidence, "state")
            if state == "OBSERVED":
                evidence["provenance"] = {
                    "capture_method": observation.capture_method,
                    "rule_id": None,
                    "confidence": None,
                }
            elif state == "INFERRED":
                evidence["provenance"] = {
                    "capture_method": observation.capture_method,
                    "rule_id": "glassbox.replay.context-observation.v1",
                    "confidence": 1.0,
                }
            else:
                evidence["provenance"] = {
                    "capture_method": "OWNER_DECLARATION",
                    "rule_id": None,
                    "confidence": None,
                }
        result.append(evidence)
    return result


def _capability_matches(capability: ReadOnlyCapability, tool: Mapping[str, Any]) -> bool:
    return (
        capability.tool_id == tool.get("id")
        and capability.version == tool.get("version")
        and capability.source_digest == _nested_digest(tool, "source_digest")
        and capability.schema_digest == _nested_digest(tool, "schema_digest")
    )


def _execution_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_EXECUTION_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:replay-execution:sha256:{digest}"


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayExecutionError(f"{key} must be an object")
    return selected


def _list_of_mappings(value: Mapping[str, Any], key: str) -> tuple[Mapping[str, Any], ...]:
    selected = value.get(key)
    if not isinstance(selected, list) or not all(isinstance(item, Mapping) for item in selected):
        raise ReplayExecutionError(f"{key} must be an array of objects")
    return tuple(selected)


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayExecutionError(f"{key} must be a non-empty string")
    return selected


def _nested_digest(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        return None
    digest = selected.get("value")
    return digest if isinstance(digest, str) and _SHA256.fullmatch(digest) else None


def _required_nested_digest(value: Mapping[str, Any], key: str) -> str:
    digest = _nested_digest(value, key)
    if digest is None:
        raise ReplayExecutionError(f"{key} must be a SHA-256 digest")
    return digest


def _digest_object(value: str) -> dict[str, str]:
    _digest(value, "digest")
    return {"algorithm": "sha256", "value": value}


def _digest(value: str, name: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ReplayExecutionError(f"{name} must be a lowercase SHA-256 digest")


def _nonempty(value: str, name: str) -> None:
    if not value:
        raise ReplayExecutionError(f"{name} must be non-empty")


def _unique(values: Iterable[str], name: str) -> None:
    selected = tuple(values)
    if len(selected) != len(set(selected)):
        raise ReplayExecutionError(f"{name} must be unique")


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplayExecutionError(f"{name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplayExecutionError(f"{name} must include a timezone")
    return parsed


__all__ = [
    "ExecutedAction",
    "OutputProjector",
    "ReadOnlyCapability",
    "ReadOnlyReplayExecution",
    "ReadOnlyReplayExecutor",
    "ReplayActionInput",
    "ReplayContextObservation",
    "ReplayExecutionError",
    "ReplayExecutionInputs",
    "build_replay_receipt",
]
