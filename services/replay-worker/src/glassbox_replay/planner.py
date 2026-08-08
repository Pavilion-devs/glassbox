"""Deterministic replay policy over verified bundles and exact resource inventory."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from glassbox_dbom.canonical import canonicalize
from glassbox_replay.approval import (
    ApprovalVerification,
    ReplayApproval,
    verify_replay_approval,
)
from glassbox_replay.bundle import ReplayBundleError, verify_replay_bundle
from glassbox_replay.models import (
    ModelDeterminism,
    ReplayDecision,
    ReplayMode,
    ReplayReason,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
)

REPLAY_POLICY_VERSION = "glassbox.replay-policy.v1"
_ACTION_SET_DOMAIN = b"glassbox.replay.action-set.v1\0"
_PLAN_DOMAIN = b"glassbox.replay.plan.v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class ReplayPlan:
    """Content-addressed policy result; it carries no executable callbacks."""

    plan_id: str
    bundle_id: str
    source_receipt_id: str
    evaluated_at: str
    environment: str
    policy_version: str
    decision: ReplayDecision
    reason_codes: tuple[ReplayReason, ...]
    action_set_digest: str
    missing_resources: tuple[str, ...]
    approval_id: str | None
    approval_verification: ApprovalVerification | None
    execution_permitted: bool
    dry_run_permitted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "bundle_id": self.bundle_id,
            "source_receipt_id": self.source_receipt_id,
            "evaluated_at": self.evaluated_at,
            "environment": self.environment,
            "policy_version": self.policy_version,
            "decision": self.decision.value,
            "reason_codes": [item.value for item in self.reason_codes],
            "action_set_digest": {"algorithm": "sha256", "value": self.action_set_digest},
            "missing_resources": list(self.missing_resources),
            "approval_id": self.approval_id,
            "approval_verification": (
                self.approval_verification.to_dict()
                if self.approval_verification is not None
                else None
            ),
            "execution_permitted": self.execution_permitted,
            "dry_run_permitted": self.dry_run_permitted,
        }

    @property
    def valid(self) -> bool:
        return self.plan_id == _plan_id(self._material())

    def _material(self) -> dict[str, Any]:
        value = self.to_dict()
        value.pop("plan_id")
        return value


def plan_replay(
    bundle: Mapping[str, Any],
    *,
    source_receipt: Mapping[str, Any],
    inventory: ResourceInventory,
    evaluated_at: str,
    approval: ReplayApproval | None = None,
    trusted_approval_key_ids: frozenset[str] = frozenset(),
    require_bundle_signature: bool = True,
    require_source_signature: bool = True,
) -> ReplayPlan:
    """Return the same closed decision for the same verified planning inputs."""

    _validate_timestamp(evaluated_at)
    verification = verify_replay_bundle(
        bundle,
        require_signature=require_bundle_signature,
        source_receipt=source_receipt,
        require_source_signature=require_source_signature,
    )
    if not verification.valid:
        raise ReplayBundleError(
            "replay bundle verification failed: " + "; ".join(verification.errors)
        )

    bundle_id = _text(bundle, "bundle_id")
    source = _mapping(bundle, "source")
    recipe = _mapping(bundle, "recipe")
    execution = _mapping(bundle, "execution")
    mode = ReplayMode(_text(bundle, "mode"))
    environment = _text(recipe, "environment")
    reasons: set[ReplayReason] = set()
    missing: list[str] = []

    source_eligibility = _text(source, "replay_eligibility")
    if source_eligibility == "UNREPLAYABLE":
        reasons.add(ReplayReason.SOURCE_UNREPLAYABLE)
    elif source_eligibility == "NOT_EVALUATED":
        reasons.add(ReplayReason.SOURCE_NOT_EVALUATED)

    matched_resources = _check_resources(recipe, inventory, reasons, missing)
    _check_execution(execution, recipe, reasons)
    _check_context(bundle, reasons)
    _check_action_input_replacements(bundle, recipe, reasons)
    actions = _list_of_mappings(recipe, "actions")
    reversible_tools: set[str] = set()
    for action in actions:
        status = _text(action, "status")
        effect = _text(action, "effect")
        if status in {"ATTEMPTED", "PLANNED"}:
            reasons.add(ReplayReason.ACTION_OUTCOME_UNCERTAIN)
        elif status in {"FAILED", "BLOCKED"}:
            reasons.add(ReplayReason.ACTION_FAILED_OR_BLOCKED)
        if effect == "IRREVERSIBLE":
            reasons.add(ReplayReason.IRREVERSIBLE_ACTION)
        elif effect == "UNKNOWN_EFFECT":
            reasons.add(ReplayReason.UNKNOWN_ACTION_EFFECT)
        elif effect == "REVERSIBLE":
            reasons.add(ReplayReason.REVERSIBLE_ACTION)
            reversible_tools.add(_text(action, "tool_id"))
            if action.get("idempotency_key") is None:
                reasons.add(ReplayReason.IDEMPOTENCY_KEY_MISSING)

    for tool_id in sorted(reversible_tools):
        available = inventory.find(ResourceKind.TOOL, tool_id)
        if available is None or available.rollback_contract_digest is None:
            reasons.add(ReplayReason.ROLLBACK_CONTRACT_MISSING)

    action_set_digest = _action_set_digest(
        bundle_id=bundle_id,
        recipe=recipe,
        execution=execution,
        context=_list_of_mappings(bundle, "context"),
        matched_resources=matched_resources,
    )

    approval_verification: ApprovalVerification | None = None
    hard_reasons = {
        ReplayReason.SOURCE_UNREPLAYABLE,
        ReplayReason.ACTION_OUTCOME_UNCERTAIN,
        ReplayReason.ACTION_FAILED_OR_BLOCKED,
        ReplayReason.RESOURCE_UNPINNED,
        ReplayReason.RESOURCE_UNAVAILABLE,
    }
    dry_reasons = {
        ReplayReason.SOURCE_NOT_EVALUATED,
        ReplayReason.IRREVERSIBLE_ACTION,
        ReplayReason.UNKNOWN_ACTION_EFFECT,
        ReplayReason.IDEMPOTENCY_KEY_MISSING,
        ReplayReason.ROLLBACK_CONTRACT_MISSING,
        ReplayReason.CONTEXT_INCOMPLETE,
        ReplayReason.CONTEXT_REPLACEMENT_UNVERIFIED,
        ReplayReason.ACTION_INPUT_REPLACEMENT_UNVERIFIED,
        ReplayReason.EXECUTION_INPUT_UNAVAILABLE,
        ReplayReason.FEATURE_FLAGS_UNPINNED,
        ReplayReason.MODEL_CONFIG_UNPINNED,
        ReplayReason.MODEL_DETERMINISM_UNKNOWN,
    }

    if mode is ReplayMode.DRY:
        reasons.add(ReplayReason.DRY_MODE_REQUESTED)
        decision = ReplayDecision.DRY_RUN_ONLY
    elif reasons & hard_reasons:
        decision = ReplayDecision.BLOCK
    elif reasons & dry_reasons:
        decision = ReplayDecision.DRY_RUN_ONLY
    elif ReplayReason.REVERSIBLE_ACTION in reasons:
        if approval is None:
            reasons.add(ReplayReason.APPROVAL_REQUIRED)
            decision = ReplayDecision.REQUIRE_HUMAN_APPROVAL
        else:
            approval_verification = verify_replay_approval(
                approval,
                expected_bundle_id=bundle_id,
                expected_action_set_digest=action_set_digest,
                expected_environment=environment,
                evaluated_at=evaluated_at,
                trusted_key_ids=trusted_approval_key_ids,
            )
            if approval_verification.valid:
                decision = ReplayDecision.ALLOW_WITH_RECEIPT
            else:
                reasons.add(ReplayReason.APPROVAL_INVALID)
                decision = ReplayDecision.BLOCK
    else:
        reasons.add(ReplayReason.SAFE_READ_ONLY_REPLAY)
        decision = ReplayDecision.ALLOW

    execution_permitted = decision in {
        ReplayDecision.ALLOW,
        ReplayDecision.ALLOW_WITH_RECEIPT,
    }
    material: dict[str, Any] = {
        "bundle_id": bundle_id,
        "source_receipt_id": _text(source, "receipt_id"),
        "evaluated_at": evaluated_at,
        "environment": environment,
        "policy_version": REPLAY_POLICY_VERSION,
        "decision": decision.value,
        "reason_codes": [item.value for item in sorted(reasons, key=lambda item: item.value)],
        "action_set_digest": {"algorithm": "sha256", "value": action_set_digest},
        "missing_resources": sorted(missing),
        "approval_id": approval.approval_id if approval is not None else None,
        "approval_verification": (
            approval_verification.to_dict() if approval_verification is not None else None
        ),
        "execution_permitted": execution_permitted,
        "dry_run_permitted": True,
    }
    return ReplayPlan(
        plan_id=_plan_id(material),
        bundle_id=bundle_id,
        source_receipt_id=_text(source, "receipt_id"),
        evaluated_at=evaluated_at,
        environment=environment,
        policy_version=REPLAY_POLICY_VERSION,
        decision=decision,
        reason_codes=tuple(sorted(reasons, key=lambda item: item.value)),
        action_set_digest=action_set_digest,
        missing_resources=tuple(sorted(missing)),
        approval_id=approval.approval_id if approval is not None else None,
        approval_verification=approval_verification,
        execution_permitted=execution_permitted,
    )


def _check_resources(
    recipe: Mapping[str, Any],
    inventory: ResourceInventory,
    reasons: set[ReplayReason],
    missing: list[str],
) -> tuple[ResourceAvailability, ...]:
    pins: list[tuple[ResourceKind, Mapping[str, Any], bool]] = [
        (ResourceKind.AGENT, _mapping(recipe, "agent"), True),
        (ResourceKind.WORKFLOW, _mapping(recipe, "workflow"), False),
    ]
    for kind, key, source_required in (
        (ResourceKind.MODEL, "models", True),
        (ResourceKind.SKILL, "skills", True),
        (ResourceKind.TOOL, "tools", True),
    ):
        pins.extend((kind, item, source_required) for item in _list_of_mappings(recipe, key))

    matched: list[ResourceAvailability] = []
    for kind, pin, source_required in pins:
        resource_id = _text(pin, "id")
        version = pin.get("version")
        source_digest = _digest_value(pin.get("source_digest"))
        schema_digest = _digest_value(pin.get("schema_digest"))
        identity = f"{kind.value}:{resource_id}"
        if not isinstance(version, str) or not version:
            reasons.add(ReplayReason.RESOURCE_UNPINNED)
            missing.append(identity + ":version")
            continue
        if source_required and source_digest is None:
            reasons.add(ReplayReason.RESOURCE_UNPINNED)
            missing.append(identity + ":source_digest")
            continue
        if kind is ResourceKind.TOOL and schema_digest is None:
            reasons.add(ReplayReason.RESOURCE_UNPINNED)
            missing.append(identity + ":schema_digest")
            continue
        available = inventory.find(kind, resource_id)
        if (
            available is None
            or available.version != version
            or available.source_digest != source_digest
            or (kind is ResourceKind.TOOL and available.schema_digest != schema_digest)
        ):
            reasons.add(ReplayReason.RESOURCE_UNAVAILABLE)
            missing.append(identity)
            continue
        matched.append(available)
    return tuple(sorted(matched, key=lambda item: (item.kind.value, item.resource_id)))


def _check_execution(
    execution: Mapping[str, Any],
    recipe: Mapping[str, Any],
    reasons: set[ReplayReason],
) -> None:
    if execution.get("input_digest") is None or execution.get("input_reference") is None:
        reasons.add(ReplayReason.EXECUTION_INPUT_UNAVAILABLE)
    if execution.get("feature_flags_digest") is None:
        reasons.add(ReplayReason.FEATURE_FLAGS_UNPINNED)
    model_configs = {
        _text(item, "model_id"): item for item in _list_of_mappings(execution, "model_configs")
    }
    for model in _list_of_mappings(recipe, "models"):
        model_id = _text(model, "id")
        config = model_configs.get(model_id)
        if config is None:
            reasons.add(ReplayReason.MODEL_CONFIG_UNPINNED)
            continue
        determinism = ModelDeterminism(_text(config, "determinism"))
        if determinism is ModelDeterminism.UNKNOWN:
            reasons.add(ReplayReason.MODEL_DETERMINISM_UNKNOWN)
        elif determinism is ModelDeterminism.NONDETERMINISTIC:
            reasons.add(ReplayReason.MODEL_NONDETERMINISM_DISCLOSED)


def _check_context(bundle: Mapping[str, Any], reasons: set[ReplayReason]) -> None:
    for item in _list_of_mappings(bundle, "context"):
        if item.get("active_representation_digest") is None or item.get("state") == "UNKNOWN":
            reasons.add(ReplayReason.CONTEXT_INCOMPLETE)
        if (
            item.get("origin") == "CONTEXT_REPLACEMENT"
            and item.get("verification_authority") is None
        ):
            reasons.add(ReplayReason.CONTEXT_REPLACEMENT_UNVERIFIED)


def _check_action_input_replacements(
    bundle: Mapping[str, Any],
    recipe: Mapping[str, Any],
    reasons: set[ReplayReason],
) -> None:
    context = {_text(item, "evidence_id"): item for item in _list_of_mappings(bundle, "context")}
    referenced: set[str] = set()
    invalid = False
    for action in _list_of_mappings(recipe, "actions"):
        fields = (
            action.get("original_input_digest"),
            action.get("input_origin"),
            action.get("input_evidence_ids"),
            action.get("input_verification_authority"),
        )
        if not any(value is not None for value in fields):
            continue
        evidence_ids = action.get("input_evidence_ids")
        authority = action.get("input_verification_authority")
        if (
            action.get("input_origin") != "CONTEXT_REPLACEMENT"
            or _digest_value(action.get("original_input_digest")) is None
            or not isinstance(evidence_ids, list)
            or not evidence_ids
            or not all(isinstance(item, str) and item for item in evidence_ids)
            or not isinstance(authority, str)
            or not authority
        ):
            invalid = True
            continue
        for evidence_id in evidence_ids:
            selected = context.get(evidence_id)
            if (
                selected is None
                or selected.get("role") != "INPUT"
                or selected.get("origin") != "CONTEXT_REPLACEMENT"
                or selected.get("verification_authority") != authority
            ):
                invalid = True
            else:
                referenced.add(evidence_id)

    replaced_inputs = {
        evidence_id
        for evidence_id, item in context.items()
        if item.get("role") == "INPUT" and item.get("origin") == "CONTEXT_REPLACEMENT"
    }
    if invalid or referenced != replaced_inputs:
        reasons.add(ReplayReason.ACTION_INPUT_REPLACEMENT_UNVERIFIED)


def _action_set_digest(
    *,
    bundle_id: str,
    recipe: Mapping[str, Any],
    execution: Mapping[str, Any],
    context: tuple[Mapping[str, Any], ...],
    matched_resources: tuple[ResourceAvailability, ...],
) -> str:
    material = {
        "bundle_id": bundle_id,
        "actions": list(_list_of_mappings(recipe, "actions")),
        "execution": dict(execution),
        "context": [dict(item) for item in context],
        "resources": [item.to_dict() for item in matched_resources],
    }
    return hashlib.sha256(_ACTION_SET_DOMAIN + canonicalize(material)).hexdigest()


def _plan_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_PLAN_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:replay-plan:sha256:{digest}"


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayBundleError(f"{key} must be an object")
    return selected


def _list_of_mappings(value: Mapping[str, Any], key: str) -> tuple[Mapping[str, Any], ...]:
    selected = value.get(key)
    if not isinstance(selected, list) or not all(isinstance(item, Mapping) for item in selected):
        raise ReplayBundleError(f"{key} must be an array of objects")
    return tuple(selected)


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayBundleError(f"{key} must be a non-empty string")
    return selected


def _digest_value(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        return None
    digest = value.get("value")
    if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
        return None
    return digest


def _validate_timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplayBundleError("evaluated_at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplayBundleError("evaluated_at must include a timezone")


__all__ = ["REPLAY_POLICY_VERSION", "ReplayPlan", "plan_replay"]
