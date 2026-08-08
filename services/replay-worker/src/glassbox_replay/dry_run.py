"""Side-effect-free replay rendering with no tool invocation capability."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from glassbox_dbom.canonical import canonicalize
from glassbox_replay.bundle import ReplayBundleError, verify_replay_bundle
from glassbox_replay.models import ReplayDecision
from glassbox_replay.planner import ReplayPlan

_REPORT_DOMAIN = b"glassbox.replay.dry-run-report.v1\0"


@dataclass(frozen=True)
class DryRunReport:
    """A deterministic reconstruction report that proves it invoked nothing."""

    report_id: str
    plan_id: str
    bundle_id: str
    source_receipt_id: str
    status: str
    decision: ReplayDecision
    steps: tuple[dict[str, Any], ...]
    external_calls: int = 0
    history_mutations: int = 0
    would_invoke_actions: bool = False

    @property
    def valid(self) -> bool:
        return (
            self.external_calls == 0
            and self.history_mutations == 0
            and not self.would_invoke_actions
            and self.report_id == _report_id(self._material())
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "plan_id": self.plan_id,
            "bundle_id": self.bundle_id,
            "source_receipt_id": self.source_receipt_id,
            "status": self.status,
            "decision": self.decision.value,
            "steps": list(self.steps),
            "external_calls": self.external_calls,
            "history_mutations": self.history_mutations,
            "would_invoke_actions": self.would_invoke_actions,
        }

    def _material(self) -> dict[str, Any]:
        value = self.to_dict()
        value.pop("report_id")
        return value


class DryRunExecutor:
    """Render verified actions without accepting or calling an execution backend."""

    def render(
        self,
        bundle: Mapping[str, Any],
        plan: ReplayPlan,
        *,
        source_receipt: Mapping[str, Any],
        require_bundle_signature: bool = True,
        require_source_signature: bool = True,
    ) -> DryRunReport:
        """Return a no-side-effect report for a verified bundle and authentic plan."""

        if not plan.valid:
            raise ReplayBundleError("replay plan content address is invalid")
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
        if bundle.get("bundle_id") != plan.bundle_id:
            raise ReplayBundleError("replay plan references a different bundle")
        source = _mapping(bundle, "source")
        if source.get("receipt_id") != plan.source_receipt_id:
            raise ReplayBundleError("replay plan references a different source receipt")
        recipe = _mapping(bundle, "recipe")
        actions = _list_of_mappings(recipe, "actions")
        steps = tuple(
            {
                "sequence": index,
                "action_id": _text(action, "action_id"),
                "tool_id": _text(action, "tool_id"),
                "effect": _text(action, "effect"),
                "input_digest": dict(_mapping(action, "input_digest")),
                "action_digest": dict(_mapping(action, "action_digest")),
                "operation": "DESCRIBE_ONLY",
            }
            for index, action in enumerate(actions, start=1)
        )
        if plan.decision is ReplayDecision.BLOCK:
            status = "BLOCKED"
        elif plan.execution_permitted:
            status = "READY_FOR_ISOLATED_EXECUTOR"
        else:
            status = "POLICY_LIMITED"
        material: dict[str, Any] = {
            "plan_id": plan.plan_id,
            "bundle_id": plan.bundle_id,
            "source_receipt_id": plan.source_receipt_id,
            "status": status,
            "decision": plan.decision.value,
            "steps": list(steps),
            "external_calls": 0,
            "history_mutations": 0,
            "would_invoke_actions": False,
        }
        return DryRunReport(
            report_id=_report_id(material),
            plan_id=plan.plan_id,
            bundle_id=plan.bundle_id,
            source_receipt_id=plan.source_receipt_id,
            status=status,
            decision=plan.decision,
            steps=steps,
        )


def _report_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_REPORT_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:replay-dry-run:sha256:{digest}"


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


__all__ = ["DryRunExecutor", "DryRunReport"]
