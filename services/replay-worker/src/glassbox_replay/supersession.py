"""Content-addressed, history-preserving replay supersession records."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from glassbox_dbom import verify_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_policy import SemanticResult
from glassbox_replay.diff import ReplayDiff
from glassbox_replay.execution import ReadOnlyReplayExecution, ReplayExecutionError
from glassbox_replay.planner import ReplayPlan

SUPERSESSION_POLICY_VERSION = "glassbox.replay-supersession.v1"
_SUPERSESSION_DOMAIN = b"glassbox.replay.supersession.v1\0"


@dataclass(frozen=True)
class SupersessionRecord:
    """Immutable link among the source, replay, execution, and diff artifacts."""

    supersession_id: str
    source_receipt_id: str
    replay_receipt_id: str
    bundle_id: str
    plan_id: str
    execution_id: str
    diff_id: str
    semantic_method: str
    semantic_policy_id: str
    semantic_rule_id: str
    semantic_rule_version: str
    semantic_result: str
    semantic_exact_match: bool
    structural_change_count: int
    created_at: str
    policy_version: str = SUPERSESSION_POLICY_VERSION
    relation: str = "SUPERSEDES"

    @property
    def valid(self) -> bool:
        return (
            self.semantic_method == "DETERMINISTIC"
            and self.semantic_policy_id.startswith("gbx:semantic-policy:sha256:")
            and bool(self.semantic_rule_id)
            and bool(self.semantic_rule_version)
            and self.semantic_result in {item.value for item in SemanticResult}
            and self.supersession_id == _supersession_id(self._material())
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "supersession_id": self.supersession_id,
            "source_receipt_id": self.source_receipt_id,
            "replay_receipt_id": self.replay_receipt_id,
            "bundle_id": self.bundle_id,
            "plan_id": self.plan_id,
            "execution_id": self.execution_id,
            "diff_id": self.diff_id,
            "semantic_method": self.semantic_method,
            "semantic_policy_id": self.semantic_policy_id,
            "semantic_rule_id": self.semantic_rule_id,
            "semantic_rule_version": self.semantic_rule_version,
            "semantic_result": self.semantic_result,
            "semantic_exact_match": self.semantic_exact_match,
            "structural_change_count": self.structural_change_count,
            "created_at": self.created_at,
            "policy_version": self.policy_version,
            "relation": self.relation,
        }

    def _material(self) -> dict[str, Any]:
        value = self.to_dict()
        value.pop("supersession_id")
        return value


def create_supersession_record(
    source_receipt: Mapping[str, Any],
    replay_receipt: Mapping[str, Any],
    *,
    execution: ReadOnlyReplayExecution,
    plan: ReplayPlan,
    diff: ReplayDiff,
    created_at: str,
    require_signatures: bool = True,
) -> SupersessionRecord:
    """Create an exact link only after every upstream artifact verifies."""

    _timestamp(created_at)
    for label, receipt in (("source", source_receipt), ("replay", replay_receipt)):
        report = verify_receipt(receipt, require_signature=require_signatures)
        if not report.valid:
            raise ReplayExecutionError(f"{label} receipt verification failed")
    if not execution.valid or execution.status != "SUCCEEDED":
        raise ReplayExecutionError("only a valid successful execution can supersede history")
    if not plan.valid or plan.plan_id != execution.plan_id:
        raise ReplayExecutionError("supersession plan binding is invalid")
    if not diff.valid:
        raise ReplayExecutionError("replay diff content address is invalid")

    source_id = _text(source_receipt, "receipt_id")
    replay_id = _text(replay_receipt, "receipt_id")
    if execution.source_receipt_id != source_id:
        raise ReplayExecutionError("execution source receipt binding is invalid")
    if diff.source_receipt_id != source_id or diff.replay_receipt_id != replay_id:
        raise ReplayExecutionError("diff receipt binding is invalid")
    if execution.output_digest != diff.replay_output_digest:
        raise ReplayExecutionError("execution output is not the diff replay output")
    replay_extensions = _mapping(replay_receipt, "extensions")
    expected_extensions = {
        "glassbox.replay.bundle_id": execution.bundle_id,
        "glassbox.replay.plan_id": execution.plan_id,
        "glassbox.replay.execution_id": execution.execution_id,
        "glassbox.replay.source_receipt_id": source_id,
    }
    if any(replay_extensions.get(key) != value for key, value in expected_extensions.items()):
        raise ReplayExecutionError("replay receipt extensions do not bind execution artifacts")

    material: dict[str, Any] = {
        "source_receipt_id": source_id,
        "replay_receipt_id": replay_id,
        "bundle_id": execution.bundle_id,
        "plan_id": execution.plan_id,
        "execution_id": execution.execution_id,
        "diff_id": diff.diff_id,
        "semantic_method": diff.semantic.method,
        "semantic_policy_id": diff.semantic.policy_id,
        "semantic_rule_id": diff.semantic.rule_id,
        "semantic_rule_version": diff.semantic.rule_version,
        "semantic_result": diff.semantic.result,
        "semantic_exact_match": diff.semantic.exact_match,
        "structural_change_count": len(diff.structural_changes),
        "created_at": created_at,
        "policy_version": SUPERSESSION_POLICY_VERSION,
        "relation": "SUPERSEDES",
    }
    return SupersessionRecord(
        supersession_id=_supersession_id(material),
        source_receipt_id=source_id,
        replay_receipt_id=replay_id,
        bundle_id=execution.bundle_id,
        plan_id=execution.plan_id,
        execution_id=execution.execution_id,
        diff_id=diff.diff_id,
        semantic_method=diff.semantic.method,
        semantic_policy_id=diff.semantic.policy_id,
        semantic_rule_id=diff.semantic.rule_id,
        semantic_rule_version=diff.semantic.rule_version,
        semantic_result=diff.semantic.result,
        semantic_exact_match=diff.semantic.exact_match,
        structural_change_count=len(diff.structural_changes),
        created_at=created_at,
    )


def _supersession_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_SUPERSESSION_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:replay-supersession:sha256:{digest}"


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayExecutionError(f"{key} must be an object")
    return selected


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayExecutionError(f"{key} must be a non-empty string")
    return selected


def _timestamp(value: str) -> None:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplayExecutionError("created_at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplayExecutionError("created_at must include a timezone")


__all__ = [
    "SUPERSESSION_POLICY_VERSION",
    "SupersessionRecord",
    "create_supersession_record",
]
