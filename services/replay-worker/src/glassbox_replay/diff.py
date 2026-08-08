"""Privacy-preserving structural and exact-semantic replay output diffs."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from glassbox.redaction import RedactionPolicy, digest_value
from glassbox_dbom import verify_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_policy import (
    SemanticAssessment,
    SemanticPolicyError,
    SemanticPolicyRegistry,
    assess_exact_semantics,
    assess_with_semantic_policy,
)
from glassbox_replay.execution import ReplayExecutionError

_DIFF_DOMAIN = b"glassbox.replay.diff.v1\0"
_VALUE_DOMAIN = b"glassbox.replay.diff.value.v1\0"


@dataclass(frozen=True)
class StructuralChange:
    """One changed JSON location represented only by type and digest commitments."""

    path: str
    kind: str
    before_type: str | None
    after_type: str | None
    before_digest: str | None
    after_digest: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "kind": self.kind,
            "before_type": self.before_type,
            "after_type": self.after_type,
            "before_digest": _optional_digest(self.before_digest),
            "after_digest": _optional_digest(self.after_digest),
        }


@dataclass(frozen=True)
class ReplayDiff:
    """Content-addressed diff containing no raw output values."""

    diff_id: str
    source_receipt_id: str
    replay_receipt_id: str
    source_output_digest: str
    replay_output_digest: str
    structural_changes: tuple[StructuralChange, ...]
    semantic: SemanticAssessment

    @property
    def valid(self) -> bool:
        structural_paths = {item.path for item in self.structural_changes}
        matched_paths = {
            path
            for evaluation in self.semantic.evaluations
            if evaluation.passed
            for path in evaluation.covered_change_paths
        }
        return (
            self.semantic.valid
            and self.semantic.structural_change_count == len(self.structural_changes)
            and matched_paths.issubset(structural_paths)
            and self.semantic.matched_change_count == len(matched_paths)
            and self.diff_id == _diff_id(self._material())
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "diff_id": self.diff_id,
            "source_receipt_id": self.source_receipt_id,
            "replay_receipt_id": self.replay_receipt_id,
            "source_output_digest": _digest_object(self.source_output_digest),
            "replay_output_digest": _digest_object(self.replay_output_digest),
            "structural_changes": [item.to_dict() for item in self.structural_changes],
            "semantic": self.semantic.to_dict(),
            "raw_values_retained": False,
        }

    def _material(self) -> dict[str, Any]:
        value = self.to_dict()
        value.pop("diff_id")
        return value


def build_replay_diff(
    source_receipt: Mapping[str, Any],
    replay_receipt: Mapping[str, Any],
    *,
    source_output: object,
    replay_output: object,
    require_signatures: bool = True,
    semantic_policy_id: str | None = None,
    semantic_registry: SemanticPolicyRegistry | None = None,
) -> ReplayDiff:
    """Verify both DBOMs and compare supplied outputs against their commitments."""

    for label, receipt in (("source", source_receipt), ("replay", replay_receipt)):
        report = verify_receipt(receipt, require_signature=require_signatures)
        if not report.valid:
            raise ReplayExecutionError(f"{label} receipt verification failed")
    source_id = _text(source_receipt, "receipt_id")
    replay_id = _text(replay_receipt, "receipt_id")
    if source_id == replay_id:
        raise ReplayExecutionError("replay diff requires two distinct receipts")
    source_digest = _output_digest(source_receipt)
    replay_digest = _output_digest(replay_receipt)
    if digest_value(source_output) != source_digest:
        raise ReplayExecutionError("source output does not match its receipt digest")
    if digest_value(replay_output) != replay_digest:
        raise ReplayExecutionError("replay output does not match its receipt digest")
    prior = _mapping(_mapping(replay_receipt, "replay"), "prior_receipt_digest")
    source_payload = _output_value(_mapping(source_receipt, "integrity"), "payload_digest")
    if _output_value(prior, None) != source_payload:
        raise ReplayExecutionError("replay receipt is not linked to the source payload digest")

    policy = RedactionPolicy()
    before = policy.normalize_for_digest(source_output)
    after = policy.normalize_for_digest(replay_output)
    changes: list[StructuralChange] = []
    _compare(before, after, "", changes)
    ordered = tuple(sorted(changes, key=lambda item: (item.path, item.kind)))
    identical = source_digest == replay_digest
    if (semantic_policy_id is None) != (semantic_registry is None):
        raise ReplayExecutionError(
            "semantic policy ID and trusted registry must be supplied together"
        )
    if semantic_policy_id is None:
        semantic = assess_exact_semantics(
            identical=identical,
            structural_change_count=len(ordered),
        )
    else:
        source_kind = _text(_mapping(source_receipt, "output"), "kind")
        replay_kind = _text(_mapping(replay_receipt, "output"), "kind")
        if source_kind != replay_kind:
            raise ReplayExecutionError("semantic policy requires matching receipt output kinds")
        try:
            semantic_policy = semantic_registry.resolve(  # type: ignore[union-attr]
                semantic_policy_id,
                output_kind=source_kind,
            )
            semantic = assess_with_semantic_policy(
                semantic_policy,
                before=before,
                after=after,
                structural_change_paths=tuple(item.path for item in ordered),
            )
        except SemanticPolicyError as exc:
            raise ReplayExecutionError("semantic policy evaluation failed") from exc
    material: dict[str, Any] = {
        "source_receipt_id": source_id,
        "replay_receipt_id": replay_id,
        "source_output_digest": _digest_object(source_digest),
        "replay_output_digest": _digest_object(replay_digest),
        "structural_changes": [item.to_dict() for item in ordered],
        "semantic": semantic.to_dict(),
        "raw_values_retained": False,
    }
    return ReplayDiff(
        diff_id=_diff_id(material),
        source_receipt_id=source_id,
        replay_receipt_id=replay_id,
        source_output_digest=source_digest,
        replay_output_digest=replay_digest,
        structural_changes=ordered,
        semantic=semantic,
    )


def _compare(before: Any, after: Any, path: str, changes: list[StructuralChange]) -> None:
    before_type = _type_name(before)
    after_type = _type_name(after)
    if before_type != after_type:
        changes.append(_change(path, "TYPE_CHANGED", before, after))
        return
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            child = f"{path}/{_pointer(key)}"
            if key not in before:
                changes.append(_change(child, "ADDED", None, after[key], before_missing=True))
            elif key not in after:
                changes.append(_change(child, "REMOVED", before[key], None, after_missing=True))
            else:
                _compare(before[key], after[key], child, changes)
        return
    if isinstance(before, list) and isinstance(after, list):
        for index in range(max(len(before), len(after))):
            child = f"{path}/{index}"
            if index >= len(before):
                changes.append(_change(child, "ADDED", None, after[index], before_missing=True))
            elif index >= len(after):
                changes.append(_change(child, "REMOVED", before[index], None, after_missing=True))
            else:
                _compare(before[index], after[index], child, changes)
        return
    if before != after:
        changes.append(_change(path or "/", "VALUE_CHANGED", before, after))


def _change(
    path: str,
    kind: str,
    before: Any,
    after: Any,
    *,
    before_missing: bool = False,
    after_missing: bool = False,
) -> StructuralChange:
    return StructuralChange(
        path=path or "/",
        kind=kind,
        before_type=None if before_missing else _type_name(before),
        after_type=None if after_missing else _type_name(after),
        before_digest=None if before_missing else _value_digest(before),
        after_digest=None if after_missing else _value_digest(after),
    )


def _type_name(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "opaque"


def _value_digest(value: object) -> str:
    return hashlib.sha256(_VALUE_DOMAIN + canonicalize(value)).hexdigest()


def _pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _output_digest(receipt: Mapping[str, Any]) -> str:
    return _output_value(_mapping(receipt, "output"), "digest")


def _output_value(value: Mapping[str, Any], key: str | None) -> str:
    selected: object = value if key is None else value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayExecutionError("digest must be an object")
    digest = selected.get("value")
    if not isinstance(digest, str):
        raise ReplayExecutionError("digest value must be a string")
    return digest


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


def _digest_object(value: str) -> dict[str, str]:
    return {"algorithm": "sha256", "value": value}


def _optional_digest(value: str | None) -> dict[str, str] | None:
    return _digest_object(value) if value is not None else None


def _diff_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_DIFF_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:replay-diff:sha256:{digest}"


__all__ = [
    "ReplayDiff",
    "SemanticAssessment",
    "StructuralChange",
    "build_replay_diff",
]
