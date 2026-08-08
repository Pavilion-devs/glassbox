"""Content-addressed deterministic semantic comparison policies."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from glassbox_dbom.canonical import canonicalize

SEMANTIC_POLICY_SPEC_VERSION = "0.1.0"
SEMANTIC_POLICY_CONTRACT = "glassbox.semantic-policy.v1"
EXACT_SEMANTIC_POLICY_NAME = "glassbox.exact-output-equivalence"
EXACT_SEMANTIC_POLICY_VERSION = "1.0.0"

_POLICY_DOMAIN = b"glassbox.semantic.policy.v1\0"
_SCHEMA_RELATIVE_PATH = (
    Path("schemas") / "semantic-policy" / SEMANTIC_POLICY_SPEC_VERSION / "schema.json"
)
_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_VERSION_PATTERN = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
_DECIMAL_PATTERN = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]+)?$")
_MISSING = object()
_RULE_REASON_CODES = frozenset(
    {
        "NON_FINITE_NUMBER",
        "NUMERIC_TOLERANCE_EXCEEDED",
        "NUMERIC_TOLERANCE_MATCH",
        "RULE_PATH_MISSING",
        "RULE_TYPE_MISMATCH",
        "UNORDERED_COLLECTION_CHANGED",
        "UNORDERED_COLLECTION_MATCH",
    }
)
_ASSESSMENT_REASON_CODES = frozenset(
    {
        "ALL_CHANGES_PROVEN_EQUIVALENT",
        "EXACT_OUTPUT_DIGEST_MATCH",
        "OUTPUT_DIGEST_CHANGED",
        "SEMANTIC_RULE_FAILED",
        "UNMATCHED_STRUCTURAL_CHANGE",
    }
)


class SemanticPolicyError(ValueError):
    """Raised when a semantic policy cannot support a deterministic decision."""


class SemanticRuleKind(StrEnum):
    """Closed deterministic comparison primitives supported by policy v1."""

    NUMERIC_TOLERANCE = "NUMERIC_TOLERANCE"
    UNORDERED_COLLECTION = "UNORDERED_COLLECTION"


class SemanticResult(StrEnum):
    """Deterministic relationship between the source and replay outputs."""

    EQUIVALENT = "EQUIVALENT"
    CHANGED = "CHANGED"


@dataclass(frozen=True)
class SemanticRule:
    """One closed comparison rule over an exact JSON Pointer."""

    rule_id: str
    kind: SemanticRuleKind
    path: str
    absolute_tolerance: str | None = None
    relative_tolerance: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "kind": self.kind.value,
            "path": self.path,
            "absolute_tolerance": self.absolute_tolerance,
            "relative_tolerance": self.relative_tolerance,
        }


@dataclass(frozen=True)
class SemanticRulePack:
    """Versioned content-addressed domain policy containing no executable code."""

    policy_id: str
    name: str
    version: str
    output_kind: str
    rules: tuple[SemanticRule, ...]
    contract: str = SEMANTIC_POLICY_CONTRACT
    spec_version: str = SEMANTIC_POLICY_SPEC_VERSION

    @classmethod
    def create(
        cls,
        *,
        name: str,
        version: str,
        output_kind: str,
        rules: Iterable[SemanticRule],
    ) -> SemanticRulePack:
        ordered = tuple(sorted(rules, key=lambda item: (item.path, item.rule_id)))
        _validate_pack_fields(name, version, output_kind, ordered)
        material = _policy_material(name, version, output_kind, ordered)
        return cls(
            policy_id=_policy_id(material),
            name=name,
            version=version,
            output_kind=output_kind,
            rules=ordered,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SemanticRulePack:
        validate_semantic_policy_document(value)
        rules_value = value.get("rules")
        if not isinstance(rules_value, list):  # pragma: no cover - schema closes this branch
            raise SemanticPolicyError("semantic policy rules must be an array")
        try:
            rules = tuple(
                SemanticRule(
                    rule_id=_required_text(item, "rule_id"),
                    kind=SemanticRuleKind(_required_text(item, "kind")),
                    path=_required_string(item, "path"),
                    absolute_tolerance=_optional_text(item, "absolute_tolerance"),
                    relative_tolerance=_optional_text(item, "relative_tolerance"),
                )
                for item in rules_value
                if isinstance(item, Mapping)
            )
        except ValueError as exc:
            raise SemanticPolicyError("semantic policy rule kind is invalid") from exc
        result = cls(
            policy_id=_required_text(value, "policy_id"),
            name=_required_text(value, "name"),
            version=_required_text(value, "version"),
            output_kind=_required_text(value, "output_kind"),
            rules=rules,
            contract=_required_text(value, "contract"),
            spec_version=_required_text(value, "spec_version"),
        )
        if not result.valid:
            raise SemanticPolicyError("semantic policy content address is invalid")
        return result

    @property
    def valid(self) -> bool:
        try:
            _validate_pack_fields(self.name, self.version, self.output_kind, self.rules)
        except SemanticPolicyError:
            return False
        return (
            self.contract == SEMANTIC_POLICY_CONTRACT
            and self.spec_version == SEMANTIC_POLICY_SPEC_VERSION
            and self.policy_id
            == _policy_id(_policy_material(self.name, self.version, self.output_kind, self.rules))
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "spec_version": self.spec_version,
            "policy_id": self.policy_id,
            "name": self.name,
            "version": self.version,
            "output_kind": self.output_kind,
            "rules": [item.to_dict() for item in self.rules],
            "raw_content_returned": False,
        }


@dataclass(frozen=True)
class SemanticRuleEvaluation:
    """Raw-free proof describing how one declared rule evaluated."""

    rule_id: str
    kind: str
    path: str
    passed: bool
    reason_code: str
    covered_change_paths: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return (
            self.kind in {item.value for item in SemanticRuleKind}
            and bool(self.rule_id)
            and isinstance(self.path, str)
            and self.reason_code in _RULE_REASON_CODES
            and tuple(sorted(set(self.covered_change_paths))) == self.covered_change_paths
            and all(isinstance(item, str) and item for item in self.covered_change_paths)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "kind": self.kind,
            "path": self.path,
            "passed": self.passed,
            "reason_code": self.reason_code,
            "covered_change_paths": list(self.covered_change_paths),
            "raw_content_returned": False,
        }


@dataclass(frozen=True)
class SemanticAssessment:
    """Content-bound deterministic assessment with complete change coverage."""

    method: str
    policy_id: str
    rule_id: str
    rule_version: str
    result: str
    score: float
    exact_match: bool
    structural_change_count: int
    matched_change_count: int
    reason_codes: tuple[str, ...]
    evaluations: tuple[SemanticRuleEvaluation, ...]

    @property
    def valid(self) -> bool:
        return (
            self.method == "DETERMINISTIC"
            and self.result in {item.value for item in SemanticResult}
            and self.score in {0.0, 1.0}
            and self.structural_change_count >= 0
            and 0 <= self.matched_change_count <= self.structural_change_count
            and bool(self.policy_id)
            and bool(self.rule_id)
            and bool(self.rule_version)
            and bool(self.reason_codes)
            and set(self.reason_codes).issubset(_ASSESSMENT_REASON_CODES)
            and tuple(dict.fromkeys(self.reason_codes)) == self.reason_codes
            and all(item.valid for item in self.evaluations)
            and len({item.rule_id for item in self.evaluations}) == len(self.evaluations)
            and (self.result == SemanticResult.EQUIVALENT.value) == (self.score == 1.0)
            and (not self.exact_match or self.structural_change_count == 0)
            and (not self.exact_match or not self.evaluations)
            and (
                self.result != SemanticResult.EQUIVALENT.value
                or self.exact_match
                or (
                    self.matched_change_count == self.structural_change_count
                    and all(item.passed for item in self.evaluations)
                )
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "policy_id": self.policy_id,
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "result": self.result,
            "score": self.score,
            "exact_match": self.exact_match,
            "structural_change_count": self.structural_change_count,
            "matched_change_count": self.matched_change_count,
            "reason_codes": list(self.reason_codes),
            "evaluations": [item.to_dict() for item in self.evaluations],
            "raw_content_returned": False,
        }


@dataclass(frozen=True)
class SemanticPolicyRegistry:
    """Operator-selected allowlist that separates policy integrity from authority."""

    policies: tuple[SemanticRulePack, ...]
    trusted_policy_ids: frozenset[str]

    def __post_init__(self) -> None:
        if not self.policies:
            raise SemanticPolicyError("semantic policy registry must contain a policy")
        ids = [item.policy_id for item in self.policies]
        identities = [(item.name, item.version) for item in self.policies]
        if any(not item.valid for item in self.policies):
            raise SemanticPolicyError("semantic policy registry contains an invalid policy")
        if len(set(ids)) != len(ids) or len(set(identities)) != len(identities):
            raise SemanticPolicyError("semantic policy registry contains duplicate identities")
        if set(ids) != set(self.trusted_policy_ids):
            raise SemanticPolicyError(
                "semantic policy registry trust set must match loaded policies"
            )

    @classmethod
    def trust(cls, policies: Iterable[SemanticRulePack]) -> SemanticPolicyRegistry:
        selected = tuple(sorted(policies, key=lambda item: item.policy_id))
        return cls(selected, frozenset(item.policy_id for item in selected))

    def resolve(self, policy_id: str, *, output_kind: str) -> SemanticRulePack:
        matches = [item for item in self.policies if item.policy_id == policy_id]
        if len(matches) != 1:
            raise SemanticPolicyError("semantic policy is not trusted by this registry")
        policy = matches[0]
        if policy.output_kind != output_kind:
            raise SemanticPolicyError("semantic policy output kind does not match the receipts")
        return policy


def assess_exact_semantics(*, identical: bool, structural_change_count: int) -> SemanticAssessment:
    """Return the deterministic default when no domain policy is explicitly selected."""

    result = SemanticResult.EQUIVALENT if identical else SemanticResult.CHANGED
    return SemanticAssessment(
        method="DETERMINISTIC",
        policy_id=EXACT_SEMANTIC_POLICY_ID,
        rule_id=EXACT_SEMANTIC_POLICY_NAME,
        rule_version=EXACT_SEMANTIC_POLICY_VERSION,
        result=result.value,
        score=1.0 if identical else 0.0,
        exact_match=identical,
        structural_change_count=structural_change_count,
        matched_change_count=structural_change_count if identical else 0,
        reason_codes=("EXACT_OUTPUT_DIGEST_MATCH" if identical else "OUTPUT_DIGEST_CHANGED",),
        evaluations=(),
    )


def assess_with_semantic_policy(
    policy: SemanticRulePack,
    *,
    before: Any,
    after: Any,
    structural_change_paths: Sequence[str],
) -> SemanticAssessment:
    """Apply every rule and require positive coverage for every structural change."""

    if not policy.valid:
        raise SemanticPolicyError("cannot evaluate an invalid semantic policy")
    changes = tuple(sorted(set(structural_change_paths)))
    if canonicalize(before) == canonicalize(after):
        return SemanticAssessment(
            method="DETERMINISTIC",
            policy_id=policy.policy_id,
            rule_id=policy.name,
            rule_version=policy.version,
            result=SemanticResult.EQUIVALENT.value,
            score=1.0,
            exact_match=True,
            structural_change_count=0,
            matched_change_count=0,
            reason_codes=("EXACT_OUTPUT_DIGEST_MATCH",),
            evaluations=(),
        )

    evaluations: list[SemanticRuleEvaluation] = []
    passed_coverage: set[str] = set()
    for rule in policy.rules:
        covered = tuple(item for item in changes if _rule_covers(rule, item))
        passed, reason = _evaluate_rule(rule, before, after)
        if passed:
            passed_coverage.update(covered)
        evaluations.append(
            SemanticRuleEvaluation(
                rule_id=rule.rule_id,
                kind=rule.kind.value,
                path=rule.path,
                passed=passed,
                reason_code=reason,
                covered_change_paths=covered,
            )
        )

    unmatched = set(changes).difference(passed_coverage)
    all_rules_passed = all(item.passed for item in evaluations)
    equivalent = all_rules_passed and not unmatched and bool(changes)
    reasons: list[str] = []
    if not all_rules_passed:
        reasons.append("SEMANTIC_RULE_FAILED")
    if unmatched:
        reasons.append("UNMATCHED_STRUCTURAL_CHANGE")
    if equivalent:
        reasons.append("ALL_CHANGES_PROVEN_EQUIVALENT")
    return SemanticAssessment(
        method="DETERMINISTIC",
        policy_id=policy.policy_id,
        rule_id=policy.name,
        rule_version=policy.version,
        result=(SemanticResult.EQUIVALENT if equivalent else SemanticResult.CHANGED).value,
        score=1.0 if equivalent else 0.0,
        exact_match=False,
        structural_change_count=len(changes),
        matched_change_count=len(passed_coverage),
        reason_codes=tuple(reasons),
        evaluations=tuple(evaluations),
    )


def load_semantic_policy_schema(path: Path | None = None) -> dict[str, Any]:
    """Load the normative semantic-policy schema from source or an installed wheel."""

    if path is not None:
        return _read_schema(path)
    repository = (
        Path(__file__).resolve().parents[4]
        / "schemas"
        / "semantic-policy"
        / SEMANTIC_POLICY_SPEC_VERSION
        / "schema.json"
    )
    if repository.is_file():
        return _read_schema(repository)
    packaged = resources.files("glassbox_policy").joinpath(str(_SCHEMA_RELATIVE_PATH))
    with packaged.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise SemanticPolicyError("semantic-policy schema root must be an object")
    return loaded


def validate_semantic_policy_document(
    value: Mapping[str, Any],
    *,
    schema: Mapping[str, Any] | None = None,
) -> None:
    """Reject every schema drift before constructing a trusted policy object."""

    selected = dict(schema) if schema is not None else load_semantic_policy_schema()
    failures = sorted(
        Draft202012Validator(selected).iter_errors(value), key=lambda item: list(item.path)
    )
    if failures:
        messages = []
        for failure in failures:
            location = "/" + "/".join(str(part) for part in failure.absolute_path)
            messages.append(f"{location}: {failure.message}")
        raise SemanticPolicyError("; ".join(messages))


def _evaluate_rule(rule: SemanticRule, before: Any, after: Any) -> tuple[bool, str]:
    left = _resolve_pointer(before, rule.path)
    right = _resolve_pointer(after, rule.path)
    if left is _MISSING or right is _MISSING:
        return False, "RULE_PATH_MISSING"
    if rule.kind is SemanticRuleKind.NUMERIC_TOLERANCE:
        return _numeric_tolerance(rule, left, right)
    if rule.kind is SemanticRuleKind.UNORDERED_COLLECTION:
        if not isinstance(left, list) or not isinstance(right, list):
            return False, "RULE_TYPE_MISMATCH"
        left_counts = Counter(hashlib.sha256(canonicalize(item)).hexdigest() for item in left)
        right_counts = Counter(hashlib.sha256(canonicalize(item)).hexdigest() for item in right)
        return (
            (True, "UNORDERED_COLLECTION_MATCH")
            if left_counts == right_counts
            else (False, "UNORDERED_COLLECTION_CHANGED")
        )
    raise SemanticPolicyError("unsupported semantic rule kind")  # pragma: no cover


def _numeric_tolerance(rule: SemanticRule, before: Any, after: Any) -> tuple[bool, str]:
    if (
        not isinstance(before, int | float)
        or isinstance(before, bool)
        or not isinstance(after, int | float)
        or isinstance(after, bool)
    ):
        return False, "RULE_TYPE_MISMATCH"
    left = Decimal(str(before))
    right = Decimal(str(after))
    if not left.is_finite() or not right.is_finite():
        return False, "NON_FINITE_NUMBER"
    delta = abs(left - right)
    passed = False
    if rule.absolute_tolerance is not None:
        passed = delta <= Decimal(rule.absolute_tolerance)
    if rule.relative_tolerance is not None:
        relative_limit = Decimal(rule.relative_tolerance) * max(abs(left), abs(right))
        passed = passed or delta <= relative_limit
    return (True, "NUMERIC_TOLERANCE_MATCH") if passed else (False, "NUMERIC_TOLERANCE_EXCEEDED")


def _rule_covers(rule: SemanticRule, change_path: str) -> bool:
    if rule.kind is SemanticRuleKind.NUMERIC_TOLERANCE:
        return change_path == (rule.path or "/")
    if not rule.path:
        return True
    return change_path == rule.path or change_path.startswith(rule.path + "/")


def _resolve_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    current = value
    for encoded in pointer.removeprefix("/").split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if token not in current:
                return _MISSING
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit():
                return _MISSING
            index = int(token)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _validate_pack_fields(
    name: str,
    version: str,
    output_kind: str,
    rules: tuple[SemanticRule, ...],
) -> None:
    if not _NAME_PATTERN.fullmatch(name):
        raise SemanticPolicyError("semantic policy name is invalid")
    if not _VERSION_PATTERN.fullmatch(version):
        raise SemanticPolicyError("semantic policy version must be semantic version x.y.z")
    if not output_kind or len(output_kind) > 128:
        raise SemanticPolicyError("semantic policy output kind is invalid")
    if not rules:
        raise SemanticPolicyError("domain semantic policy must contain at least one rule")
    if tuple(sorted(rules, key=lambda item: (item.path, item.rule_id))) != rules:
        raise SemanticPolicyError("semantic policy rules must be canonically ordered")
    if len({item.rule_id for item in rules}) != len(rules):
        raise SemanticPolicyError("semantic policy rule IDs must be unique")
    for index, rule in enumerate(rules):
        _validate_rule(rule)
        for other in rules[index + 1 :]:
            if _paths_overlap(rule.path, other.path):
                raise SemanticPolicyError("semantic policy rule paths must not overlap")


def _validate_rule(rule: SemanticRule) -> None:
    if not _NAME_PATTERN.fullmatch(rule.rule_id):
        raise SemanticPolicyError("semantic rule ID is invalid")
    _validate_pointer(rule.path)
    if rule.kind is SemanticRuleKind.NUMERIC_TOLERANCE:
        if rule.absolute_tolerance is None and rule.relative_tolerance is None:
            raise SemanticPolicyError("numeric tolerance requires an absolute or relative bound")
        for label, value in (
            ("absolute", rule.absolute_tolerance),
            ("relative", rule.relative_tolerance),
        ):
            if value is None:
                continue
            if not _DECIMAL_PATTERN.fullmatch(value):
                raise SemanticPolicyError(f"{label} tolerance must be a non-negative decimal")
            try:
                parsed = Decimal(value)
            except InvalidOperation as exc:  # pragma: no cover - regex closes this branch
                raise SemanticPolicyError(f"{label} tolerance is invalid") from exc
            if not parsed.is_finite():
                raise SemanticPolicyError(f"{label} tolerance must be finite")
    elif rule.absolute_tolerance is not None or rule.relative_tolerance is not None:
        raise SemanticPolicyError("unordered collection rule cannot declare tolerances")


def _validate_pointer(path: str) -> None:
    if path and not path.startswith("/"):
        raise SemanticPolicyError("semantic rule path must be a JSON Pointer")
    index = 0
    while index < len(path):
        if path[index] == "~" and (index + 1 >= len(path) or path[index + 1] not in "01"):
            raise SemanticPolicyError("semantic rule path contains an invalid escape")
        index += 1


def _paths_overlap(left: str, right: str) -> bool:
    if left == right or not left or not right:
        return True
    return left.startswith(right + "/") or right.startswith(left + "/")


def _policy_material(
    name: str,
    version: str,
    output_kind: str,
    rules: tuple[SemanticRule, ...],
) -> dict[str, Any]:
    return {
        "contract": SEMANTIC_POLICY_CONTRACT,
        "spec_version": SEMANTIC_POLICY_SPEC_VERSION,
        "name": name,
        "version": version,
        "output_kind": output_kind,
        "rules": [item.to_dict() for item in rules],
    }


def _policy_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_POLICY_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:semantic-policy:sha256:{digest}"


def _read_schema(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise SemanticPolicyError("semantic-policy schema root must be an object")
    return loaded


def _required_text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise SemanticPolicyError(f"{key} must be a non-empty string")
    return selected


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str):
        raise SemanticPolicyError(f"{key} must be a string")
    return selected


def _optional_text(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is None:
        return None
    if not isinstance(selected, str):
        raise SemanticPolicyError(f"{key} must be a string or null")
    return selected


_EXACT_POLICY_MATERIAL = {
    "contract": SEMANTIC_POLICY_CONTRACT,
    "spec_version": SEMANTIC_POLICY_SPEC_VERSION,
    "name": EXACT_SEMANTIC_POLICY_NAME,
    "version": EXACT_SEMANTIC_POLICY_VERSION,
    "output_kind": "*",
    "rules": [],
}
EXACT_SEMANTIC_POLICY_ID = _policy_id(_EXACT_POLICY_MATERIAL)


__all__ = [
    "EXACT_SEMANTIC_POLICY_ID",
    "EXACT_SEMANTIC_POLICY_NAME",
    "EXACT_SEMANTIC_POLICY_VERSION",
    "SEMANTIC_POLICY_CONTRACT",
    "SEMANTIC_POLICY_SPEC_VERSION",
    "SemanticAssessment",
    "SemanticPolicyError",
    "SemanticPolicyRegistry",
    "SemanticResult",
    "SemanticRule",
    "SemanticRuleEvaluation",
    "SemanticRuleKind",
    "SemanticRulePack",
    "assess_exact_semantics",
    "assess_with_semantic_policy",
    "load_semantic_policy_schema",
    "validate_semantic_policy_document",
]
