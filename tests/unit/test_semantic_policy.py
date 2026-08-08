"""Deterministic domain-semantic policy and replay integration tests."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey
from glassbox_policy import (
    SemanticAssessment,
    SemanticPolicyError,
    SemanticPolicyRegistry,
    SemanticRule,
    SemanticRuleEvaluation,
    SemanticRuleKind,
    SemanticRulePack,
    assess_with_semantic_policy,
    pricing_recommendation_policy_v1,
)
from glassbox_replay import ReplayExecutionError, build_replay_diff, build_replay_receipt
from tests.unit.test_replay_execution import _bundle, _execute, _source

_FIXTURE = (
    Path(__file__).resolve().parents[2]
    / "examples"
    / "semantic-policies"
    / "pricing-recommendation-v1.json"
)


def _numeric_policy(*, output_kind: str = "pricing-recommendation") -> SemanticRulePack:
    return SemanticRulePack.create(
        name="example.numeric-recommendation",
        version="1.2.0",
        output_kind=output_kind,
        rules=(
            SemanticRule(
                rule_id="bounded-price-drift",
                kind=SemanticRuleKind.NUMERIC_TOLERANCE,
                path="/recommended_price",
                absolute_tolerance="0.50",
                relative_tolerance="0.005",
            ),
        ),
    )


def test_reference_policy_is_canonical_content_addressed_and_schema_round_trips() -> None:
    document = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    from_document = SemanticRulePack.from_dict(document)
    from_code = pricing_recommendation_policy_v1()

    assert from_document == from_code
    assert from_document.valid
    assert from_document.to_dict() == document
    assert from_document.policy_id.startswith("gbx:semantic-policy:sha256:")

    tampered = copy.deepcopy(document)
    tampered["rules"][0]["absolute_tolerance"] = "500"
    with pytest.raises(SemanticPolicyError, match="content address"):
        SemanticRulePack.from_dict(tampered)


def test_numeric_policy_requires_complete_positive_coverage_without_retaining_values() -> None:
    policy = _numeric_policy()
    equivalent = assess_with_semantic_policy(
        policy,
        before={"recommended_price": 100.0, "customer": "private-before"},
        after={"recommended_price": 100.4, "customer": "private-before"},
        structural_change_paths=("/recommended_price",),
    )
    exceeded = assess_with_semantic_policy(
        policy,
        before={"recommended_price": 100.0},
        after={"recommended_price": 101.0},
        structural_change_paths=("/recommended_price",),
    )
    unmatched = assess_with_semantic_policy(
        policy,
        before={"recommended_price": 100.0, "currency": "USD"},
        after={"recommended_price": 100.4, "currency": "EUR"},
        structural_change_paths=("/recommended_price", "/currency"),
    )

    assert equivalent.valid and equivalent.result == "EQUIVALENT"
    assert equivalent.exact_match is False
    assert equivalent.matched_change_count == equivalent.structural_change_count == 1
    assert equivalent.evaluations[0].reason_code == "NUMERIC_TOLERANCE_MATCH"
    assert exceeded.valid and exceeded.result == "CHANGED"
    assert exceeded.evaluations[0].reason_code == "NUMERIC_TOLERANCE_EXCEEDED"
    assert unmatched.valid and unmatched.result == "CHANGED"
    assert unmatched.matched_change_count == 1
    assert "UNMATCHED_STRUCTURAL_CHANGE" in unmatched.reason_codes
    encoded = json.dumps(equivalent.to_dict())
    assert "private-before" not in encoded
    assert "100.4" not in encoded
    assert equivalent.to_dict()["raw_content_returned"] is False


def test_unordered_collection_policy_is_multiset_safe_and_duplicate_sensitive() -> None:
    policy = SemanticRulePack.create(
        name="example.ranked-identifiers",
        version="1.0.0",
        output_kind="ranking",
        rules=(
            SemanticRule(
                rule_id="rank-order-is-nonmaterial",
                kind=SemanticRuleKind.UNORDERED_COLLECTION,
                path="/identifiers",
            ),
        ),
    )
    reordered = assess_with_semantic_policy(
        policy,
        before={"identifiers": ["a", "b", "a"]},
        after={"identifiers": ["a", "a", "b"]},
        structural_change_paths=("/identifiers/1", "/identifiers/2"),
    )
    changed = assess_with_semantic_policy(
        policy,
        before={"identifiers": ["a", "b", "a"]},
        after={"identifiers": ["a", "b", "b"]},
        structural_change_paths=("/identifiers/2",),
    )

    assert reordered.valid and reordered.result == "EQUIVALENT"
    assert reordered.matched_change_count == 2
    assert changed.valid and changed.result == "CHANGED"
    assert changed.evaluations[0].reason_code == "UNORDERED_COLLECTION_CHANGED"


def test_policy_construction_and_registry_fail_closed_on_ambiguity_or_drift() -> None:
    policy = _numeric_policy()
    registry = SemanticPolicyRegistry.trust((policy,))
    assert registry.resolve(policy.policy_id, output_kind=policy.output_kind) == policy

    with pytest.raises(SemanticPolicyError, match="trust set"):
        SemanticPolicyRegistry((policy,), frozenset())
    with pytest.raises(SemanticPolicyError, match="not trusted"):
        registry.resolve("gbx:semantic-policy:sha256:" + "0" * 64, output_kind=policy.output_kind)
    with pytest.raises(SemanticPolicyError, match="output kind"):
        registry.resolve(policy.policy_id, output_kind="different")
    with pytest.raises(SemanticPolicyError, match="must contain"):
        SemanticRulePack.create(
            name="example.empty-policy",
            version="1.0.0",
            output_kind="recommendation",
            rules=(),
        )
    with pytest.raises(SemanticPolicyError, match="must not overlap"):
        SemanticRulePack.create(
            name="example.overlapping-policy",
            version="1.0.0",
            output_kind="recommendation",
            rules=(
                SemanticRule(
                    "nested-number",
                    SemanticRuleKind.NUMERIC_TOLERANCE,
                    "/result/value",
                    absolute_tolerance="1",
                ),
                SemanticRule(
                    "unordered-result",
                    SemanticRuleKind.UNORDERED_COLLECTION,
                    "/result",
                ),
            ),
        )
    with pytest.raises(SemanticPolicyError, match="non-negative decimal"):
        SemanticRulePack.create(
            name="example.invalid-tolerance",
            version="1.0.0",
            output_kind="recommendation",
            rules=(
                SemanticRule(
                    "invalid-number",
                    SemanticRuleKind.NUMERIC_TOLERANCE,
                    "/value",
                    absolute_tolerance="-1",
                ),
            ),
        )


def test_registry_rejects_empty_invalid_and_duplicate_policy_sets() -> None:
    policy = _numeric_policy()
    invalid = replace(policy, policy_id="gbx:semantic-policy:sha256:" + "0" * 64)

    with pytest.raises(SemanticPolicyError, match="must contain"):
        SemanticPolicyRegistry.trust(())
    with pytest.raises(SemanticPolicyError, match="invalid policy"):
        SemanticPolicyRegistry((invalid,), frozenset((invalid.policy_id,)))
    with pytest.raises(SemanticPolicyError, match="duplicate identities"):
        SemanticPolicyRegistry((policy, policy), frozenset((policy.policy_id,)))


@pytest.mark.parametrize(
    "rule",
    (
        SemanticRule("no-bound", SemanticRuleKind.NUMERIC_TOLERANCE, "/value"),
        SemanticRule(
            "ordered-with-bound",
            SemanticRuleKind.UNORDERED_COLLECTION,
            "/items",
            absolute_tolerance="1",
        ),
        SemanticRule("bad-pointer", SemanticRuleKind.UNORDERED_COLLECTION, "items"),
        SemanticRule("bad-escape", SemanticRuleKind.UNORDERED_COLLECTION, "/items~2"),
    ),
)
def test_policy_rule_contract_rejects_unsafe_shapes(rule: SemanticRule) -> None:
    with pytest.raises(SemanticPolicyError):
        SemanticRulePack.create(
            name="example.unsafe-shape",
            version="1.0.0",
            output_kind="example-output",
            rules=(rule,),
        )


@pytest.mark.parametrize(
    ("name", "version", "output_kind"),
    (
        ("BAD NAME", "1.0.0", "output"),
        ("example.valid-name", "v1", "output"),
        ("example.valid-name", "1.0.0", ""),
    ),
)
def test_policy_identity_contract_rejects_invalid_fields(
    name: str,
    version: str,
    output_kind: str,
) -> None:
    with pytest.raises(SemanticPolicyError):
        SemanticRulePack.create(
            name=name,
            version=version,
            output_kind=output_kind,
            rules=(
                SemanticRule(
                    "valid-rule",
                    SemanticRuleKind.NUMERIC_TOLERANCE,
                    "/value",
                    absolute_tolerance="1",
                ),
            ),
        )


def test_policy_rejects_duplicate_rule_ids_even_on_distinct_paths() -> None:
    with pytest.raises(SemanticPolicyError, match="IDs must be unique"):
        SemanticRulePack.create(
            name="example.duplicate-rule-id",
            version="1.0.0",
            output_kind="output",
            rules=(
                SemanticRule(
                    "same-rule",
                    SemanticRuleKind.NUMERIC_TOLERANCE,
                    "/first",
                    absolute_tolerance="1",
                ),
                SemanticRule(
                    "same-rule",
                    SemanticRuleKind.NUMERIC_TOLERANCE,
                    "/second",
                    absolute_tolerance="1",
                ),
            ),
        )


def test_domain_assessment_handles_exact_root_escaped_and_invalid_pointer_cases() -> None:
    numeric = SemanticRulePack.create(
        name="example.escaped-pointer",
        version="1.0.0",
        output_kind="output",
        rules=(
            SemanticRule(
                "escaped-number",
                SemanticRuleKind.NUMERIC_TOLERANCE,
                "/a~1b/~0value",
                absolute_tolerance="1",
            ),
        ),
    )
    exact = assess_with_semantic_policy(
        numeric,
        before={"a/b": {"~value": 5}},
        after={"a/b": {"~value": 5}},
        structural_change_paths=(),
    )
    escaped = assess_with_semantic_policy(
        numeric,
        before={"a/b": {"~value": 5}},
        after={"a/b": {"~value": 6}},
        structural_change_paths=("/a~1b/~0value",),
    )
    wrong_type = assess_with_semantic_policy(
        numeric,
        before={"a/b": {"~value": True}},
        after={"a/b": {"~value": 1}},
        structural_change_paths=("/a~1b/~0value",),
    )
    missing = assess_with_semantic_policy(
        numeric,
        before={"a/b": {}},
        after={"a/b": {"~value": 1}},
        structural_change_paths=("/a~1b/~0value",),
    )

    root_multiset = SemanticRulePack.create(
        name="example.root-multiset",
        version="1.0.0",
        output_kind="output",
        rules=(SemanticRule("root-order", SemanticRuleKind.UNORDERED_COLLECTION, ""),),
    )
    root = assess_with_semantic_policy(
        root_multiset,
        before=[{"id": 1}, {"id": 2}],
        after=[{"id": 2}, {"id": 1}],
        structural_change_paths=("/0/id", "/1/id"),
    )
    root_type_mismatch = assess_with_semantic_policy(
        root_multiset,
        before={"id": 1},
        after={"id": 2},
        structural_change_paths=("/id",),
    )

    assert exact.valid and exact.exact_match
    assert escaped.valid and escaped.result == "EQUIVALENT"
    assert wrong_type.evaluations[0].reason_code == "RULE_TYPE_MISMATCH"
    assert missing.evaluations[0].reason_code == "RULE_PATH_MISSING"
    assert root.valid and root.result == "EQUIVALENT"
    assert root_type_mismatch.evaluations[0].reason_code == "RULE_TYPE_MISMATCH"


def test_array_pointer_resolution_fails_closed_for_invalid_or_unreachable_indexes() -> None:
    policies = tuple(
        SemanticRulePack.create(
            name=f"example.pointer-{index}",
            version="1.0.0",
            output_kind="output",
            rules=(
                SemanticRule(
                    f"pointer-{index}",
                    SemanticRuleKind.NUMERIC_TOLERANCE,
                    path,
                    absolute_tolerance="1",
                ),
            ),
        )
        for index, path in enumerate(("/items/not-index", "/items/9", "/items/0/value"))
    )

    for policy in policies:
        result = assess_with_semantic_policy(
            policy,
            before={"items": [1]},
            after={"items": [2]},
            structural_change_paths=(policy.rules[0].path,),
        )
        assert result.valid and result.result == "CHANGED"
        assert result.evaluations[0].reason_code == "RULE_PATH_MISSING"


def test_semantic_proof_validators_reject_malformed_persisted_evidence() -> None:
    evaluation = SemanticRuleEvaluation(
        rule_id="bounded-value",
        kind="NUMERIC_TOLERANCE",
        path="/value",
        passed=True,
        reason_code="NUMERIC_TOLERANCE_MATCH",
        covered_change_paths=("/value",),
    )
    assessment = SemanticAssessment(
        method="DETERMINISTIC",
        policy_id="gbx:semantic-policy:sha256:" + "1" * 64,
        rule_id="example.value",
        rule_version="1.0.0",
        result="EQUIVALENT",
        score=1.0,
        exact_match=False,
        structural_change_count=1,
        matched_change_count=1,
        reason_codes=("ALL_CHANGES_PROVEN_EQUIVALENT",),
        evaluations=(evaluation,),
    )
    assert evaluation.valid and assessment.valid

    invalid_evaluations = (
        replace(evaluation, kind="EXECUTABLE"),
        replace(evaluation, rule_id=""),
        replace(evaluation, reason_code="UNBOUNDED_REASON"),
        replace(evaluation, covered_change_paths=("/value", "/value")),
        replace(evaluation, covered_change_paths=("",)),
    )
    assert all(not item.valid for item in invalid_evaluations)

    malformed = (
        replace(assessment, method="MODEL"),
        replace(assessment, result="MAYBE"),
        replace(assessment, score=0.5),
        replace(assessment, structural_change_count=-1),
        replace(assessment, matched_change_count=2),
        replace(assessment, policy_id=""),
        replace(assessment, rule_id=""),
        replace(assessment, rule_version=""),
        replace(assessment, reason_codes=()),
        replace(assessment, reason_codes=("UNKNOWN",)),
        replace(
            assessment,
            reason_codes=("ALL_CHANGES_PROVEN_EQUIVALENT",) * 2,
        ),
        replace(assessment, evaluations=(invalid_evaluations[0],)),
        replace(assessment, evaluations=(evaluation, evaluation)),
        replace(assessment, score=0.0),
        replace(assessment, exact_match=True),
        replace(assessment, matched_change_count=0),
        replace(assessment, evaluations=(replace(evaluation, passed=False),)),
    )
    assert all(not item.valid for item in malformed)


def test_replay_diff_uses_only_an_exact_trusted_policy_and_binds_its_evidence() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source_output = {"recommended_price": 100.0, "currency": "USD"}
    replay_output = {"recommended_price": 100.4, "currency": "USD"}
    source = _source(action_input=action_input, source_output=source_output)
    bundle = _bundle(source, replay_input=replay_input)
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=lambda _input, _outputs: replay_output,
    )
    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("semantic-replay", Ed25519PrivateKey.generate()),),
    )
    policy = _numeric_policy(output_kind="recommendation")
    registry = SemanticPolicyRegistry.trust((policy,))
    diff = build_replay_diff(
        source,
        replay_receipt,
        source_output=source_output,
        replay_output=replay_output,
        semantic_policy_id=policy.policy_id,
        semantic_registry=registry,
    )

    assert diff.valid and diff.semantic.result == "EQUIVALENT"
    assert diff.semantic.exact_match is False
    assert diff.semantic.policy_id == policy.policy_id
    assert len(diff.structural_changes) == 1
    assert diff.semantic.matched_change_count == 1

    with pytest.raises(ReplayExecutionError, match="supplied together"):
        build_replay_diff(
            source,
            replay_receipt,
            source_output=source_output,
            replay_output=replay_output,
            semantic_policy_id=policy.policy_id,
        )
    with pytest.raises(ReplayExecutionError, match="evaluation failed"):
        build_replay_diff(
            source,
            replay_receipt,
            source_output=source_output,
            replay_output=replay_output,
            semantic_policy_id="gbx:semantic-policy:sha256:" + "0" * 64,
            semantic_registry=registry,
        )
