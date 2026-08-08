"""Reviewed reference semantic policies built from the closed v1 primitives."""

from __future__ import annotations

from glassbox_policy.semantic import SemanticRule, SemanticRuleKind, SemanticRulePack


def pricing_recommendation_policy_v1() -> SemanticRulePack:
    """Treat sub-unit price drift as equivalent for pricing recommendations.

    The rule accepts a maximum absolute delta of 0.50 or a relative delta of 0.5%.
    Every other structural change remains material because the evaluator requires
    complete positive rule coverage.
    """

    return SemanticRulePack.create(
        name="glassbox.pricing-recommendation",
        version="1.0.0",
        output_kind="pricing-recommendation",
        rules=(
            SemanticRule(
                rule_id="recommended-price-tolerance",
                kind=SemanticRuleKind.NUMERIC_TOLERANCE,
                path="/recommended_price",
                absolute_tolerance="0.50",
                relative_tolerance="0.005",
            ),
        ),
    )


__all__ = ["pricing_recommendation_policy_v1"]
