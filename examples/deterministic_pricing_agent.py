"""Deterministic, network-free agent used by runtime and compiler tests."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from pathlib import Path

from examples.pricing_policy import apply_replayable_pricing_policy

from glassbox import ActionEffect, EvidenceRole, EvidenceState, GlassBox

ORDERS_URN = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"


def build_pricing_agent(
    runtime: GlassBox,
    *,
    schema_field_urn: str | None = None,
) -> Callable[[str], dict[str, int | str]]:
    """Return a deterministic agent instrumented through the public decorator API."""

    @runtime.consequential(
        agent_id="glassbox.demo.pricing-agent",
        agent_version="0.1.0",
        workflow_id="glassbox.demo.recommend-price",
        workflow_version="0.1.0",
    )
    def recommend_price(customer_id: str) -> dict[str, int | str]:
        aggregate = _synthetic_order_aggregate(customer_id)
        runtime.observe_evidence(
            entity_type="dataset",
            datahub_urn=ORDERS_URN,
            schema_field_urn=schema_field_urn,
            state=EvidenceState.OBSERVED,
            role=EvidenceRole.INPUT,
            representation=aggregate,
            metadata={"source": "deterministic-fixture", "authorization": "demo-secret"},
        )
        return runtime.call_tool(
            "glassbox.demo.pricing-policy",
            _apply_pricing_policy,
            aggregate,
            effect=ActionEffect.READ_ONLY,
            metadata={"policy.version": "0.1.0"},
        )

    return recommend_price


def build_replayable_pricing_agent(
    runtime: GlassBox,
    *,
    schema_field_urn: str,
) -> Callable[[str], dict[str, int | str]]:
    """Return the field-dependent v2 agent used by the causal recovery proof."""

    @runtime.consequential(
        agent_id="glassbox.demo.pricing-agent",
        agent_version="0.2.0",
        workflow_id="glassbox.demo.recommend-price",
        workflow_version="0.2.0",
    )
    def recommend_price(customer_id: str) -> dict[str, int | str]:
        aggregate = _synthetic_order_aggregate(customer_id)
        aggregate["average_order_value"] = str(aggregate["average_order_value"])
        runtime.observe_evidence(
            entity_type="dataset",
            datahub_urn=ORDERS_URN,
            schema_field_urn=schema_field_urn,
            state=EvidenceState.OBSERVED,
            role=EvidenceRole.INPUT,
            representation=aggregate,
            metadata={"source": "deterministic-fixture", "authorization": "demo-secret"},
        )
        return runtime.call_tool(
            "glassbox.demo.pricing-policy",
            apply_replayable_pricing_policy,
            aggregate,
            effect=ActionEffect.READ_ONLY,
            metadata={"policy.version": "0.2.0"},
        )

    return recommend_price


def corrected_pricing_input(
    customer_id: str,
    *,
    average_order_value: int,
) -> dict[str, int | str]:
    """Resolve the corrected numeric input used by an authorized replay."""

    aggregate = _synthetic_order_aggregate(customer_id)
    aggregate["average_order_value"] = average_order_value
    return aggregate


def pricing_source_digest() -> str:
    """Commit the exact source module that implements the demo capability."""

    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def _synthetic_order_aggregate(customer_id: str) -> dict[str, int | str]:
    stable_score = sum(customer_id.encode("utf-8")) % 7
    return {
        "customer_id": customer_id,
        "order_count": 10 + stable_score,
        "average_order_value": 40 + stable_score,
    }


def _apply_pricing_policy(aggregate: dict[str, int | str]) -> dict[str, int | str]:
    order_count = aggregate["order_count"]
    assert isinstance(order_count, int)
    adjustment = min(order_count, 15)
    return {
        "customer_id": aggregate["customer_id"],
        "recommended_price": 100 - adjustment,
        "currency": "USD",
    }
