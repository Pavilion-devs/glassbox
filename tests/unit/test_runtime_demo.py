"""Executable proof for the deterministic sample agent."""

from __future__ import annotations

import json

from examples.deterministic_pricing_agent import build_pricing_agent

from glassbox import EventKind, GlassBox, InMemorySink


def test_pricing_agent_is_deterministic_and_keeps_values_out_of_events() -> None:
    sink = InMemorySink()
    runtime = GlassBox(sink)
    agent = build_pricing_agent(runtime)

    first = agent("customer-private-17")
    second = agent("customer-private-17")

    assert (
        first
        == second
        == {
            "customer_id": "customer-private-17",
            "recommended_price": 85,
            "currency": "USD",
        }
    )
    assert [event.kind for event in sink.events[:5]] == [
        EventKind.RUN_STARTED,
        EventKind.EVIDENCE_OBSERVED,
        EventKind.ACTION_ATTEMPTED,
        EventKind.ACTION_FINISHED,
        EventKind.RUN_FINISHED,
    ]
    encoded = json.dumps([event.to_dict() for event in sink.events])
    assert "customer-private-17" not in encoded
    assert "demo-secret" not in encoded
