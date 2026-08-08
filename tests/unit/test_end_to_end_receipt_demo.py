"""Offline checks for the live end-to-end proof fixture."""

from __future__ import annotations

import json

from examples.end_to_end_receipt import build_signed_receipt
from examples.pricing_policy import pricing_policy_source_digest

from glassbox_dbom import verify_receipt


def test_live_proof_fixture_is_repeatable_signed_and_private() -> None:
    first = build_signed_receipt()
    second = build_signed_receipt()

    assert verify_receipt(first, require_signature=True).valid
    assert verify_receipt(second, require_signature=True).valid
    assert first["receipt_id"] == second["receipt_id"]
    assert first["integrity"]["payload_digest"] == second["integrity"]["payload_digest"]
    assert first["run"]["run_id"] == "glassbox-live-pricing-run-001"
    assert first["evidence"][0]["state"] == "OBSERVED"
    assert first["actions"][0]["status"] == "SUCCEEDED"
    assert first["replay"]["eligibility"] == "ELIGIBLE"

    encoded = json.dumps(first)
    assert "synthetic-live-customer" not in encoded


def test_replay_ready_fixture_pins_executable_resources_and_uses_field_input() -> None:
    field = (
        "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:postgres,"
        "commerce.orders,PROD),average_order_value)"
    )
    receipt = build_signed_receipt(schema_field_urn=field, replay_ready=True)

    assert verify_receipt(receipt, require_signature=True).valid
    assert receipt["agent"]["version"] == "0.2.0"
    assert receipt["agent"]["source_digest"] is not None
    assert receipt["models"] == []
    assert receipt["skills"][0]["source_digest"] == receipt["agent"]["source_digest"]
    assert receipt["tools"][0]["source_digest"]["value"] == pricing_policy_source_digest()
    assert receipt["tools"][0]["source_digest"] != receipt["agent"]["source_digest"]
    assert receipt["tools"][0]["schema_digest"] is not None
