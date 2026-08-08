"""Offline contract for the guarded live DataHub forensic proof."""

from __future__ import annotations

from examples.end_to_end_forensics_skill import USED_FIELD_URN, build_forensics_receipt

from glassbox_dbom import verify_receipt


def test_forensics_live_demo_builds_a_signed_field_precise_receipt() -> None:
    receipt = build_forensics_receipt()

    assert verify_receipt(receipt, require_signature=True).valid
    assert receipt["run"]["run_id"] == "forensics-live-run-001"
    assert receipt["evidence"][0]["schema_field_urn"] == USED_FIELD_URN
    assert receipt["evidence"][0]["state"] == "OBSERVED"
