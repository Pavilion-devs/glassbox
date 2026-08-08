"""Contract checks for the committed raw-free semantic-policy DataHub proof."""

from __future__ import annotations

import json
from pathlib import Path

REPORT = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "compatibility"
    / "datahub-1.6.0-semantic-policy.live.json"
)


def test_committed_semantic_policy_report_proves_non_exact_equivalence() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    artifacts = report["artifacts"]
    policy = report["semantic_policy"]

    assert report["valid"] is True
    assert report["contract"] == "glassbox.datahub-semantic-policy.v1"
    assert report["compatibility"]["datahub_core_target"] == "1.6.0"
    assert report["compatibility"]["sdk_version"] == "1.6.0.15"
    assert report["raw_content_returned"] is False

    assert artifacts["valid"] is True
    assert artifacts["semantic_policy_id"] == policy["policy_id"]
    assert artifacts["semantic_rule_id"] == policy["rule_id"]
    assert artifacts["semantic_rule_version"] == policy["rule_version"]
    assert artifacts["semantic_result"] == policy["result"] == "EQUIVALENT"
    assert artifacts["semantic_exact_match"] is policy["exact_match"] is False
    assert artifacts["structural_change_count"] == policy["structural_change_count"] == 1
    assert policy["matched_change_count"] == 1
    assert policy["reason_codes"] == ["ALL_CHANGES_PROVEN_EQUIVALENT"]
    assert policy["rule_evaluations"] == [
        {
            "covered_change_paths": ["/recommended_price"],
            "kind": "NUMERIC_TOLERANCE",
            "passed": True,
            "path": "/recommended_price",
            "raw_content_returned": False,
            "reason_code": "NUMERIC_TOLERANCE_MATCH",
            "rule_id": "recommended-price-tolerance",
        }
    ]

    assert report["supersession"]["valid"] is True
    assert report["supersession"]["verified_property_count"] == 19
    assert report["history_preservation"]["receipt_documents_unchanged_after_supersession"]
    assert (
        report["history_preservation"]["direct_entity_digests_before"]
        == report["history_preservation"]["direct_entity_digests_after"]
    )
    assert set(report["privacy"].values()) == {False}

    encoded = json.dumps(report, sort_keys=True).lower()
    for forbidden in (
        "semantic-private-customer",
        '"recommended_price": 100',
        "postgresql://",
        "/users/",
        "begin private key",
        "authorization",
        "password",
    ):
        assert forbidden not in encoded
