"""Deterministic correctness and schema contracts for the flagship benchmark."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import ValidationError

from benchmarks.agent_invalidation.runner import (
    Ablation,
    FixtureError,
    build_benchmark_report,
    load_cases,
    validate_benchmark_report,
)


def _variants(report: dict) -> dict[str, dict]:
    return {item["variant"]: item for item in report["variants"]}


def _case(variant: dict, case_id: str) -> dict:
    return next(item for item in variant["cases"] if item["case_id"] == case_id)


def test_five_way_ablation_is_content_addressed_schema_valid_and_repeatable() -> None:
    first = build_benchmark_report()
    second = build_benchmark_report()

    assert first == second
    validate_benchmark_report(first)
    assert first["case_count"] == 12
    assert [item["variant"] for item in first["variants"]] == [item.value for item in Ablation]
    assert first["replay_policy"]["correctness"] == {
        "numerator": 4,
        "denominator": 4,
        "value": 1.0,
    }
    assert first["redaction"]["escape_rate"]["value"] == 0.0
    assert first["live_evidence"]["completed_redelivery_zero_write_rate"]["value"] == 1.0


def test_full_evidence_removes_false_invalidations_without_hiding_unknowns() -> None:
    variants = _variants(build_benchmark_report(live_report_path=None))
    static = variants[Ablation.STATIC_DECLARED_LINEAGE.value]
    raw = variants[Ablation.RAW_OTEL_TRACES.value]
    no_field = variants[Ablation.GLASSBOX_WITHOUT_FIELD_EVIDENCE.value]
    no_snapshot = variants[Ablation.GLASSBOX_WITHOUT_METADATA_SNAPSHOTS.value]
    full = variants[Ablation.FULL_GLASSBOX.value]

    assert static["impact"]["false_invalidation_rate"]["value"] == 0.833333
    assert raw["impact"]["false_invalidation_rate"]["value"] == 0.666667
    assert no_field["impact"]["false_invalidation_rate"]["value"] == 0.5
    assert no_snapshot["impact"]["false_invalidation_rate"]["value"] == 0.166667
    assert full["impact"]["false_invalidation_rate"]["value"] == 0.0
    assert full["impact"]["missed_invalidation_rate"]["value"] == 0.0
    assert full["impact"]["unknown_at_risk_honesty_rate"]["value"] == 1.0
    assert full["resolution"]["field_recall"]["value"] == 0.888889
    assert full["resolution"]["field_resolution_failed_cases"] == ["unresolved-runtime-context"]


def test_field_and_snapshot_ablation_changes_the_expected_causal_cases() -> None:
    variants = _variants(build_benchmark_report(live_report_path=None))
    full = variants[Ablation.FULL_GLASSBOX.value]
    no_field = variants[Ablation.GLASSBOX_WITHOUT_FIELD_EVIDENCE.value]
    no_snapshot = variants[Ablation.GLASSBOX_WITHOUT_METADATA_SNAPSHOTS.value]
    raw = variants[Ablation.RAW_OTEL_TRACES.value]

    assert _case(full, "unrelated-field-same-asset")["state"] == "UNAFFECTED"
    assert _case(no_field, "unrelated-field-same-asset")["state"] == "AT_RISK"
    assert _case(full, "matching-post-change-snapshot")["state"] == "UNAFFECTED"
    assert _case(no_snapshot, "matching-post-change-snapshot")["state"] == "STALE"
    assert _case(full, "trace-alias-collision")["state"] == "UNAFFECTED"
    assert _case(raw, "trace-alias-collision")["state"] == "AT_RISK"
    assert _case(full, "unresolved-runtime-context")["state"] == "UNKNOWN"


def test_fixture_and_report_contracts_fail_closed(tmp_path: Path) -> None:
    raw, _ = load_cases()
    malformed = copy.deepcopy(raw)
    malformed["unexpected"] = True
    fixture = tmp_path / "fixtures.json"
    fixture.write_text(json.dumps(malformed), encoding="utf-8")
    with pytest.raises(FixtureError, match="missing or unexpected"):
        load_cases(fixture)

    report = build_benchmark_report(live_report_path=None)
    report["unexpected"] = True
    with pytest.raises(ValidationError):
        validate_benchmark_report(report)


def test_benchmark_report_never_contains_redaction_sentinels_or_personal_paths() -> None:
    rendered = json.dumps(build_benchmark_report(live_report_path=None), sort_keys=True)

    assert "benchmark-sensitive-value" not in rendered
    assert "/" + "Users/" not in rendered
    assert "postgresql://" not in rendered
