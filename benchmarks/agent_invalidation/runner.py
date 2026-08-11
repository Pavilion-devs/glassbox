"""Deterministic five-way evidence ablation over the production policy engine."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import platform
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from examples.deterministic_pricing_agent import (
    _synthetic_order_aggregate,
    build_replayable_pricing_agent,
)
from examples.end_to_end_invalidation import FIELD_URN
from examples.end_to_end_receipt import build_signed_receipt
from examples.pricing_policy import apply_replayable_pricing_policy
from jsonschema import Draft202012Validator

from glassbox import GlassBox, InMemorySink
from glassbox.redaction import RedactionPolicy, digest_value
from glassbox_dbom import SigningKey, seal_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_policy import (
    ChangeKind,
    EvidenceDependency,
    EvidenceRole,
    EvidenceState,
    FieldCoverage,
    FieldLineageProof,
    ImpactState,
    NormalizedChange,
    ReceiptDependencyProfile,
    classify_materiality,
)
from glassbox_replay import (
    ReplayDecision,
    ReplayMode,
    ReplaySupplement,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
    build_replay_bundle,
    plan_replay,
)

BENCHMARK_NAME = "glassbox.agent-invalidation-ablation.v1"
BENCHMARK_VERSION = "0.1.0"
_BENCHMARK_DOMAIN = b"glassbox.benchmark.agent-invalidation.v1\0"
_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_FIXTURES = Path(__file__).with_name("fixtures.v1.json")
DEFAULT_SCHEMA = _ROOT / "schemas" / "benchmark-report" / BENCHMARK_VERSION / "schema.json"
DEFAULT_LIVE_REPORT = (
    _ROOT / "docs" / "compatibility" / "datahub-1.6.0-flagship-causal-recovery.live.json"
)
_UNCERTAIN_STATES = frozenset({ImpactState.AT_RISK, ImpactState.UNKNOWN})


class FixtureError(ValueError):
    """Raised when a benchmark fixture violates the closed evaluation contract."""


class Truth(StrEnum):
    """Ground-truth impact labels used only by the synthetic benchmark."""

    CONTAMINATED = "CONTAMINATED"
    CLEAN = "CLEAN"
    INDETERMINATE = "INDETERMINATE"


class Ablation(StrEnum):
    """Required evidence-capability variants from the GlassBox evaluation plan."""

    STATIC_DECLARED_LINEAGE = "STATIC_DECLARED_LINEAGE"
    RAW_OTEL_TRACES = "RAW_OTEL_TRACES"
    GLASSBOX_WITHOUT_FIELD_EVIDENCE = "GLASSBOX_WITHOUT_FIELD_EVIDENCE"
    GLASSBOX_WITHOUT_METADATA_SNAPSHOTS = "GLASSBOX_WITHOUT_METADATA_SNAPSHOTS"
    FULL_GLASSBOX = "FULL_GLASSBOX"


_REMOVED_CAPABILITIES = {
    Ablation.STATIC_DECLARED_LINEAGE: [
        "runtime observation state",
        "field identity",
        "metadata snapshot binding",
    ],
    Ablation.RAW_OTEL_TRACES: [
        "verified DataHub resolution authority",
        "field identity",
        "metadata snapshot binding",
    ],
    Ablation.GLASSBOX_WITHOUT_FIELD_EVIDENCE: ["field identity", "field-lineage proof"],
    Ablation.GLASSBOX_WITHOUT_METADATA_SNAPSHOTS: [
        "observation timestamp and representation digest"
    ],
    Ablation.FULL_GLASSBOX: [],
}


@dataclass(frozen=True)
class BenchmarkCase:
    """One normalized context-change case and its independent ground truth."""

    case_id: str
    description: str
    truth: Truth
    ground_truth_assets: tuple[str, ...]
    ground_truth_fields: tuple[str, ...]
    static_declared_assets: tuple[str, ...]
    raw_otel_assets: tuple[str, ...]
    dependency: Mapping[str, Any]
    lineage: Mapping[str, Any]
    change: Mapping[str, Any]


def _required_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise FixtureError(f"{key} must be an object")
    return selected


def _required_list(value: Mapping[str, Any], key: str) -> list[Any]:
    selected = value.get(key)
    if not isinstance(selected, list):
        raise FixtureError(f"{key} must be an array")
    return selected


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise FixtureError(f"{key} must be a non-empty string")
    return selected


def _string_tuple(value: Mapping[str, Any], key: str) -> tuple[str, ...]:
    selected = _required_list(value, key)
    if any(not isinstance(item, str) or not item for item in selected):
        raise FixtureError(f"{key} must contain only non-empty strings")
    result = tuple(sorted(selected))
    if len(result) != len(set(result)):
        raise FixtureError(f"{key} must not contain duplicate values")
    return result


def load_cases(
    path: Path = DEFAULT_FIXTURES,
) -> tuple[Mapping[str, Any], tuple[BenchmarkCase, ...]]:
    """Load and close-check the published benchmark fixture set."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, Mapping):
        raise FixtureError("benchmark fixture root must be an object")
    if raw.get("schema_version") != BENCHMARK_VERSION or raw.get("benchmark") != BENCHMARK_NAME:
        raise FixtureError("benchmark fixture identity or schema version drifted")
    allowed_root = {"schema_version", "benchmark", "cases"}
    if set(raw) != allowed_root:
        raise FixtureError("benchmark fixture root has missing or unexpected properties")
    raw_cases = _required_list(raw, "cases")
    cases: list[BenchmarkCase] = []
    case_ids: set[str] = set()
    expected_case_keys = {
        "case_id",
        "description",
        "truth",
        "ground_truth",
        "signals",
        "dependency",
        "lineage",
        "change",
    }
    for item in raw_cases:
        if not isinstance(item, Mapping) or set(item) != expected_case_keys:
            raise FixtureError("every benchmark case must use the closed case contract")
        case_id = _required_string(item, "case_id")
        if case_id in case_ids:
            raise FixtureError("benchmark case IDs must be unique")
        case_ids.add(case_id)
        truth = Truth(_required_string(item, "truth"))
        ground_truth = _required_mapping(item, "ground_truth")
        signals = _required_mapping(item, "signals")
        if set(ground_truth) != {"assets", "fields"} or set(signals) != {
            "static_declared_assets",
            "raw_otel_assets",
        }:
            raise FixtureError("ground_truth or signals has an unexpected property")
        dependency = _required_mapping(item, "dependency")
        lineage = _required_mapping(item, "lineage")
        change = _required_mapping(item, "change")
        cases.append(
            BenchmarkCase(
                case_id=case_id,
                description=_required_string(item, "description"),
                truth=truth,
                ground_truth_assets=_string_tuple(ground_truth, "assets"),
                ground_truth_fields=_string_tuple(ground_truth, "fields"),
                static_declared_assets=_string_tuple(signals, "static_declared_assets"),
                raw_otel_assets=_string_tuple(signals, "raw_otel_assets"),
                dependency=dependency,
                lineage=lineage,
                change=change,
            )
        )
    if not cases or not {item.truth for item in cases} == set(Truth):
        raise FixtureError("benchmark requires contaminated, clean, and indeterminate cases")
    return raw, tuple(cases)


def _sha256_label(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise FixtureError("snapshot version labels must be non-empty strings or null")
    return hashlib.sha256(value.encode()).hexdigest()


def _lineage(value: Mapping[str, Any], *, remove_field_proof: bool) -> FieldLineageProof:
    if set(value) != {"coverage", "rule_id", "wildcard_query"}:
        raise FixtureError("lineage fixture has an unexpected property")
    if remove_field_proof:
        return FieldLineageProof()
    coverage = FieldCoverage(_required_string(value, "coverage"))
    rule_id = value.get("rule_id")
    wildcard = value.get("wildcard_query")
    if rule_id is not None and not isinstance(rule_id, str):
        raise FixtureError("lineage rule_id must be a string or null")
    if wildcard is not None and not isinstance(wildcard, bool):
        raise FixtureError("lineage wildcard_query must be a boolean or null")
    return FieldLineageProof(coverage=coverage, rule_id=rule_id, wildcard_query=wildcard)


def _base_dependency(case: BenchmarkCase) -> EvidenceDependency:
    value = case.dependency
    expected = {
        "entity_urn",
        "schema_field_urn",
        "state",
        "role",
        "observed_at",
        "snapshot_version",
    }
    if set(value) != expected:
        raise FixtureError("dependency fixture has an unexpected property")
    entity = value.get("entity_urn")
    field = value.get("schema_field_urn")
    observed_at = value.get("observed_at")
    for selected, label in ((entity, "entity_urn"), (field, "schema_field_urn")):
        if selected is not None and not isinstance(selected, str):
            raise FixtureError(f"dependency {label} must be a string or null")
    if observed_at is not None and not isinstance(observed_at, str):
        raise FixtureError("dependency observed_at must be a string or null")
    return EvidenceDependency(
        evidence_id=f"evidence-{case.case_id}",
        datahub_urn=entity,
        schema_field_urn=field,
        state=EvidenceState(_required_string(value, "state")),
        role=EvidenceRole(_required_string(value, "role")),
        observed_at=observed_at,
        representation_digest=_sha256_label(value.get("snapshot_version")),
    )


def _change(case: BenchmarkCase) -> NormalizedChange:
    value = case.change
    expected = {
        "event_id",
        "entity_urn",
        "aspect_name",
        "kind",
        "occurred_at",
        "schema_field_urn",
        "before_version",
        "after_version",
    }
    if set(value) != expected:
        raise FixtureError("change fixture has an unexpected property")
    field = value.get("schema_field_urn")
    if field is not None and not isinstance(field, str):
        raise FixtureError("change schema_field_urn must be a string or null")
    return NormalizedChange(
        event_id=_required_string(value, "event_id"),
        entity_urn=_required_string(value, "entity_urn"),
        aspect_name=_required_string(value, "aspect_name"),
        kind=ChangeKind(_required_string(value, "kind")),
        occurred_at=_required_string(value, "occurred_at"),
        schema_field_urn=field,
        before_digest=_sha256_label(value.get("before_version")),
        after_digest=_sha256_label(value.get("after_version")),
    )


def _receipt_identity(case: BenchmarkCase, ablation: Ablation) -> tuple[str, str]:
    digest = hashlib.sha256(f"{case.case_id}:{ablation.value}".encode()).hexdigest()
    return (
        f"gbx:receipt:sha256:{digest}",
        f"urn:li:document:glassbox.receipt.{digest}",
    )


def _signal_dependencies(
    case: BenchmarkCase,
    ablation: Ablation,
    assets: tuple[str, ...],
    state: EvidenceState,
) -> tuple[EvidenceDependency, ...]:
    role = EvidenceRole(_required_string(case.dependency, "role"))
    if not assets:
        return (
            EvidenceDependency(
                evidence_id=f"evidence-{case.case_id}-{ablation.value.lower()}-unresolved",
                datahub_urn=None,
                schema_field_urn=None,
                state=EvidenceState.UNKNOWN,
                role=role,
                observed_at=None,
                representation_digest=None,
            ),
        )
    return tuple(
        EvidenceDependency(
            evidence_id=f"evidence-{case.case_id}-{ablation.value.lower()}-{index}",
            datahub_urn=asset,
            schema_field_urn=None,
            state=state,
            role=role,
            observed_at=None,
            representation_digest=None,
        )
        for index, asset in enumerate(assets)
    )


def project_profile(case: BenchmarkCase, ablation: Ablation) -> ReceiptDependencyProfile:
    """Remove only the evidence capabilities named by one ablation."""

    dependency = _base_dependency(case)
    if ablation is Ablation.STATIC_DECLARED_LINEAGE:
        dependencies = _signal_dependencies(
            case,
            ablation,
            case.static_declared_assets,
            EvidenceState.DECLARED,
        )
        lineage = FieldLineageProof()
    elif ablation is Ablation.RAW_OTEL_TRACES:
        dependencies = _signal_dependencies(
            case,
            ablation,
            case.raw_otel_assets,
            EvidenceState.INFERRED,
        )
        lineage = FieldLineageProof()
    elif ablation is Ablation.GLASSBOX_WITHOUT_FIELD_EVIDENCE:
        dependencies = (
            EvidenceDependency(
                evidence_id=dependency.evidence_id,
                datahub_urn=dependency.datahub_urn,
                schema_field_urn=None,
                state=dependency.state,
                role=dependency.role,
                observed_at=dependency.observed_at,
                representation_digest=dependency.representation_digest,
            ),
        )
        lineage = _lineage(case.lineage, remove_field_proof=True)
    elif ablation is Ablation.GLASSBOX_WITHOUT_METADATA_SNAPSHOTS:
        dependencies = (
            EvidenceDependency(
                evidence_id=dependency.evidence_id,
                datahub_urn=dependency.datahub_urn,
                schema_field_urn=dependency.schema_field_urn,
                state=dependency.state,
                role=dependency.role,
                observed_at=None,
                representation_digest=None,
            ),
        )
        lineage = _lineage(case.lineage, remove_field_proof=False)
    else:
        dependencies = (dependency,)
        lineage = _lineage(case.lineage, remove_field_proof=False)
    receipt_id, document_urn = _receipt_identity(case, ablation)
    return ReceiptDependencyProfile(
        receipt_id=receipt_id,
        document_urn=document_urn,
        ended_at="2026-08-08T12:00:01Z",
        dependencies=dependencies,
        field_lineage=lineage,
    )


def _ratio(numerator: int, denominator: int) -> dict[str, int | float | None]:
    return {
        "numerator": numerator,
        "denominator": denominator,
        "value": None if denominator == 0 else round(numerator / denominator, 6),
    }


def _resolution_metrics(
    cases: Sequence[BenchmarkCase], profiles: Sequence[ReceiptDependencyProfile]
) -> dict[str, Any]:
    true_assets = predicted_assets = correct_assets = 0
    true_fields = predicted_fields = correct_fields = 0
    failed_assets: list[str] = []
    failed_fields: list[str] = []
    for case, profile in zip(cases, profiles, strict=True):
        expected_assets = set(case.ground_truth_assets)
        expected_fields = set(case.ground_truth_fields)
        projected_assets = {
            item.datahub_urn for item in profile.dependencies if item.datahub_urn is not None
        }
        projected_fields = {
            item.schema_field_urn
            for item in profile.dependencies
            if item.schema_field_urn is not None
        }
        true_assets += len(expected_assets)
        predicted_assets += len(projected_assets)
        correct_assets += len(expected_assets & projected_assets)
        true_fields += len(expected_fields)
        predicted_fields += len(projected_fields)
        correct_fields += len(expected_fields & projected_fields)
        if projected_assets != expected_assets:
            failed_assets.append(case.case_id)
        if projected_fields != expected_fields:
            failed_fields.append(case.case_id)
    return {
        "asset_precision": _ratio(correct_assets, predicted_assets),
        "asset_recall": _ratio(correct_assets, true_assets),
        "field_precision": _ratio(correct_fields, predicted_fields),
        "field_recall": _ratio(correct_fields, true_fields),
        "asset_resolution_failed_cases": sorted(failed_assets),
        "field_resolution_failed_cases": sorted(failed_fields),
    }


def _impact_metrics(results: Sequence[tuple[BenchmarkCase, ImpactState]]) -> dict[str, Any]:
    contaminated = [item for item in results if item[0].truth is Truth.CONTAMINATED]
    clean = [item for item in results if item[0].truth is Truth.CLEAN]
    indeterminate = [item for item in results if item[0].truth is Truth.INDETERMINATE]

    def quarantined(state: ImpactState) -> bool:
        return state in {
            ImpactState.STALE,
            ImpactState.AT_RISK,
            ImpactState.UNKNOWN,
        }

    contamination_quarantined = sum(quarantined(state) for _, state in contaminated)
    clean_quarantined = sum(quarantined(state) for _, state in clean)
    confident_true = sum(state is ImpactState.STALE for _, state in contaminated)
    confident_false = sum(state is ImpactState.STALE for _, state in clean)
    honest_unknown = sum(state in _UNCERTAIN_STATES for _, state in indeterminate)
    false_cases = sorted(case.case_id for case, state in clean if quarantined(state))
    missed_cases = sorted(case.case_id for case, state in contaminated if not quarantined(state))
    dishonest_cases = sorted(
        case.case_id for case, state in indeterminate if state not in _UNCERTAIN_STATES
    )
    return {
        "quarantine_precision": _ratio(
            contamination_quarantined,
            contamination_quarantined + clean_quarantined,
        ),
        "quarantine_recall": _ratio(contamination_quarantined, len(contaminated)),
        "false_invalidation_rate": _ratio(clean_quarantined, len(clean)),
        "missed_invalidation_rate": _ratio(
            len(contaminated) - contamination_quarantined,
            len(contaminated),
        ),
        "confident_stale_precision": _ratio(
            confident_true,
            confident_true + confident_false,
        ),
        "confident_stale_recall": _ratio(confident_true, len(contaminated)),
        "unknown_at_risk_honesty_rate": _ratio(honest_unknown, len(indeterminate)),
        "false_invalidation_cases": false_cases,
        "missed_invalidation_cases": missed_cases,
        "dishonest_indeterminate_cases": dishonest_cases,
    }


def _evaluate_variant(cases: Sequence[BenchmarkCase], ablation: Ablation) -> dict[str, Any]:
    profiles = [project_profile(case, ablation) for case in cases]
    case_results: list[dict[str, Any]] = []
    states: list[tuple[BenchmarkCase, ImpactState]] = []
    for case, profile in zip(cases, profiles, strict=True):
        assessment = classify_materiality(profile, _change(case))
        states.append((case, assessment.state))
        case_results.append(
            {
                "case_id": case.case_id,
                "truth": case.truth.value,
                "state": assessment.state.value,
                "reason_code": assessment.reason_code,
                "quarantine_required": assessment.quarantine_required,
                "matched_evidence_count": len(assessment.matched_evidence_ids),
                "resolved_asset_count": len(
                    {
                        item.datahub_urn
                        for item in profile.dependencies
                        if item.datahub_urn is not None
                    }
                ),
                "resolved_field_count": len(
                    {
                        item.schema_field_urn
                        for item in profile.dependencies
                        if item.schema_field_urn is not None
                    }
                ),
            }
        )
    return {
        "variant": ablation.value,
        "policy_version": "glassbox.materiality.v1",
        "removed_capabilities": _REMOVED_CAPABILITIES[ablation],
        "resolution": _resolution_metrics(cases, profiles),
        "impact": _impact_metrics(states),
        "cases": case_results,
    }


def _inventory(receipt: Mapping[str, Any]) -> ResourceInventory:
    resources: list[ResourceAvailability] = []
    singular = (
        (ResourceKind.AGENT, receipt["agent"], True),
        (ResourceKind.WORKFLOW, receipt["workflow"], False),
    )
    plural = (
        (ResourceKind.MODEL, receipt["models"], True),
        (ResourceKind.SKILL, receipt["skills"], True),
        (ResourceKind.TOOL, receipt["tools"], True),
    )
    for kind, item, source_required in singular:
        if not isinstance(item, Mapping):
            raise RuntimeError("replay benchmark receipt resource is invalid")
        resources.append(_availability(kind, item, source_required=source_required))
    for kind, items, source_required in plural:
        if not isinstance(items, list):
            raise RuntimeError("replay benchmark receipt resource list is invalid")
        for item in items:
            if not isinstance(item, Mapping):
                raise RuntimeError("replay benchmark receipt resource is invalid")
            resources.append(_availability(kind, item, source_required=source_required))
    return ResourceInventory(tuple(resources))


def _availability(
    kind: ResourceKind,
    item: Mapping[str, Any],
    *,
    source_required: bool,
) -> ResourceAvailability:
    source = item.get("source_digest")
    schema = item.get("schema_digest")
    source_digest = source.get("value") if isinstance(source, Mapping) else None
    schema_digest = schema.get("value") if isinstance(schema, Mapping) else None
    if source_required and not isinstance(source_digest, str):
        raise RuntimeError("replay benchmark resource lacks a source digest")
    return ResourceAvailability(
        kind=kind,
        resource_id=str(item["id"]),
        version=str(item["version"]),
        source_digest=source_digest,
        schema_digest=schema_digest if kind is ResourceKind.TOOL else None,
    )


def _reseal_receipt(
    source: Mapping[str, Any],
    *,
    effect: str,
    eligibility: str,
) -> dict[str, Any]:
    payload = copy.deepcopy(dict(source))
    payload.pop("receipt_id")
    payload.pop("integrity")
    payload["actions"][0]["effect"] = effect
    payload["replay"]["eligibility"] = eligibility
    return seal_receipt(
        payload,
        signing_keys=(SigningKey("benchmark-source", Ed25519PrivateKey.generate()),),
    )


def _replay_case(
    source: Mapping[str, Any],
    *,
    inventory: ResourceInventory,
    supplement: ReplaySupplement,
) -> ReplayDecision:
    bundle = build_replay_bundle(
        source,
        mode=ReplayMode.PINNED,
        supplement=supplement,
        signing_keys=(SigningKey("benchmark-bundle", Ed25519PrivateKey.generate()),),
    )
    return plan_replay(
        bundle,
        source_receipt=source,
        inventory=inventory,
        evaluated_at="2026-08-08T12:30:00Z",
    ).decision


def _replay_policy_proof() -> dict[str, Any]:
    source = build_signed_receipt(schema_field_urn=FIELD_URN, replay_ready=True)
    safe_supplement = ReplaySupplement(
        input_digest=digest_value({"benchmark": "authorized-input"}),
        input_reference="artifact://glassbox-benchmark/replay-input",
        feature_flags_digest=hashlib.sha256(b"benchmark-flags-v1").hexdigest(),
    )
    irreversible = _reseal_receipt(
        source,
        effect="IRREVERSIBLE",
        eligibility="UNREPLAYABLE",
    )
    cases = (
        (
            "safe-read-only",
            _replay_case(source, inventory=_inventory(source), supplement=safe_supplement),
            ReplayDecision.ALLOW,
        ),
        (
            "irreversible-refusal",
            _replay_case(
                irreversible,
                inventory=_inventory(irreversible),
                supplement=safe_supplement,
            ),
            ReplayDecision.BLOCK,
        ),
        (
            "missing-resource-refusal",
            _replay_case(
                source,
                inventory=ResourceInventory(()),
                supplement=safe_supplement,
            ),
            ReplayDecision.BLOCK,
        ),
        (
            "missing-execution-material-dry-only",
            _replay_case(
                source,
                inventory=_inventory(source),
                supplement=ReplaySupplement(),
            ),
            ReplayDecision.DRY_RUN_ONLY,
        ),
    )
    correct = sum(actual is expected for _, actual, expected in cases)
    return {
        "policy_version": "glassbox.replay-policy.v1",
        "correctness": _ratio(correct, len(cases)),
        "cases": [
            {
                "case_id": case_id,
                "actual": actual.value,
                "expected": expected.value,
                "correct": actual is expected,
            }
            for case_id, actual, expected in cases
        ],
    }


def _redaction_proof() -> dict[str, Any]:
    policy = RedactionPolicy(sensitive_paths=frozenset({"customer.ssn"}))
    sensitive_keys = (
        "authorization",
        "api_key",
        "cookie",
        "password",
        "refresh_token",
        "secret",
        "set-cookie",
        "token",
        "x-api-key",
    )
    sentinels = [f"benchmark-sensitive-value-{index}" for index in range(len(sensitive_keys) + 1)]
    payload: dict[str, Any] = {key: sentinels[index] for index, key in enumerate(sensitive_keys)}
    payload["customer"] = {"ssn": sentinels[-1], "segment": "synthetic"}
    rendered = json.dumps(policy.sanitize(payload), sort_keys=True)
    escapes = sum(sentinel in rendered for sentinel in sentinels)
    return {
        "policy_id": policy.policy_id,
        "escape_rate": _ratio(escapes, len(sentinels)),
        "plaintext_values_retained": escapes,
    }


def _percentiles(samples_ns: Sequence[int], *, unit_divisor: float) -> dict[str, float | int]:
    if not samples_ns:
        raise ValueError("performance measurement requires at least one sample")
    ordered = sorted(samples_ns)

    def selected(percentile: float) -> float:
        index = max(0, min(len(ordered) - 1, round((len(ordered) - 1) * percentile)))
        return round(ordered[index] / unit_divisor, 6)

    return {
        "samples": len(ordered),
        "p50": selected(0.50),
        "p95": selected(0.95),
        "min": round(ordered[0] / unit_divisor, 6),
        "max": round(ordered[-1] / unit_divisor, 6),
    }


def _measure_call(function: Any) -> int:
    started = time.perf_counter_ns()
    function()
    return time.perf_counter_ns() - started


def _performance_measurement(
    cases: Sequence[BenchmarkCase],
    *,
    samples: int,
    compilation_samples: int,
) -> dict[str, Any]:
    if samples == 0 and compilation_samples == 0:
        return {"status": "NOT_MEASURED"}
    if samples < 1 or compilation_samples < 1:
        raise ValueError("both performance sample counts must be positive or both zero")
    classification: dict[str, dict[str, float | int]] = {}
    for ablation in Ablation:
        prepared = [(project_profile(case, ablation), _change(case)) for case in cases]

        suite_samples: list[int] = []
        for _ in range(samples):
            started = time.perf_counter_ns()
            for profile, change in prepared:
                classify_materiality(profile, change)
            suite_samples.append(time.perf_counter_ns() - started)

        classification[ablation.value] = _percentiles(
            suite_samples,
            unit_divisor=1_000.0,
        )

    def baseline_agent() -> None:
        aggregate = _synthetic_order_aggregate("synthetic-benchmark-customer")
        aggregate["average_order_value"] = str(aggregate["average_order_value"])
        apply_replayable_pricing_policy(aggregate)

    runtime = GlassBox(InMemorySink())
    instrumented_agent = build_replayable_pricing_agent(runtime, schema_field_urn=FIELD_URN)

    def observed_agent() -> None:
        instrumented_agent("synthetic-benchmark-customer")

    baseline_samples = [_measure_call(baseline_agent) for _ in range(samples)]
    observed_samples = [_measure_call(observed_agent) for _ in range(samples)]
    baseline_summary = _percentiles(baseline_samples, unit_divisor=1_000.0)
    observed_summary = _percentiles(observed_samples, unit_divisor=1_000.0)
    compilation = _percentiles(
        [
            _measure_call(
                lambda: build_signed_receipt(schema_field_urn=FIELD_URN, replay_ready=True)
            )
            for _ in range(compilation_samples)
        ],
        unit_divisor=1_000_000.0,
    )
    baseline_p50 = float(baseline_summary["p50"])
    observed_p50 = float(observed_summary["p50"])
    baseline_p95 = float(baseline_summary["p95"])
    observed_p95 = float(observed_summary["p95"])
    return {
        "status": "MEASURED_OFFLINE",
        "clock": "time.perf_counter_ns",
        "environment": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "policy_suite_latency_microseconds": classification,
        "agent_runtime_microseconds": {
            "baseline": baseline_summary,
            "glassbox_observed": observed_summary,
            "overhead_p50": round(observed_p50 - baseline_p50, 6),
            "overhead_p95": round(observed_p95 - baseline_p95, 6),
        },
        "receipt_compilation_milliseconds": compilation,
        "scope": (
            "Single-process deterministic microbenchmark; excludes network, DataHub, MCP, "
            "PostgreSQL, container startup, and model-provider latency."
        ),
    }


def _live_evidence(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {"status": "NOT_REQUESTED"}
    raw = path.read_bytes()
    report = json.loads(raw)
    if not isinstance(report, Mapping) or not report.get("valid"):
        raise RuntimeError("live flagship evidence is not a valid report")
    source = _required_mapping(report, "source_decision")
    negative = _required_mapping(report, "negative_control")
    invalidation = _required_mapping(report, "invalidation")
    replay = _required_mapping(report, "corrected_replay")
    supersession = _required_mapping(report, "supersession")
    closure = _required_mapping(report, "incident_closure")
    source_publication = _required_mapping(_required_mapping(source, "publication"), "datahub")
    replay_publication = _required_mapping(_required_mapping(replay, "publication"), "datahub")
    write_units = {
        "source_receipt_emissions": int(source_publication["emissions"]),
        "invalidation_emissions": int(invalidation["first_delivery_emissions"]),
        "replay_receipt_emissions": int(replay_publication["emissions"]),
        "supersession_emissions": int(supersession["emissions"]),
        "incident_closure_aspect_writes": int(closure["aspect_writes"]),
    }
    idempotent = (
        source.get("completed_redelivery_datahub_write_performed") is False,
        invalidation.get("redelivery_emissions") == 0,
        replay.get("completed_redelivery_datahub_write_performed") is False,
    )
    relative = path.name if path.parent.name == "compatibility" else path.as_posix()
    return {
        "status": "MEASURED_LIVE_REPORT",
        "source_report": relative,
        "source_report_sha256": hashlib.sha256(raw).hexdigest(),
        "datahub_write_units": {
            "measurement_unit": (
                "adapter-reported proposal emissions or aspect writes; not storage rows"
            ),
            "breakdown": write_units,
            "total": sum(write_units.values()),
        },
        "completed_redelivery_zero_write_rate": _ratio(sum(idempotent), len(idempotent)),
        "negative_control_zero_write_rate": _ratio(
            int(
                negative.get("first_delivery_emissions") == 0
                and negative.get("redelivery_emissions") == 0
            ),
            1,
        ),
        "corrected_replay_success_rate": _ratio(
            int(replay.get("execution_status") == "SUCCEEDED"),
            1,
        ),
        "verified_incident_closure_rate": _ratio(int(closure.get("valid") is True), 1),
    }


def _report_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_BENCHMARK_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:benchmark:sha256:{digest}"


def build_benchmark_report(
    *,
    fixture_path: Path = DEFAULT_FIXTURES,
    live_report_path: Path | None = DEFAULT_LIVE_REPORT,
    performance_samples: int = 0,
    compilation_samples: int = 0,
) -> dict[str, Any]:
    """Build a raw-free benchmark report with exact denominators and failed cases."""

    raw_fixtures, cases = load_cases(fixture_path)
    variants = [_evaluate_variant(cases, ablation) for ablation in Ablation]
    replay = _replay_policy_proof()
    redaction = _redaction_proof()
    correctness_material: dict[str, Any] = {
        "benchmark": BENCHMARK_NAME,
        "contract_version": BENCHMARK_VERSION,
        "fixture_sha256": hashlib.sha256(canonicalize(raw_fixtures)).hexdigest(),
        "case_count": len(cases),
        "variants": variants,
        "replay_policy": replay,
        "redaction": redaction,
    }
    report: dict[str, Any] = {
        "benchmark_id": _report_id(correctness_material),
        **correctness_material,
        "truth_distribution": {
            truth.value: sum(case.truth is truth for case in cases) for truth in Truth
        },
        "primary_result": {
            "selected_variant": Ablation.FULL_GLASSBOX.value,
            "selection_rule": (
                "Minimize missed invalidation, then false invalidation, while requiring "
                "perfect indeterminate-case honesty."
            ),
            "selection_is_model_judged": False,
        },
        "performance": _performance_measurement(
            cases,
            samples=performance_samples,
            compilation_samples=compilation_samples,
        ),
        "live_evidence": _live_evidence(live_report_path),
        "metric_coverage": {
            "asset_resolution_precision_recall": "MEASURED_SYNTHETIC_EXACT",
            "field_resolution_precision_recall": "MEASURED_SYNTHETIC_EXACT",
            "false_and_missed_invalidation": "MEASURED_SYNTHETIC_EXACT",
            "unknown_at_risk_honesty": "MEASURED_SYNTHETIC_EXACT",
            "receipt_compilation_latency": (
                "MEASURED_OFFLINE" if performance_samples else "NOT_MEASURED"
            ),
            "agent_overhead_p50_p95": (
                "MEASURED_OFFLINE" if performance_samples else "NOT_MEASURED"
            ),
            "datahub_write_amplification": (
                "MEASURED_LIVE_REPORT" if live_report_path is not None else "NOT_MEASURED"
            ),
            "idempotent_event_handling": (
                "MEASURED_LIVE_REPORT" if live_report_path is not None else "NOT_MEASURED"
            ),
            "replay_success_and_refusal": (
                "MEASURED_DETERMINISTIC_AND_LIVE"
                if live_report_path is not None
                else "MEASURED_DETERMINISTIC"
            ),
            "secret_redaction_escape": "MEASURED_SYNTHETIC_EXACT",
            "fresh_checkout_setup": "NOT_MEASURED_ON_A_FRESH_HOST",
        },
        "limitations": [
            (
                "Synthetic correctness fixtures measure a closed causal contract, not "
                "production prevalence."
            ),
            (
                "Raw OpenTelemetry means spans without GlassBox-qualified DataHub field "
                "and snapshot attributes."
            ),
            (
                "Offline latency excludes service, network, model-provider, and container "
                "startup time."
            ),
            (
                "The live write unit is an adapter emission/aspect write, not an underlying "
                "database row."
            ),
            (
                "A fresh-host success rate needs independent clean-host repetitions; this "
                "report does not invent it."
            ),
        ],
        "privacy": {
            "synthetic_fixtures_only": True,
            "raw_prompts_retained": False,
            "raw_evidence_retained": False,
            "raw_action_inputs_retained": False,
            "raw_outputs_retained": False,
            "credentials_retained": False,
        },
    }
    return report


def validate_benchmark_report(
    report: Mapping[str, Any], schema_path: Path = DEFAULT_SCHEMA
) -> None:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
        report
    )
    material = {
        key: report[key]
        for key in (
            "benchmark",
            "contract_version",
            "fixture_sha256",
            "case_count",
            "variants",
            "replay_policy",
            "redaction",
        )
    }
    if report.get("benchmark_id") != _report_id(material):
        raise RuntimeError("benchmark report content address does not verify")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-agent-invalidation-benchmark")
    parser.add_argument("--fixtures", type=Path, default=DEFAULT_FIXTURES)
    parser.add_argument("--live-report", type=Path, default=DEFAULT_LIVE_REPORT)
    parser.add_argument("--without-live-report", action="store_true")
    parser.add_argument("--performance-samples", type=int, default=200)
    parser.add_argument("--compilation-samples", type=int, default=20)
    parser.add_argument("--output", type=Path, default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    report = build_benchmark_report(
        fixture_path=args.fixtures,
        live_report_path=None if args.without_live_report else args.live_report,
        performance_samples=args.performance_samples,
        compilation_samples=args.compilation_samples,
    )
    validate_benchmark_report(report)
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
