#!/usr/bin/env python3
"""Produce a deterministic, raw-value-free forensic projection of a DBOM or Document."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

_SAFE_PROJECTION_PROPERTIES = frozenset(
    {
        "glassbox.action_count",
        "glassbox.agent_id",
        "glassbox.agent_urn",
        "glassbox.compatibility_mode",
        "glassbox.evidence_count",
        "glassbox.invalidation_campaign_id",
        "glassbox.invalidation_campaign_urn",
        "glassbox.invalidation_change_event_id",
        "glassbox.invalidation_change_kind",
        "glassbox.invalidation_changed_entity_urn",
        "glassbox.invalidation_policy_version",
        "glassbox.invalidation_reason_code",
        "glassbox.invalidation_state",
        "glassbox.invalidated_at",
        "glassbox.merkle_root",
        "glassbox.native_entity_type",
        "glassbox.output_digest",
        "glassbox.payload_digest",
        "glassbox.receipt_id",
        "glassbox.referenced_urns",
        "glassbox.replay_bundle_id",
        "glassbox.replay_diff_id",
        "glassbox.replay_eligibility",
        "glassbox.replay_execution_id",
        "glassbox.replay_plan_id",
        "glassbox.replay_receipt_id",
        "glassbox.replay_receipt_urn",
        "glassbox.replay_semantic_result",
        "glassbox.replay_structural_change_count",
        "glassbox.run_id",
        "glassbox.run_status",
        "glassbox.signature_count",
        "glassbox.source_receipt_id",
        "glassbox.source_receipt_urn",
        "glassbox.spec_version",
        "glassbox.superseded_by",
        "glassbox.supersession_created_at",
        "glassbox.supersession_id",
        "glassbox.supersession_policy_version",
        "glassbox.supersession_relation",
        "glassbox.trace_id",
    }
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="inspect_receipt.py")
    parser.add_argument("input", type=Path)
    parser.add_argument("--allow-unsigned", action="store_true")
    parser.add_argument(
        "--signer-trust-policy",
        type=Path,
        default=_trust_path_from_environment(),
    )
    parser.add_argument(
        "--trust-mode",
        choices=("ADMISSION", "HISTORICAL"),
        default="ADMISSION",
        help="use HISTORICAL only for receipts obtained from trusted admitted state",
    )
    parser.add_argument("--allow-untrusted-signers", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    return parser


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError("input must contain a JSON object")
    return value


def _verify(
    receipt: Mapping[str, Any],
    *,
    allow_unsigned: bool,
    signer_trust_policy: Path | None,
    allow_untrusted_signers: bool,
    trust_mode: str,
) -> dict[str, Any]:
    try:
        from glassbox_dbom import (
            SignerTrustMode,
            load_signer_trust_policy,
            verify_receipt,
        )
    except ImportError:
        return {
            "status": "NOT_VERIFIED",
            "valid": None,
            "reason": "glassbox_dbom verifier is unavailable",
            "errors": [],
        }
    if signer_trust_policy is not None:
        if allow_unsigned:
            raise ValueError("--allow-unsigned cannot be combined with a signer trust policy")
        trust = load_signer_trust_policy(signer_trust_policy).verify_receipt(
            receipt,
            mode=SignerTrustMode(trust_mode),
        )
        report = trust.integrity
        valid = trust.valid
        errors = list(trust.failure_codes)
        trust_policy = True
        trusted_signature_count: int | None = trust.trusted_signature_count
        minimum_trusted_signatures: int | None = trust.minimum_trusted_signatures
    else:
        if not allow_unsigned and not allow_untrusted_signers:
            raise ValueError(
                "a signer trust policy is required; use --allow-untrusted-signers "
                "only for development"
            )
        report = verify_receipt(receipt, require_signature=not allow_unsigned)
        valid = report.valid
        errors = list(report.errors)
        trust_policy = False
        trusted_signature_count = None
        minimum_trusted_signatures = None
    return {
        "status": "VERIFIED" if valid else "INVALID",
        "valid": valid,
        "reason": None,
        "payload_digest_valid": report.payload_digest_valid,
        "receipt_id_valid": report.receipt_id_valid,
        "merkle_root_valid": report.merkle_root_valid,
        "trusted_signer_policy": trust_policy,
        "trusted_signature_count": trusted_signature_count,
        "minimum_trusted_signatures": minimum_trusted_signatures,
        "errors": errors,
    }


def _receipt_report(
    receipt: Mapping[str, Any],
    *,
    allow_unsigned: bool,
    signer_trust_policy: Path | None,
    allow_untrusted_signers: bool,
    trust_mode: str,
) -> dict[str, Any]:
    integrity = _mapping(receipt, "integrity")
    run = _mapping(receipt, "run")
    replay = _mapping(receipt, "replay")
    output = _mapping(receipt, "output")
    evidence = _mapping_items(receipt, "evidence")
    actions = _mapping_items(receipt, "actions")
    signatures = _mapping_items(integrity, "signatures")
    verification = _verify(
        receipt,
        allow_unsigned=allow_unsigned,
        signer_trust_policy=signer_trust_policy,
        allow_untrusted_signers=allow_untrusted_signers,
        trust_mode=trust_mode,
    )
    findings: list[dict[str, str]] = []
    if verification["status"] == "INVALID":
        findings.append(_finding("CRITICAL", "RECEIPT_INTEGRITY_INVALID"))
    elif verification["status"] == "NOT_VERIFIED":
        findings.append(_finding("WARNING", "RECEIPT_INTEGRITY_NOT_VERIFIED"))
    if not signatures:
        findings.append(_finding("WARNING", "NO_RECEIPT_SIGNATURE"))

    evidence_projection = []
    for item in evidence:
        state = _optional_text(item, "state") or "UNKNOWN"
        if state == "UNKNOWN":
            findings.append(_finding("ERROR", "UNKNOWN_EVIDENCE_STATE"))
        elif state == "DECLARED":
            findings.append(_finding("INFO", "DECLARED_DEPENDENCY_NOT_OBSERVED"))
        elif state == "INFERRED":
            findings.append(_finding("INFO", "INFERRED_DEPENDENCY_REQUIRES_RULE_REVIEW"))
        evidence_projection.append(
            {
                "evidence_id": _optional_text(item, "evidence_id"),
                "datahub_urn": _optional_text(item, "datahub_urn"),
                "schema_field_urn": _optional_text(item, "schema_field_urn"),
                "state": state,
                "role": _optional_text(item, "role"),
                "observed_at": _optional_text(item, "observed_at"),
                "representation_digest": _digest_value(item.get("representation_digest")),
            }
        )

    action_projection = []
    for item in actions:
        effect = _optional_text(item, "effect") or "UNKNOWN_EFFECT"
        status = _optional_text(item, "status") or "UNKNOWN"
        approval_id = _optional_text(item, "approval_id")
        if effect == "IRREVERSIBLE":
            findings.append(_finding("CRITICAL", "IRREVERSIBLE_ACTION_RECORDED"))
        elif effect == "UNKNOWN_EFFECT":
            findings.append(_finding("ERROR", "UNKNOWN_ACTION_EFFECT"))
        if status in {"ATTEMPTED", "PLANNED"}:
            findings.append(_finding("ERROR", "ACTION_OUTCOME_UNCERTAIN"))
        elif status in {"FAILED", "BLOCKED"}:
            findings.append(_finding("ERROR", "ACTION_NOT_SUCCESSFUL"))
        if effect in {"REVERSIBLE", "IRREVERSIBLE"} and approval_id is None:
            findings.append(_finding("ERROR", "MUTATING_ACTION_WITHOUT_RECORDED_APPROVAL"))
        action_projection.append(
            {
                "action_id": _optional_text(item, "action_id"),
                "tool_id": _optional_text(item, "tool_id"),
                "effect": effect,
                "status": status,
                "approval_id": approval_id,
                "input_digest": _digest_value(item.get("input_digest")),
                "output_digest": _digest_value(item.get("output_digest")),
            }
        )

    if output.get("redacted") is not True:
        findings.append(_finding("WARNING", "OUTPUT_NOT_MARKED_REDACTED"))
    counts: dict[str, int] = {}
    for item in evidence_projection:
        state = str(item["state"])
        counts[state] = counts.get(state, 0) + 1
    return {
        "report_version": "datahub-agent-forensics.v1",
        "target": {
            "kind": "DBOM_RECEIPT",
            "receipt_id": _optional_text(receipt, "receipt_id"),
            "spec_version": _optional_text(receipt, "spec_version"),
        },
        "integrity": verification,
        "safe_for_deterministic_policy": verification["valid"] is True,
        "run": {
            "run_id": _optional_text(run, "run_id"),
            "status": _optional_text(run, "status"),
            "started_at": _optional_text(run, "started_at"),
            "ended_at": _optional_text(run, "ended_at"),
            "environment": _optional_text(run, "environment"),
        },
        "evidence": evidence_projection,
        "evidence_state_counts": dict(sorted(counts.items())),
        "actions": action_projection,
        "output": {
            "kind": _optional_text(output, "kind"),
            "mime_type": _optional_text(output, "mime_type"),
            "digest": _digest_value(output.get("digest")),
            "redacted": output.get("redacted"),
        },
        "replay": {
            "eligibility": _optional_text(replay, "eligibility"),
            "reason": _optional_text(replay, "reason"),
            "prior_receipt_digest": _digest_value(replay.get("prior_receipt_digest")),
        },
        "findings": _sorted_findings(findings),
        "raw_values_retained": False,
    }


def _document_report(document: Mapping[str, Any]) -> dict[str, Any]:
    properties = _find_custom_properties(document)
    managed = {
        key: value
        for key, value in properties.items()
        if key in _SAFE_PROJECTION_PROPERTIES and isinstance(value, str)
    }
    ignored = sum(
        1
        for key in properties
        if isinstance(key, str)
        and key.startswith("glassbox.")
        and key not in _SAFE_PROJECTION_PROPERTIES
    )
    receipt_id = managed.get("glassbox.receipt_id")
    findings = [_finding("WARNING", "DATAHUB_PROJECTION_IS_NOT_A_SIGNED_DBOM")]
    if receipt_id is None:
        findings.append(_finding("ERROR", "DATAHUB_DOCUMENT_HAS_NO_RECEIPT_ID"))
    if ignored:
        findings.append(_finding("INFO", "UNRECOGNIZED_GLASSBOX_PROPERTIES_OMITTED"))
    return {
        "report_version": "datahub-agent-forensics.v1",
        "target": {
            "kind": "DATAHUB_DOCUMENT_PROJECTION",
            "receipt_id": receipt_id,
        },
        "integrity": {
            "status": "PROJECTION_ONLY",
            "valid": None,
            "reason": "Fetch the signed DBOM artifact to verify integrity and Merkle commitments.",
            "errors": [],
        },
        "safe_for_deterministic_policy": False,
        "projection": dict(sorted(managed.items())),
        "ignored_property_count": ignored,
        "findings": _sorted_findings(findings),
        "raw_values_retained": False,
    }


def _find_custom_properties(value: object) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        for key in ("customProperties", "custom_properties"):
            candidate = value.get(key)
            if isinstance(candidate, Mapping):
                return candidate
        for child in value.values():
            found = _find_custom_properties(child)
            if found:
                return found
    elif isinstance(value, list):
        for child in value:
            found = _find_custom_properties(child)
            if found:
                return found
    return {}


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    return selected if isinstance(selected, Mapping) else {}


def _mapping_items(value: Mapping[str, Any], key: str) -> tuple[Mapping[str, Any], ...]:
    selected = value.get(key)
    if not isinstance(selected, list):
        return ()
    return tuple(item for item in selected if isinstance(item, Mapping))


def _optional_text(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    return selected if isinstance(selected, str) and selected else None


def _digest_value(value: object) -> str | None:
    if not isinstance(value, Mapping):
        return None
    selected = value.get("value")
    return selected if isinstance(selected, str) else None


def _finding(severity: str, code: str) -> dict[str, str]:
    return {"severity": severity, "code": code}


def _sorted_findings(findings: Sequence[dict[str, str]]) -> list[dict[str, str]]:
    rank = {"CRITICAL": 0, "ERROR": 1, "WARNING": 2, "INFO": 3}
    unique = {(item["severity"], item["code"]) for item in findings}
    return [
        {"severity": severity, "code": code}
        for severity, code in sorted(unique, key=lambda item: (rank[item[0]], item[1]))
    ]


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        value = _load(args.input)
        report = (
            _receipt_report(
                value,
                allow_unsigned=args.allow_unsigned,
                signer_trust_policy=args.signer_trust_policy,
                allow_untrusted_signers=args.allow_untrusted_signers,
                trust_mode=args.trust_mode,
            )
            if "receipt_id" in value
            else _document_report(value)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"inspect_receipt.py: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 1 if report["integrity"]["status"] == "INVALID" else 0


def _trust_path_from_environment() -> Path | None:
    value = os.getenv("GLASSBOX_SIGNER_TRUST_POLICY_PATH")
    return Path(value) if value else None


if __name__ == "__main__":
    raise SystemExit(main())
