#!/usr/bin/env python3
"""Classify one verified receipt with the canonical GlassBox materiality engine."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="classify_impact.py")
    parser.add_argument("receipt", type=Path)
    parser.add_argument("change", type=Path)
    parser.add_argument(
        "--field-coverage",
        choices=("NONE", "PARTIAL", "COMPLETE"),
        default="NONE",
    )
    parser.add_argument("--field-rule")
    parser.add_argument(
        "--wildcard-query",
        choices=("true", "false", "unknown"),
        default="unknown",
    )
    parser.add_argument("--superseded-by")
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


def _object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        from glassbox_dbom import SignerTrustMode, load_signer_trust_policy
        from glassbox_policy import (
            ChangeKind,
            FieldCoverage,
            FieldLineageProof,
            NormalizedChange,
            ReceiptDependencyProfile,
            classify_materiality,
        )
    except ImportError:
        print(
            "classify_impact.py: glassbox_policy is required; refusing to guess impact",
            file=sys.stderr,
        )
        return 2
    try:
        receipt = _object(args.receipt)
        change_value = _object(args.change)
        wildcard = {"true": True, "false": False, "unknown": None}[args.wildcard_query]
        lineage = FieldLineageProof(
            coverage=FieldCoverage(args.field_coverage),
            rule_id=args.field_rule,
            wildcard_query=wildcard,
        )
        if args.signer_trust_policy is None and not (
            args.allow_unsigned or args.allow_untrusted_signers
        ):
            raise ValueError(
                "a signer trust policy is required; use --allow-untrusted-signers "
                "only for development"
            )
        if args.signer_trust_policy is not None and args.allow_unsigned:
            raise ValueError("--allow-unsigned cannot be combined with a signer trust policy")
        signer_trust_policy = (
            load_signer_trust_policy(args.signer_trust_policy)
            if args.signer_trust_policy is not None
            else None
        )
        profile = ReceiptDependencyProfile.from_receipt(
            receipt,
            field_lineage=lineage,
            superseded_by=args.superseded_by,
            require_signature=not args.allow_unsigned,
            signer_trust_policy=signer_trust_policy,
            signer_trust_mode=SignerTrustMode(args.trust_mode),
        )
        change = NormalizedChange(
            event_id=_text(change_value, "event_id"),
            entity_urn=_text(change_value, "entity_urn"),
            aspect_name=_text(change_value, "aspect_name"),
            kind=ChangeKind(_text(change_value, "kind")),
            occurred_at=_text(change_value, "occurred_at"),
            schema_field_urn=_optional_text(change_value, "schema_field_urn"),
            before_digest=_optional_text(change_value, "before_digest"),
            after_digest=_optional_text(change_value, "after_digest"),
        )
        assessment = classify_materiality(profile, change)
        report = {
            "report_version": "datahub-agent-forensics.impact.v1",
            "receipt_id": assessment.receipt_id,
            "document_urn": assessment.document_urn,
            "state": assessment.state.value,
            "reason_code": assessment.reason_code,
            "matched_evidence_ids": list(assessment.matched_evidence_ids),
            "policy_version": assessment.policy_version,
            "quarantine_required": assessment.quarantine_required,
            "change": {
                "event_id": change.event_id,
                "entity_urn": change.entity_urn,
                "schema_field_urn": change.schema_field_urn,
                "kind": change.kind.value,
                "occurred_at": change.occurred_at,
            },
            "field_lineage": {
                "coverage": lineage.coverage.value,
                "rule_id": lineage.rule_id,
                "wildcard_query": lineage.wildcard_query,
            },
        }
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"classify_impact.py: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2 if args.pretty else None, sort_keys=True))
    return 0


def _text(value: dict[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ValueError(f"{key} must be a non-empty string")
    return selected


def _optional_text(value: dict[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is not None and (not isinstance(selected, str) or not selected):
        raise ValueError(f"{key} must be null or a non-empty string")
    return selected


def _trust_path_from_environment() -> Path | None:
    value = os.getenv("GLASSBOX_SIGNER_TRUST_POLICY_PATH")
    return Path(value) if value else None


if __name__ == "__main__":
    raise SystemExit(main())
