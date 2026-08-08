"""Command-line interface for independent DBOM verification."""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from glassbox_dbom.errors import DBOMError
from glassbox_dbom.integrity import verify_receipt
from glassbox_dbom.trust import (
    SignerStatus,
    SignerTrustMode,
    TrustedSigner,
    load_signer_trust_policy,
    signing_key_fingerprint,
    signing_key_from_base64url,
    signing_key_public_key,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glassbox-dbom",
        description="Validate and independently verify a GlassBox DBOM receipt.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify", help="verify schema and integrity material")
    verify.add_argument("receipt", type=Path)
    verify.add_argument(
        "--require-signature",
        action="store_true",
        help="fail unsigned receipts even when all other integrity checks pass",
    )
    verify.add_argument(
        "--signer-trust-policy",
        type=Path,
        help="verify operator signer trust using the normative policy JSON",
    )
    verify.add_argument(
        "--trust-mode",
        choices=[item.value for item in SignerTrustMode],
        default=SignerTrustMode.ADMISSION.value,
        help=(
            "default to current-time admission; use HISTORICAL only when prior "
            "trusted admission is independently established"
        ),
    )
    verify.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="emit a stable JSON report",
    )
    policy = subparsers.add_parser(
        "verify-policy",
        help="validate a trusted-signer registry without loading a private key",
    )
    policy.add_argument("policy", type=Path)
    entry = subparsers.add_parser(
        "signer-entry",
        help="derive a policy-ready public signer entry from an environment-indirect key",
    )
    entry.add_argument("--key-id", required=True)
    entry.add_argument("--private-key-env", required=True)
    entry.add_argument("--not-before", required=True)
    entry.add_argument("--not-after")
    entry.add_argument(
        "--status",
        choices=[item.value for item in SignerStatus],
        default=SignerStatus.ACTIVE.value,
    )
    return parser


def _load_receipt(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise ValueError("receipt root must be a JSON object")
    return loaded


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "verify-policy":
        return _verify_policy_command(args.policy)
    if args.command == "signer-entry":
        return _signer_entry_command(args)
    try:
        receipt = _load_receipt(args.receipt)
        if args.signer_trust_policy is not None:
            trust_report = load_signer_trust_policy(args.signer_trust_policy).verify_receipt(
                receipt,
                mode=SignerTrustMode(args.trust_mode),
            )
            valid = trust_report.valid
            signature_count = len(trust_report.signatures)
            errors = trust_report.failure_codes
            report_dict = trust_report.to_dict()
        else:
            integrity_report = verify_receipt(
                receipt,
                require_signature=args.require_signature,
            )
            valid = integrity_report.valid
            signature_count = len(integrity_report.signatures)
            errors = integrity_report.errors
            report_dict = integrity_report.to_dict()
    except (OSError, json.JSONDecodeError, ValueError, DBOMError) as exc:
        print(f"glassbox-dbom: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(report_dict, indent=2, sort_keys=True))
    elif valid:
        trust_label = " trusted" if args.signer_trust_policy is not None else ""
        print(f"VALID: {args.receipt} ({signature_count}{trust_label} signature(s))")
    else:
        print(f"INVALID: {args.receipt}", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
    return 0 if valid else 1


def _verify_policy_command(path: Path) -> int:
    try:
        policy = load_signer_trust_policy(path)
    except (OSError, ValueError, DBOMError) as exc:
        print(f"glassbox-dbom: {exc}", file=sys.stderr)
        return 2
    counts = Counter(item.status.value for item in policy.signers)
    print(
        json.dumps(
            {
                "valid": True,
                "schema_version": policy.schema_version,
                "policy_id": policy.policy_id,
                "minimum_trusted_signatures": policy.minimum_trusted_signatures,
                "signer_count": len(policy.signers),
                "status_counts": {key: counts[key] for key in sorted(counts)},
                "signers": [
                    {
                        "key_id": item.key_id,
                        "public_key_sha256": item.public_key_sha256,
                        "status": item.status.value,
                        "not_before": item.not_before,
                        "not_after": item.not_after,
                    }
                    for item in policy.signers
                ],
                "public_keys_returned": False,
                "private_keys_returned": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _signer_entry_command(args: argparse.Namespace) -> int:
    try:
        encoded = os.getenv(args.private_key_env)
        if encoded is None or not encoded:
            raise ValueError("configured private-key environment variable is unset")
        signing_key = signing_key_from_base64url(args.key_id, encoded)
        signer = TrustedSigner(
            key_id=signing_key.key_id,
            public_key=signing_key_public_key(signing_key),
            public_key_sha256=signing_key_fingerprint(signing_key),
            status=SignerStatus(args.status),
            not_before=args.not_before,
            not_after=args.not_after,
        )
    except (ValueError, DBOMError) as exc:
        print(f"glassbox-dbom: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "valid": True,
                "signer": {
                    "key_id": signer.key_id,
                    "public_key": signer.public_key,
                    "public_key_sha256": signer.public_key_sha256,
                    "status": signer.status.value,
                    "not_before": signer.not_before,
                    "not_after": signer.not_after,
                },
                "private_key_returned": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
