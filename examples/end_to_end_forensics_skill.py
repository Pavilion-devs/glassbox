"""Live proof: investigate a signed agent receipt through DataHub Core and the Skill."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from examples.replay_read_only import build_replay_artifacts

from glassbox_datahub import DataHubReceiptBackend, ReceiptEmitter
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_dbom import SigningKey, seal_receipt, verify_receipt

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
USED_FIELD_URN = f"urn:li:schemaField:({DATASET_URN},revenue)"
UNUSED_FIELD_URN = f"urn:li:schemaField:({DATASET_URN},internal_note)"
_ROOT = Path(__file__).parents[1]
_SKILL_SCRIPTS = _ROOT / "skills" / "datahub-agent-forensics" / "scripts"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-agent-forensics")
    parser.add_argument("--server", default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    parser.add_argument(
        "--datahub-cli",
        type=Path,
        default=Path(sys.executable).with_name("datahub"),
    )
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    return parser


def build_forensics_receipt() -> dict[str, Any]:
    """Build a signed field-precise DBOM without changing the replay proof fixture."""

    source = build_replay_artifacts().source_receipt
    payload = copy.deepcopy(source)
    payload.pop("receipt_id")
    payload.pop("integrity")
    payload["run"]["run_id"] = "forensics-live-run-001"
    payload["run"]["trace_id"] = "fedcba9876543210fedcba9876543210"
    payload["evidence"][0]["schema_field_urn"] = USED_FIELD_URN
    return seal_receipt(
        payload,
        signing_keys=(SigningKey("forensics-live-ephemeral", Ed25519PrivateKey.generate()),),
    )


def _change(event_id: str, field_urn: str) -> dict[str, str]:
    return {
        "event_id": event_id,
        "entity_urn": DATASET_URN,
        "aspect_name": "schemaMetadata",
        "kind": "SCHEMA_FIELD_TYPE_CHANGED",
        "occurred_at": "2026-08-07T00:00:00Z",
        "schema_field_urn": field_urn,
        "before_digest": hashlib.sha256(b"forensics-before").hexdigest(),
        "after_digest": hashlib.sha256(b"forensics-after").hexdigest(),
    }


def _run_json(
    command: Sequence[str],
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=dict(environment) if environment is not None else None,
    )
    if completed.returncode != 0:
        error = completed.stderr.strip() or "command returned no error details"
        raise RuntimeError(f"forensic command failed with status {completed.returncode}: {error}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("forensic command did not return JSON") from exc
    if not isinstance(value, dict):
        raise RuntimeError("forensic command JSON root was not an object")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    receipt = build_forensics_receipt()
    receipt_verification = verify_receipt(receipt, require_signature=True)
    if not receipt_verification.valid:
        raise RuntimeError("forensics receipt failed local verification before live writes")

    backend = DataHubReceiptBackend(server=server, token=args.token)
    backend.test_connection()
    emission = ReceiptEmitter(backend).emit_verified(receipt)
    cli_environment = os.environ.copy()
    cli_environment["DATAHUB_GMS_URL"] = server
    if args.token is not None:
        cli_environment["DATAHUB_GMS_TOKEN"] = args.token

    with tempfile.TemporaryDirectory(prefix="glassbox-forensics-") as temporary:
        temporary_path = Path(temporary)
        receipt_path = temporary_path / "receipt.json"
        document_path = temporary_path / "document.json"
        used_change_path = temporary_path / "used-change.json"
        unused_change_path = temporary_path / "unused-change.json"
        _write_json(receipt_path, receipt)
        _write_json(used_change_path, _change("forensics-live-used-field-v1", USED_FIELD_URN))
        _write_json(
            unused_change_path,
            _change("forensics-live-unused-field-v1", UNUSED_FIELD_URN),
        )

        document = _run_json(
            (
                str(args.datahub_cli),
                "-C",
                "skill=datahub-agent-forensics",
                "get",
                "--urn",
                emission.document_urn,
            ),
            environment=cli_environment,
        )
        _write_json(document_path, document)
        dbom_report = _run_json(
            (
                sys.executable,
                str(_SKILL_SCRIPTS / "inspect_receipt.py"),
                str(receipt_path),
            )
        )
        projection_report = _run_json(
            (
                sys.executable,
                str(_SKILL_SCRIPTS / "inspect_receipt.py"),
                str(document_path),
            )
        )
        used_assessment = _run_json(
            (
                sys.executable,
                str(_SKILL_SCRIPTS / "classify_impact.py"),
                str(receipt_path),
                str(used_change_path),
            )
        )
        unused_assessment = _run_json(
            (
                sys.executable,
                str(_SKILL_SCRIPTS / "classify_impact.py"),
                str(receipt_path),
                str(unused_change_path),
                "--field-coverage",
                "COMPLETE",
                "--field-rule",
                "glassbox.sql-column-lineage.v1",
                "--wildcard-query",
                "false",
            )
        )

    valid = (
        emission.valid
        and dbom_report["integrity"]["status"] == "VERIFIED"
        and dbom_report["safe_for_deterministic_policy"] is True
        and dbom_report["raw_values_retained"] is False
        and projection_report["integrity"]["status"] == "PROJECTION_ONLY"
        and projection_report["safe_for_deterministic_policy"] is False
        and projection_report["target"]["receipt_id"] == receipt["receipt_id"]
        and used_assessment["state"] == "STALE"
        and used_assessment["reason_code"] == "OBSERVED_MATERIAL_DEPENDENCY_CHANGED"
        and unused_assessment["state"] == "UNAFFECTED"
        and unused_assessment["reason_code"] == "COMPLETE_FIELD_LINEAGE_PROVES_FIELD_UNUSED"
    )
    report = {
        "valid": valid,
        "compatibility": {
            "server": server,
            "datahub_core_target": "1.6.0",
            "sdk_version": backend.sdk_version,
            "datahub_cli_context": "skill=datahub-agent-forensics",
        },
        "live_write": emission.to_dict(),
        "direct_cli_read": {
            "valid": projection_report["target"]["receipt_id"] == receipt["receipt_id"],
            "document_urn": emission.document_urn,
            "integrity_status": projection_report["integrity"]["status"],
            "safe_for_deterministic_policy": projection_report["safe_for_deterministic_policy"],
            "managed_property_count": len(projection_report["projection"]),
            "ignored_property_count": projection_report["ignored_property_count"],
        },
        "signed_dbom": {
            "receipt_id": receipt["receipt_id"],
            "integrity_status": dbom_report["integrity"]["status"],
            "safe_for_deterministic_policy": dbom_report["safe_for_deterministic_policy"],
            "evidence_state_counts": dbom_report["evidence_state_counts"],
            "raw_values_retained": dbom_report["raw_values_retained"],
        },
        "used_field_control": used_assessment,
        "unrelated_field_control": unused_assessment,
        "boundaries": {
            "change_events_are_synthetic_normalized_inputs": True,
            "datahub_mutations": 2,
            "unique_datahub_documents_written": 1,
            "quarantine_or_replay_mutations": 0,
            "plaintext_receipt_values_retained": False,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
