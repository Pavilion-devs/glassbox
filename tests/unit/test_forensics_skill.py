"""Adversarial evaluations for the distributable DataHub forensics skill."""

from __future__ import annotations

import builtins
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    seal_receipt,
    signing_key_fingerprint,
    signing_key_public_key,
)
from tests.helpers import receipt_payload

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
USED_FIELD = f"urn:li:schemaField:({DATASET},revenue)"
UNUSED_FIELD = f"urn:li:schemaField:({DATASET},internal_note)"
_SKILL_ROOT = Path(__file__).resolve().parents[2] / "skills" / "datahub-agent-forensics"
_TEST_KEY = SigningKey("forensics-evaluation", Ed25519PrivateKey.generate())


def _load_script(name: str) -> ModuleType:
    path = _SKILL_ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"test_{name}", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _signed_receipt() -> dict[str, Any]:
    payload = receipt_payload()
    payload["evidence"][0]["schema_field_urn"] = USED_FIELD
    payload["extensions"] = {"raw_prompt": "SECRET-PROMPT-MUST-NEVER-APPEAR"}
    return seal_receipt(
        payload,
        signing_keys=(_TEST_KEY,),
    )


def _write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")


def _write_trust_policy(
    path: Path,
    *,
    status: SignerStatus = SignerStatus.ACTIVE,
) -> None:
    policy = SignerTrustPolicy(
        policy_id="forensics-skill-evaluation-v1",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=_TEST_KEY.key_id,
                public_key=signing_key_public_key(_TEST_KEY),
                public_key_sha256=signing_key_fingerprint(_TEST_KEY),
                status=status,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )
    _write_json(path, policy.to_dict())


def _change(field_urn: str) -> dict[str, str]:
    return {
        "event_id": "mcl-orders-schema-0001",
        "entity_urn": DATASET,
        "aspect_name": "schemaMetadata",
        "kind": "SCHEMA_FIELD_TYPE_CHANGED",
        "occurred_at": "2026-08-07T00:00:00Z",
        "schema_field_urn": field_urn,
        "before_digest": hashlib.sha256(b"before").hexdigest(),
        "after_digest": hashlib.sha256(b"after").hexdigest(),
    }


def test_signed_dbom_inspection_is_deterministic_and_raw_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = _load_script("inspect_receipt")
    receipt_path = tmp_path / "receipt.json"
    policy_path = tmp_path / "trusted-signers.json"
    _write_json(receipt_path, _signed_receipt())
    _write_trust_policy(policy_path)

    command = [str(receipt_path), "--signer-trust-policy", str(policy_path)]
    assert script.main(command) == 0
    first_text = capsys.readouterr().out
    assert script.main(command) == 0
    second_text = capsys.readouterr().out
    report = json.loads(first_text)

    assert first_text == second_text
    assert report["integrity"]["status"] == "VERIFIED"
    assert report["safe_for_deterministic_policy"] is True
    assert report["evidence_state_counts"] == {"OBSERVED": 1}
    assert report["raw_values_retained"] is False
    assert "SECRET-PROMPT-MUST-NEVER-APPEAR" not in first_text


def test_tampered_and_unsigned_receipts_fail_closed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = _load_script("inspect_receipt")
    policy_path = tmp_path / "trusted-signers.json"
    _write_trust_policy(policy_path)
    tampered = copy.deepcopy(_signed_receipt())
    tampered["output"]["redacted"] = False
    tampered_path = tmp_path / "tampered.json"
    _write_json(tampered_path, tampered)

    assert script.main([str(tampered_path), "--signer-trust-policy", str(policy_path)]) == 1
    tampered_report = json.loads(capsys.readouterr().out)
    assert tampered_report["integrity"]["status"] == "INVALID"
    assert tampered_report["safe_for_deterministic_policy"] is False
    assert {item["code"] for item in tampered_report["findings"]} >= {
        "OUTPUT_NOT_MARKED_REDACTED",
        "RECEIPT_INTEGRITY_INVALID",
    }

    unsigned_path = tmp_path / "unsigned.json"
    payload = receipt_payload()
    payload["evidence"][0]["schema_field_urn"] = USED_FIELD
    _write_json(unsigned_path, seal_receipt(payload))
    assert script.main([str(unsigned_path), "--signer-trust-policy", str(policy_path)]) == 1
    assert json.loads(capsys.readouterr().out)["integrity"]["status"] == "INVALID"
    assert script.main([str(unsigned_path), "--allow-unsigned"]) == 0
    assert json.loads(capsys.readouterr().out)["integrity"]["status"] == "VERIFIED"


def test_raw_receipt_helpers_default_to_admission_not_backdatable_history(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = _load_script("inspect_receipt")
    receipt_path = tmp_path / "retired-receipt.json"
    policy_path = tmp_path / "retired-signers.json"
    _write_json(receipt_path, _signed_receipt())
    _write_trust_policy(policy_path, status=SignerStatus.RETIRED)

    command = [str(receipt_path), "--signer-trust-policy", str(policy_path)]
    assert script.main(command) == 1
    admission = json.loads(capsys.readouterr().out)
    assert "SIGNER_RETIRED" in admission["integrity"]["errors"]

    assert script.main([*command, "--trust-mode", "HISTORICAL"]) == 0
    historical = json.loads(capsys.readouterr().out)
    assert historical["integrity"]["status"] == "VERIFIED"


def test_datahub_projection_is_never_promoted_and_unknown_properties_are_omitted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = _load_script("inspect_receipt")
    document_path = tmp_path / "document.json"
    _write_json(
        document_path,
        {
            "data": {
                "document": {
                    "info": {
                        "customProperties": {
                            "glassbox.receipt_id": "gbx:receipt:sha256:" + "a" * 64,
                            "glassbox.invalidation_state": "STALE",
                            "glassbox.raw_prompt": "SECRET-DATAHUB-PROMPT",
                            "unmanaged.secret": "ALSO-SECRET",
                        }
                    }
                }
            }
        },
    )

    assert script.main([str(document_path)]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)

    assert report["integrity"]["status"] == "PROJECTION_ONLY"
    assert report["safe_for_deterministic_policy"] is False
    assert report["ignored_property_count"] == 1
    assert report["projection"] == {
        "glassbox.invalidation_state": "STALE",
        "glassbox.receipt_id": "gbx:receipt:sha256:" + "a" * 64,
    }
    assert "SECRET-DATAHUB-PROMPT" not in output
    assert "ALSO-SECRET" not in output


@pytest.mark.parametrize(
    ("field_urn", "arguments", "state", "reason_code"),
    [
        (
            USED_FIELD,
            [],
            "STALE",
            "OBSERVED_MATERIAL_DEPENDENCY_CHANGED",
        ),
        (
            UNUSED_FIELD,
            [
                "--field-coverage",
                "COMPLETE",
                "--field-rule",
                "glassbox.sql-column-lineage.v1",
                "--wildcard-query",
                "false",
            ],
            "UNAFFECTED",
            "COMPLETE_FIELD_LINEAGE_PROVES_FIELD_UNUSED",
        ),
        (
            UNUSED_FIELD,
            [
                "--field-coverage",
                "PARTIAL",
                "--field-rule",
                "glassbox.sql-column-lineage.v1",
                "--wildcard-query",
                "false",
            ],
            "AT_RISK",
            "FIELD_LINEAGE_INCOMPLETE_OR_WILDCARD_UNKNOWN",
        ),
    ],
)
def test_canonical_impact_classifier_covers_materiality_boundaries(
    field_urn: str,
    arguments: list[str],
    state: str,
    reason_code: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = _load_script("classify_impact")
    receipt_path = tmp_path / "receipt.json"
    change_path = tmp_path / "change.json"
    policy_path = tmp_path / "trusted-signers.json"
    _write_json(receipt_path, _signed_receipt())
    _write_json(change_path, _change(field_urn))
    _write_trust_policy(policy_path)

    command = [
        str(receipt_path),
        str(change_path),
        "--signer-trust-policy",
        str(policy_path),
        *arguments,
    ]
    assert script.main(command) == 0
    first_text = capsys.readouterr().out
    assert script.main(command) == 0
    second_text = capsys.readouterr().out
    report = json.loads(first_text)

    assert first_text == second_text
    assert report["state"] == state
    assert report["reason_code"] == reason_code
    assert report["policy_version"] == "glassbox.materiality.v1"
    assert report["quarantine_required"] is (state != "UNAFFECTED")


def test_classifier_refuses_to_guess_when_policy_engine_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    script = _load_script("classify_impact")
    receipt_path = tmp_path / "receipt.json"
    change_path = tmp_path / "change.json"
    _write_json(receipt_path, _signed_receipt())
    _write_json(change_path, _change(USED_FIELD))
    real_import = builtins.__import__

    def missing_policy(name: str, *args: object, **kwargs: object) -> object:
        if name == "glassbox_policy":
            raise ImportError("policy engine intentionally hidden")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", missing_policy)

    assert script.main([str(receipt_path), str(change_path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "refusing to guess impact" in captured.err
