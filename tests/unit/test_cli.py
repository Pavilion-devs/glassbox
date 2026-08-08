from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
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
from glassbox_dbom.cli import main
from tests.helpers import receipt_payload


def _write_receipt(path: Path, receipt: dict[str, object]) -> None:
    path.write_text(json.dumps(receipt), encoding="utf-8")


def test_cli_returns_zero_for_valid_receipt(tmp_path: Path, capsys: object) -> None:
    receipt_path = tmp_path / "receipt.json"
    _write_receipt(receipt_path, seal_receipt(receipt_payload()))

    result = main(["verify", str(receipt_path), "--json"])

    assert result == 0


def test_cli_human_output_reports_valid_receipt(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt_path = tmp_path / "receipt.json"
    _write_receipt(receipt_path, seal_receipt(receipt_payload()))

    assert main(["verify", str(receipt_path)]) == 0
    assert "VALID:" in capsys.readouterr().out


def test_cli_returns_one_for_tampered_receipt(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt = seal_receipt(receipt_payload())
    receipt["run"]["status"] = "FAILED"
    _write_receipt(receipt_path, receipt)

    assert main(["verify", str(receipt_path)]) == 1


def test_cli_returns_two_for_invalid_json(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("not JSON", encoding="utf-8")

    assert main(["verify", str(receipt_path)]) == 2


def test_cli_returns_two_when_json_root_is_not_an_object(tmp_path: Path) -> None:
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text("[]", encoding="utf-8")

    assert main(["verify", str(receipt_path)]) == 2


def test_cli_distinguishes_operator_trust_from_self_signature(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trusted = SigningKey("trusted", Ed25519PrivateKey.generate())
    unknown = SigningKey("unknown", Ed25519PrivateKey.generate())
    receipt_path = tmp_path / "receipt.json"
    policy_path = tmp_path / "trusted-signers.json"
    _write_receipt(
        receipt_path,
        seal_receipt(receipt_payload(), signing_keys=(unknown,)),
    )
    policy = SignerTrustPolicy(
        policy_id="cli-trust-v1",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=trusted.key_id,
                public_key=signing_key_public_key(trusted),
                public_key_sha256=signing_key_fingerprint(trusted),
                status=SignerStatus.ACTIVE,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )
    policy_path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")

    assert main(["verify", str(receipt_path), "--require-signature"]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "verify",
                str(receipt_path),
                "--signer-trust-policy",
                str(policy_path),
                "--json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert report["integrity"]["valid"] is True
    assert report["valid"] is False
    assert "UNKNOWN_KEY_ID" in report["failure_codes"]


def test_cli_defaults_raw_receipts_to_admission_and_requires_explicit_history(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    key = SigningKey("retired-cli-key", Ed25519PrivateKey.generate())
    receipt_path = tmp_path / "retired-receipt.json"
    policy_path = tmp_path / "retired-signers.json"
    _write_receipt(receipt_path, seal_receipt(receipt_payload(), signing_keys=(key,)))
    policy = SignerTrustPolicy(
        policy_id="cli-retired-trust-v1",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=key.key_id,
                public_key=signing_key_public_key(key),
                public_key_sha256=signing_key_fingerprint(key),
                status=SignerStatus.RETIRED,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )
    policy_path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")
    base = [
        "verify",
        str(receipt_path),
        "--signer-trust-policy",
        str(policy_path),
        "--json",
    ]

    assert main(base) == 1
    admission = json.loads(capsys.readouterr().out)
    assert admission["mode"] == "ADMISSION"
    assert "SIGNER_RETIRED" in admission["failure_codes"]

    assert main([*base, "--trust-mode", "HISTORICAL"]) == 0
    historical = json.loads(capsys.readouterr().out)
    assert historical["mode"] == "HISTORICAL"
    assert historical["valid"] is True


def test_cli_derives_public_enrollment_and_verifies_policy_without_returning_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    private = Ed25519PrivateKey.generate()
    encoded = (
        base64.urlsafe_b64encode(
            private.private_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PrivateFormat.Raw,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        .rstrip(b"=")
        .decode()
    )
    monkeypatch.setenv("GLASSBOX_TEST_ENROLLMENT_KEY", encoded)

    assert (
        main(
            [
                "signer-entry",
                "--key-id",
                "rotation-2026-08",
                "--private-key-env",
                "GLASSBOX_TEST_ENROLLMENT_KEY",
                "--not-before",
                "2026-08-01T00:00:00Z",
                "--not-after",
                "2026-09-01T00:00:00Z",
            ]
        )
        == 0
    )
    enrollment_text = capsys.readouterr().out
    enrollment = json.loads(enrollment_text)
    assert enrollment["private_key_returned"] is False
    assert encoded not in enrollment_text

    policy_path = tmp_path / "trusted-signers.json"
    policy_path.write_text(
        json.dumps(
            {
                "schema_version": "glassbox.signer-trust.v1",
                "policy_id": "cli-enrollment-test-v1",
                "minimum_trusted_signatures": 1,
                "signers": [enrollment["signer"]],
            }
        ),
        encoding="utf-8",
    )
    assert main(["verify-policy", str(policy_path)]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["valid"] is True
    assert verified["public_keys_returned"] is False
    assert verified["private_keys_returned"] is False
