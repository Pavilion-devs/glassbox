from __future__ import annotations

import copy
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import glassbox_dbom.trust as trust_module
from glassbox_dbom import (
    SignerAdmissionEvidence,
    SignerStatus,
    SignerTrustError,
    SignerTrustMode,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    load_signer_trust_policy,
    load_signer_trust_schema,
    seal_receipt,
    signing_key_fingerprint,
    signing_key_from_base64url,
    signing_key_public_key,
)
from tests.helpers import receipt_payload

_DURING_RUN = datetime(2026, 8, 6, 0, 0, 2, tzinfo=UTC)
_AFTER_RUN = datetime(2026, 8, 7, 0, 0, 0, tzinfo=UTC)


def _key(key_id: str = "receipt-key-2026-08") -> SigningKey:
    return SigningKey(key_id, Ed25519PrivateKey.generate())


def _trusted(
    key: SigningKey,
    *,
    status: SignerStatus = SignerStatus.ACTIVE,
    not_before: str = "2026-08-01T00:00:00Z",
    not_after: str | None = "2026-09-01T00:00:00Z",
) -> TrustedSigner:
    return TrustedSigner(
        key_id=key.key_id,
        public_key=signing_key_public_key(key),
        public_key_sha256=signing_key_fingerprint(key),
        status=status,
        not_before=not_before,
        not_after=not_after,
    )


def _policy(
    *signers: TrustedSigner,
    minimum: int = 1,
) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id="glassbox-production-receipts-v1",
        minimum_trusted_signatures=minimum,
        signers=tuple(signers),
    )


def test_operator_trusted_active_signature_is_admitted() -> None:
    key = _key()
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))

    report = _policy(_trusted(key)).verify_receipt(
        receipt,
        mode=SignerTrustMode.ADMISSION,
        evaluated_at=_AFTER_RUN,
    )

    assert report.valid
    assert report.trusted_signature_count == 1
    assert report.failure_codes == ()
    assert report.signatures[0].public_key_sha256 == signing_key_fingerprint(key)
    assert all("public_key" not in item for item in report.to_dict()["signatures"])

    admission = SignerAdmissionEvidence.from_report(report)
    assert SignerAdmissionEvidence.from_dict(admission.to_dict()) == admission
    admission.verify_receipt_binding(receipt)


def test_signer_admission_evidence_cannot_be_forged_for_another_receipt() -> None:
    trusted = _key("trusted")
    other = _key("other")
    receipt = seal_receipt(receipt_payload(), signing_keys=(trusted,))
    report = _policy(_trusted(trusted)).verify_receipt(
        receipt,
        evaluated_at=_AFTER_RUN,
    )
    admission = SignerAdmissionEvidence.from_report(report)
    other_receipt = seal_receipt(receipt_payload(), signing_keys=(other,))

    with pytest.raises(SignerTrustError, match="not bound"):
        admission.verify_receipt_binding(other_receipt)


def test_mathematically_valid_self_signature_is_not_a_trust_anchor() -> None:
    trusted_key = _key("trusted")
    attacker_key = _key("attacker-controlled")
    receipt = seal_receipt(receipt_payload(), signing_keys=(attacker_key,))

    report = _policy(_trusted(trusted_key)).verify_receipt(
        receipt,
        evaluated_at=_AFTER_RUN,
    )

    assert report.integrity.valid
    assert not report.valid
    assert report.signatures[0].reason.value == "UNKNOWN_KEY_ID"
    assert "TRUSTED_SIGNATURE_THRESHOLD_NOT_MET" in report.failure_codes


def test_reusing_a_trusted_key_id_with_another_public_key_fails() -> None:
    trusted_key = _key("shared-id")
    attacker_key = _key("shared-id")
    receipt = seal_receipt(receipt_payload(), signing_keys=(attacker_key,))

    report = _policy(_trusted(trusted_key)).verify_receipt(
        receipt,
        evaluated_at=_AFTER_RUN,
    )

    assert not report.valid
    assert report.signatures[0].reason.value == "PUBLIC_KEY_MISMATCH"


def test_retired_key_preserves_history_but_cannot_admit_a_backdated_receipt() -> None:
    key = _key()
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))
    policy = _policy(_trusted(key, status=SignerStatus.RETIRED))

    admission = policy.verify_receipt(
        receipt,
        mode=SignerTrustMode.ADMISSION,
        evaluated_at=_AFTER_RUN,
    )
    historical = policy.verify_receipt(receipt, mode=SignerTrustMode.HISTORICAL)

    assert not admission.valid
    assert admission.signatures[0].reason.value == "SIGNER_RETIRED"
    assert historical.valid
    assert historical.authorization_time == "2026-08-06T00:00:02Z"


def test_revoked_key_fails_admission_and_history() -> None:
    key = _key()
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))
    policy = _policy(_trusted(key, status=SignerStatus.REVOKED))

    admission = policy.verify_receipt(receipt, evaluated_at=_AFTER_RUN)
    historical = policy.verify_receipt(receipt, mode=SignerTrustMode.HISTORICAL)

    assert not admission.valid
    assert not historical.valid
    assert admission.signatures[0].reason.value == "SIGNER_REVOKED"
    assert historical.signatures[0].reason.value == "SIGNER_REVOKED"


def test_validity_window_is_start_inclusive_and_end_exclusive() -> None:
    key = _key()
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))
    signer = _trusted(
        key,
        not_before="2026-08-06T00:00:02Z",
        not_after="2026-08-07T00:00:00Z",
    )
    policy = _policy(signer)

    assert policy.verify_receipt(receipt, mode=SignerTrustMode.HISTORICAL).valid
    assert not policy.verify_receipt(
        receipt,
        evaluated_at=datetime(2026, 8, 7, tzinfo=UTC),
    ).valid


def test_overlap_rotation_supports_a_two_signer_threshold() -> None:
    first = _key("rotation-a")
    second = _key("rotation-b")
    receipt = seal_receipt(receipt_payload(), signing_keys=(first, second))
    policy = _policy(_trusted(first), _trusted(second), minimum=2)

    assert policy.verify_receipt(receipt, evaluated_at=_AFTER_RUN).valid

    one_signature = seal_receipt(receipt_payload(), signing_keys=(second,))
    report = policy.verify_receipt(one_signature, evaluated_at=_AFTER_RUN)
    assert not report.valid
    assert report.trusted_signature_count == 1


def test_unknown_extra_signature_does_not_cancel_a_trusted_threshold() -> None:
    trusted = _key("trusted")
    unknown = _key("unknown")
    receipt = seal_receipt(receipt_payload(), signing_keys=(trusted, unknown))

    report = _policy(_trusted(trusted)).verify_receipt(receipt, evaluated_at=_AFTER_RUN)

    assert report.valid
    assert [item.reason.value for item in report.signatures] == ["TRUSTED", "UNKNOWN_KEY_ID"]


def test_integrity_tampering_cannot_pass_signer_trust() -> None:
    key = _key()
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))
    tampered = copy.deepcopy(receipt)
    tampered["run"]["status"] = "FAILED"

    report = _policy(_trusted(key)).verify_receipt(tampered, evaluated_at=_AFTER_RUN)

    assert not report.valid
    assert "INTEGRITY_INVALID" in report.failure_codes


def test_configured_private_key_must_be_currently_active() -> None:
    key = _key()
    active = _policy(_trusted(key))
    retired = _policy(_trusted(key, status=SignerStatus.RETIRED))

    assert active.require_active_signing_key(key, evaluated_at=_AFTER_RUN) == (
        signing_key_fingerprint(key)
    )
    with pytest.raises(SignerTrustError, match="SIGNER_RETIRED"):
        retired.require_active_signing_key(key, evaluated_at=_AFTER_RUN)


def test_policy_rejects_fingerprint_mismatch_duplicate_identity_and_bad_window() -> None:
    key = _key()
    signer = _trusted(key)
    with pytest.raises(SignerTrustError, match="fingerprint"):
        TrustedSigner(
            key_id=key.key_id,
            public_key=signer.public_key,
            public_key_sha256="0" * 64,
            status=SignerStatus.ACTIVE,
            not_before=signer.not_before,
            not_after=signer.not_after,
        )
    with pytest.raises(SignerTrustError, match="key IDs"):
        _policy(signer, signer)
    with pytest.raises(SignerTrustError, match="later"):
        _trusted(
            key,
            not_before="2026-08-02T00:00:00Z",
            not_after="2026-08-01T00:00:00Z",
        )


def test_policy_file_load_is_strict_bounded_and_symlink_safe(tmp_path: Path) -> None:
    key = _key()
    policy = _policy(_trusted(key))
    path = tmp_path / "trusted-signers.json"
    path.write_text(json.dumps(policy.to_dict()), encoding="utf-8")

    loaded = load_signer_trust_policy(path)

    assert loaded == policy
    link = tmp_path / "policy-link.json"
    link.symlink_to(path)
    with pytest.raises(SignerTrustError, match="symbolic"):
        load_signer_trust_policy(link)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"unknown": True}),
        lambda value: value.update({"schema_version": "glassbox.signer-trust.v2"}),
        lambda value: value.update({"minimum_trusted_signatures": 2}),
    ],
)
def test_policy_parser_fails_closed_on_unknown_or_unsatisfied_contract(
    mutation: object,
) -> None:
    key = _key()
    value = _policy(_trusted(key)).to_dict()
    assert callable(mutation)
    mutation(value)

    with pytest.raises(SignerTrustError):
        SignerTrustPolicy.from_dict(value)


def test_naive_admission_clock_is_rejected() -> None:
    key = _key()
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))

    with pytest.raises(SignerTrustError, match="timezone"):
        _policy(_trusted(key)).verify_receipt(
            receipt,
            evaluated_at=_AFTER_RUN.replace(tzinfo=None),
        )


def test_historical_mode_uses_signed_receipt_time_not_the_callers_clock() -> None:
    key = _key()
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))
    policy = _policy(_trusted(key))

    report = policy.verify_receipt(
        receipt,
        mode=SignerTrustMode.HISTORICAL,
        evaluated_at=datetime(2099, 1, 1, tzinfo=UTC),
    )

    assert report.valid
    assert report.authorization_time == "2026-08-06T00:00:02Z"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"policy_id": "", "minimum_trusted_signatures": 1, "trusted_signers": (("a", "a" * 64),)},
        {"policy_id": "p", "minimum_trusted_signatures": 0, "trusted_signers": (("a", "a" * 64),)},
        {"policy_id": "p", "minimum_trusted_signatures": 2, "trusted_signers": (("a", "a" * 64),)},
        {
            "policy_id": "p",
            "minimum_trusted_signatures": 1,
            "trusted_signers": (("b", "b" * 64), ("a", "a" * 64)),
        },
        {
            "policy_id": "p",
            "minimum_trusted_signatures": 1,
            "trusted_signers": (("a", "a" * 64), ("a", "a" * 64)),
        },
        {"policy_id": "p", "minimum_trusted_signatures": 1, "trusted_signers": ((" ", "a" * 64),)},
        {"policy_id": "p", "minimum_trusted_signatures": 1, "trusted_signers": (("a", "bad"),)},
    ],
)
def test_admission_evidence_constructor_rejects_ambiguous_identity(
    kwargs: dict[str, object],
) -> None:
    with pytest.raises(SignerTrustError):
        SignerAdmissionEvidence(**kwargs)


@pytest.mark.parametrize(
    "value",
    [
        {},
        {
            "policy_id": "p",
            "minimum_trusted_signatures": 1,
            "trusted_signers": "not-an-array",
        },
        {
            "policy_id": "p",
            "minimum_trusted_signatures": 1,
            "trusted_signers": [{"key_id": "a"}],
        },
    ],
)
def test_admission_evidence_dict_parser_is_closed(value: dict[str, object]) -> None:
    with pytest.raises(SignerTrustError):
        SignerAdmissionEvidence.from_dict(value)


def test_admission_evidence_requires_valid_admission_and_receipt_binding() -> None:
    key = _key("admission-evidence")
    receipt = seal_receipt(receipt_payload(), signing_keys=(key,))
    policy = _policy(_trusted(key))
    historical = policy.verify_receipt(receipt, mode=SignerTrustMode.HISTORICAL)
    with pytest.raises(SignerTrustError, match="valid admission"):
        SignerAdmissionEvidence.from_report(historical)

    admission = SignerAdmissionEvidence.from_report(
        policy.verify_receipt(receipt, evaluated_at=_AFTER_RUN)
    )
    tampered = copy.deepcopy(receipt)
    tampered["run"]["status"] = "FAILED"
    with pytest.raises(SignerTrustError, match="integrity"):
        admission.verify_receipt_binding(tampered)


def test_policy_require_methods_reject_unknown_or_mismatched_keys_and_receipts() -> None:
    trusted = _key("configured")
    unknown = _key("unknown")
    same_id_wrong_key = _key("configured")
    policy = _policy(_trusted(trusted))
    with pytest.raises(SignerTrustError, match="receipt signer trust"):
        policy.require_receipt(
            seal_receipt(receipt_payload(), signing_keys=(unknown,)),
            evaluated_at=_AFTER_RUN,
        )
    with pytest.raises(SignerTrustError, match="ID is not trusted"):
        policy.require_active_signing_key(unknown, evaluated_at=_AFTER_RUN)
    with pytest.raises(SignerTrustError, match="fingerprint"):
        policy.require_active_signing_key(same_id_wrong_key, evaluated_at=_AFTER_RUN)


def test_open_ended_signer_and_invalid_private_key_encodings() -> None:
    signer = _trusted(_key("open-ended"), not_after=None)
    assert signer.ends_at is None
    with pytest.raises(SignerTrustError, match="valid base64url"):
        signing_key_from_base64url("bad", "***")
    with pytest.raises(SignerTrustError, match="Ed25519 private key"):
        signing_key_from_base64url("short", "YQ")


def test_historical_missing_or_invalid_receipt_time_is_explicit() -> None:
    key = _key("historical-time")
    policy = _policy(_trusted(key))
    for ended_at in (None, "not-a-time"):
        receipt = seal_receipt(receipt_payload())
        if ended_at is None:
            receipt["run"].pop("ended_at")
        else:
            receipt["run"]["ended_at"] = ended_at
        report = policy.verify_receipt(receipt, mode=SignerTrustMode.HISTORICAL)
        assert not report.valid
        assert "RECEIPT_TIME_INVALID" in report.failure_codes


def test_policy_and_schema_file_loaders_reject_nonregular_empty_and_invalid_inputs(
    tmp_path: Path,
) -> None:
    with pytest.raises(SignerTrustError, match="unavailable"):
        load_signer_trust_policy(tmp_path / "missing.json")
    with pytest.raises(SignerTrustError, match="regular file"):
        load_signer_trust_policy(tmp_path)
    empty = tmp_path / "empty.json"
    empty.touch()
    with pytest.raises(SignerTrustError, match="size"):
        load_signer_trust_policy(empty)
    invalid = tmp_path / "invalid.json"
    invalid.write_text("{", encoding="utf-8")
    with pytest.raises(SignerTrustError, match="valid JSON"):
        load_signer_trust_policy(invalid)
    invalid.write_text("[]", encoding="utf-8")
    with pytest.raises(SignerTrustError, match="root"):
        load_signer_trust_policy(invalid)

    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    assert load_signer_trust_schema(schema) == {"type": "object"}
    schema.write_text("not-json", encoding="utf-8")
    with pytest.raises(SignerTrustError, match="schema is not valid JSON"):
        load_signer_trust_schema(schema)
    schema.write_text("[]", encoding="utf-8")
    with pytest.raises(SignerTrustError, match="schema root"):
        load_signer_trust_schema(schema)


def test_policy_loader_detects_read_failure_and_changed_file_size(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _key("file-race")
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(_policy(_trusted(key)).to_dict()), encoding="utf-8")

    def fail_read(descriptor: int, size: int) -> bytes:
        del descriptor, size
        raise OSError("synthetic read failure")

    monkeypatch.setattr(os, "read", fail_read)
    with pytest.raises(SignerTrustError, match="could not be read"):
        load_signer_trust_policy(path)
    monkeypatch.undo()

    original_fstat = os.fstat

    def changed_size(descriptor: int) -> SimpleNamespace:
        metadata = original_fstat(descriptor)
        return SimpleNamespace(st_mode=metadata.st_mode, st_size=metadata.st_size + 1)

    monkeypatch.setattr(trust_module.os, "fstat", changed_size)
    with pytest.raises(SignerTrustError, match="changed"):
        load_signer_trust_policy(path)
