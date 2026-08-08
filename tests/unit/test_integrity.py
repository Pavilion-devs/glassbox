from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey, seal_receipt, verify_receipt
from glassbox_dbom.errors import IntegrityError
from glassbox_dbom.integrity import _base64url_decode, _signature_material, merkle_root
from tests.helpers import receipt_payload


def test_seal_is_deterministic_and_does_not_mutate_input() -> None:
    payload = receipt_payload()
    original = copy.deepcopy(payload)

    first = seal_receipt(payload)
    second = seal_receipt(payload)

    assert payload == original
    assert first == second
    assert first["receipt_id"].endswith(first["integrity"]["payload_digest"]["value"])
    assert verify_receipt(first).valid


def test_one_character_payload_tampering_fails_digest_and_merkle() -> None:
    sealed = seal_receipt(receipt_payload())
    tampered = copy.deepcopy(sealed)
    digest = tampered["output"]["digest"]["value"]
    tampered["output"]["digest"]["value"] = ("0" if digest[0] != "0" else "1") + digest[1:]

    report = verify_receipt(tampered)

    assert not report.valid
    assert not report.payload_digest_valid
    assert not report.receipt_id_valid
    assert not report.merkle_root_valid


def test_ed25519_signature_verifies() -> None:
    key = SigningKey("test-key-2026", Ed25519PrivateKey.generate())
    sealed = seal_receipt(receipt_payload(), signing_keys=[key])

    report = verify_receipt(sealed, require_signature=True)

    assert report.valid
    assert report.signatures[0].key_id == "test-key-2026"
    assert report.signatures[0].valid


def test_signature_tampering_fails_without_changing_payload_digest() -> None:
    key = SigningKey("test-key-2026", Ed25519PrivateKey.generate())
    sealed = seal_receipt(receipt_payload(), signing_keys=[key])
    signature = sealed["integrity"]["signatures"][0]["value"]
    sealed["integrity"]["signatures"][0]["value"] = (
        "A" if signature[0] != "A" else "B"
    ) + signature[1:]

    report = verify_receipt(sealed, require_signature=True)

    assert not report.valid
    assert report.payload_digest_valid
    assert not report.signatures[0].valid


def test_signature_requirement_rejects_an_unsigned_receipt() -> None:
    report = verify_receipt(seal_receipt(receipt_payload()), require_signature=True)

    assert not report.valid
    assert "signature: at least one valid signature is required" in report.errors


def test_empty_signing_key_id_is_rejected() -> None:
    with pytest.raises(IntegrityError, match="key_id"):
        SigningKey("", Ed25519PrivateKey.generate())


def test_merkle_root_rejects_non_array_sections_and_handles_empty_receipt() -> None:
    assert len(merkle_root({})) == 64
    with pytest.raises(IntegrityError, match="/evidence"):
        merkle_root({"evidence": {}})


def test_merkle_tree_duplicates_the_final_node_at_an_odd_level() -> None:
    payload = receipt_payload()
    payload["evidence"].append(copy.deepcopy(payload["evidence"][0]))

    assert len(merkle_root(payload)) == 64


@pytest.mark.parametrize(
    ("signatures", "expected_error"),
    [
        ({}, "must be an array"),
        (["not-an-object"], "must be an object"),
        (
            [{"algorithm": "RSA", "key_id": "bad", "public_key": "x", "value": "y"}],
            "unsupported signature algorithm",
        ),
        (
            [
                {
                    "algorithm": "Ed25519",
                    "key_id": "bad",
                    "public_key": "",
                    "value": "y",
                }
            ],
            "must be a non-empty string",
        ),
    ],
)
def test_malformed_signature_material_is_reported(signatures: object, expected_error: str) -> None:
    sealed = seal_receipt(receipt_payload())
    sealed["integrity"]["signatures"] = signatures

    report = verify_receipt(sealed)

    assert not report.valid
    assert any(expected_error in error for error in report.errors)


def test_duplicate_signature_key_ids_are_rejected() -> None:
    key = SigningKey("duplicate", Ed25519PrivateKey.generate())
    sealed = seal_receipt(receipt_payload(), signing_keys=[key, key])

    report = verify_receipt(sealed)

    assert not report.valid
    assert report.signatures[1].error is not None
    assert "duplicate key_id" in report.signatures[1].error


def test_schema_and_merkle_failures_are_reported_without_crashing() -> None:
    sealed = seal_receipt(receipt_payload())
    sealed["evidence"] = {}

    report = verify_receipt(sealed)

    assert not report.schema_valid
    assert not report.merkle_root_valid
    assert any("/evidence must be an array" in error for error in report.errors)


@pytest.mark.parametrize("digest", ["not-hex", "00"])
def test_invalid_signature_digest_material_is_rejected(digest: str) -> None:
    with pytest.raises(IntegrityError):
        _signature_material(digest)


def test_invalid_base64url_is_rejected() -> None:
    with pytest.raises(IntegrityError, match="base64url"):
        _base64url_decode("***")
