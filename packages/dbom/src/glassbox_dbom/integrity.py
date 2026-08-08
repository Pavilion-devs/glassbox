"""Content addressing, Merkle commitments, and Ed25519 verification for DBOM."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from glassbox_dbom.canonical import canonicalize
from glassbox_dbom.errors import IntegrityError, SchemaValidationError
from glassbox_dbom.validation import validate_receipt

_LEAF_DOMAIN = b"glassbox.dbom.leaf.v1\0"
_NODE_DOMAIN = b"glassbox.dbom.node.v1\0"
_EMPTY_DOMAIN = b"glassbox.dbom.empty.v1"
_SIGNATURE_DOMAIN = b"glassbox.dbom.signature.v1\0"
_MERKLE_SECTIONS = ("evidence", "actions", "evaluations")


@dataclass(frozen=True)
class SigningKey:
    """An in-memory signing key and its stable external identifier."""

    key_id: str
    private_key: Ed25519PrivateKey

    def __post_init__(self) -> None:
        if not self.key_id:
            raise IntegrityError("signing key_id must not be empty")


@dataclass(frozen=True)
class SignatureResult:
    """Verification result for one detached signature."""

    key_id: str
    valid: bool
    error: str | None = None


@dataclass(frozen=True)
class VerificationReport:
    """Deterministic verification result with no hidden exception state."""

    schema_valid: bool
    payload_digest_valid: bool
    receipt_id_valid: bool
    merkle_root_valid: bool
    signatures: tuple[SignatureResult, ...]
    signature_required: bool
    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        signature_gate = (not self.signature_required) or (
            bool(self.signatures) and all(item.valid for item in self.signatures)
        )
        present_signatures_valid = all(item.valid for item in self.signatures)
        return (
            self.schema_valid
            and self.payload_digest_valid
            and self.receipt_id_valid
            and self.merkle_root_valid
            and present_signatures_valid
            and signature_gate
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "schema_valid": self.schema_valid,
            "payload_digest_valid": self.payload_digest_valid,
            "receipt_id_valid": self.receipt_id_valid,
            "merkle_root_valid": self.merkle_root_valid,
            "signature_required": self.signature_required,
            "signatures": [
                {"key_id": item.key_id, "valid": item.valid, "error": item.error}
                for item in self.signatures
            ],
            "errors": list(self.errors),
        }


def payload_material(receipt: Mapping[str, Any]) -> dict[str, Any]:
    """Return the precise receipt material committed by the payload digest."""

    material = copy.deepcopy(dict(receipt))
    material.pop("receipt_id", None)
    material.pop("integrity", None)
    return material


def payload_digest(receipt: Mapping[str, Any]) -> str:
    """Compute the lowercase SHA-256 digest for the canonical payload."""

    return hashlib.sha256(canonicalize(payload_material(receipt))).hexdigest()


def merkle_root(receipt: Mapping[str, Any]) -> str:
    """Compute the documented DBOM section Merkle root."""

    leaves: list[bytes] = []
    for section in _MERKLE_SECTIONS:
        values = receipt.get(section, [])
        if not isinstance(values, list):
            raise IntegrityError(f"/{section} must be an array to compute the Merkle root")
        for index, value in enumerate(values):
            prefix = _LEAF_DOMAIN + section.encode() + b"\0" + str(index).encode() + b"\0"
            leaves.append(hashlib.sha256(prefix + canonicalize(value)).digest())

    if "output" in receipt:
        output_prefix = _LEAF_DOMAIN + b"output\0" + b"0" + b"\0"
        leaves.append(hashlib.sha256(output_prefix + canonicalize(receipt["output"])).digest())

    if not leaves:
        return hashlib.sha256(_EMPTY_DOMAIN).hexdigest()

    level = leaves
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            hashlib.sha256(_NODE_DOMAIN + level[index] + level[index + 1]).digest()
            for index in range(0, len(level), 2)
        ]
    return level[0].hex()


def seal_receipt(
    receipt: Mapping[str, Any], *, signing_keys: Iterable[SigningKey] = ()
) -> dict[str, Any]:
    """Return a sealed copy; the caller's object is never mutated."""

    sealed = copy.deepcopy(dict(receipt))
    sealed.pop("receipt_id", None)
    sealed.pop("integrity", None)

    digest = payload_digest(sealed)
    sealed["receipt_id"] = f"gbx:receipt:sha256:{digest}"
    signatures = [_create_signature(digest, signing_key) for signing_key in signing_keys]
    sealed["integrity"] = {
        "canonicalization": "RFC8785",
        "payload_digest": {"algorithm": "sha256", "value": digest},
        "merkle_root": {"algorithm": "sha256", "value": merkle_root(sealed)},
        "signatures": signatures,
    }
    validate_receipt(sealed)
    return sealed


def verify_receipt(
    receipt: Mapping[str, Any], *, require_signature: bool = False
) -> VerificationReport:
    """Verify schema, digest, receipt ID, Merkle root, and all present signatures."""

    errors: list[str] = []
    try:
        validate_receipt(receipt)
        schema_valid = True
    except SchemaValidationError as exc:
        schema_valid = False
        errors.extend(f"schema: {failure}" for failure in exc.errors)

    expected_digest = payload_digest(receipt)
    integrity = receipt.get("integrity")
    integrity_mapping = integrity if isinstance(integrity, Mapping) else {}
    recorded_digest = _nested_string(integrity_mapping, "payload_digest", "value")
    payload_digest_valid = recorded_digest is not None and hmac.compare_digest(
        expected_digest, recorded_digest
    )
    if not payload_digest_valid:
        errors.append("integrity: payload digest mismatch or missing digest")

    expected_receipt_id = f"gbx:receipt:sha256:{expected_digest}"
    receipt_id = receipt.get("receipt_id")
    receipt_id_valid = isinstance(receipt_id, str) and hmac.compare_digest(
        expected_receipt_id, receipt_id
    )
    if not receipt_id_valid:
        errors.append("integrity: receipt ID does not match the canonical payload digest")

    try:
        expected_merkle_root = merkle_root(receipt)
    except IntegrityError as exc:
        expected_merkle_root = None
        errors.append(f"integrity: {exc}")
    recorded_merkle_root = _nested_string(integrity_mapping, "merkle_root", "value")
    merkle_root_valid = (
        expected_merkle_root is not None
        and recorded_merkle_root is not None
        and hmac.compare_digest(expected_merkle_root, recorded_merkle_root)
    )
    if not merkle_root_valid:
        errors.append("integrity: Merkle root mismatch or missing root")

    signature_results = _verify_signatures(integrity_mapping, expected_digest)
    for result in signature_results:
        if not result.valid:
            errors.append(f"signature {result.key_id!r}: {result.error}")
    if require_signature and not signature_results:
        errors.append("signature: at least one valid signature is required")

    return VerificationReport(
        schema_valid=schema_valid,
        payload_digest_valid=payload_digest_valid,
        receipt_id_valid=receipt_id_valid,
        merkle_root_valid=merkle_root_valid,
        signatures=signature_results,
        signature_required=require_signature,
        errors=tuple(errors),
    )


def _create_signature(digest: str, signing_key: SigningKey) -> dict[str, str]:
    public_key_bytes = signing_key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = signing_key.private_key.sign(_signature_material(digest))
    return {
        "algorithm": "Ed25519",
        "key_id": signing_key.key_id,
        "public_key": _base64url_encode(public_key_bytes),
        "value": _base64url_encode(signature),
    }


def _verify_signatures(integrity: Mapping[str, Any], digest: str) -> tuple[SignatureResult, ...]:
    raw_signatures = integrity.get("signatures", [])
    if not isinstance(raw_signatures, list):
        return (SignatureResult(key_id="<malformed>", valid=False, error="must be an array"),)

    results: list[SignatureResult] = []
    seen_key_ids: set[str] = set()
    for raw_signature in raw_signatures:
        if not isinstance(raw_signature, Mapping):
            results.append(
                SignatureResult(key_id="<malformed>", valid=False, error="must be an object")
            )
            continue
        key_id = raw_signature.get("key_id")
        display_key_id = key_id if isinstance(key_id, str) else "<malformed>"
        if display_key_id in seen_key_ids:
            results.append(
                SignatureResult(
                    key_id=display_key_id,
                    valid=False,
                    error="duplicate key_id in signature set",
                )
            )
            continue
        seen_key_ids.add(display_key_id)
        try:
            if raw_signature.get("algorithm") != "Ed25519":
                raise IntegrityError("unsupported signature algorithm")
            public_key = Ed25519PublicKey.from_public_bytes(
                _base64url_decode(_required_string(raw_signature, "public_key"))
            )
            signature = _base64url_decode(_required_string(raw_signature, "value"))
            public_key.verify(signature, _signature_material(digest))
        except (IntegrityError, ValueError, InvalidSignature) as exc:
            error = "invalid signature" if isinstance(exc, InvalidSignature) else str(exc)
            results.append(SignatureResult(key_id=display_key_id, valid=False, error=error))
        else:
            results.append(SignatureResult(key_id=display_key_id, valid=True))
    return tuple(results)


def _signature_material(digest: str) -> bytes:
    try:
        digest_bytes = bytes.fromhex(digest)
    except ValueError as exc:
        raise IntegrityError("payload digest is not lowercase hexadecimal") from exc
    if len(digest_bytes) != 32:
        raise IntegrityError("payload digest must be exactly 32 bytes")
    return _SIGNATURE_DOMAIN + digest_bytes


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise IntegrityError(f"signature {key} must be a non-empty string")
    return selected


def _nested_string(value: Mapping[str, Any], outer: str, inner: str) -> str | None:
    nested = value.get(outer)
    if not isinstance(nested, Mapping):
        return None
    selected = nested.get(inner)
    return selected if isinstance(selected, str) else None


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise IntegrityError("invalid unpadded base64url value") from exc
