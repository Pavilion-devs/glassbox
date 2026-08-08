"""Signed approvals bound to one replay action-set digest and environment."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from glassbox_dbom import SigningKey
from glassbox_dbom.canonical import canonicalize
from glassbox_replay.models import ReplayInputError, _digest_object

APPROVAL_POLICY_VERSION = "glassbox.replay-approval.v1"
_APPROVAL_DOMAIN = b"glassbox.replay.approval.v1\0"
_SIGNATURE_DOMAIN = b"glassbox.replay.approval.signature.v1\0"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BUNDLE_ID = re.compile(r"^gbx:replay-bundle:sha256:[0-9a-f]{64}$")


@dataclass(frozen=True)
class ApprovalSignature:
    """One embedded Ed25519 approval signature."""

    algorithm: str
    key_id: str
    public_key: str
    value: str

    def to_dict(self) -> dict[str, str]:
        return {
            "algorithm": self.algorithm,
            "key_id": self.key_id,
            "public_key": self.public_key,
            "value": self.value,
        }


@dataclass(frozen=True)
class ReplayApproval:
    """Immutable approval for one exact replay action set."""

    approval_id: str
    bundle_id: str
    action_set_digest: str
    policy_version: str
    issuer: str
    environment: str
    scope: str
    reason_digest: str
    issued_at: str
    expires_at: str
    revoked: bool
    signatures: tuple[ApprovalSignature, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id,
            "bundle_id": self.bundle_id,
            "action_set_digest": _digest_object(self.action_set_digest),
            "policy_version": self.policy_version,
            "issuer": self.issuer,
            "environment": self.environment,
            "scope": self.scope,
            "reason_digest": _digest_object(self.reason_digest),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "signatures": [item.to_dict() for item in self.signatures],
        }


@dataclass(frozen=True)
class ApprovalVerification:
    """Approval verification with explicit trust, scope, and expiry gates."""

    valid: bool
    approval_id_valid: bool
    signatures_valid: bool
    trusted_signer_present: bool
    binding_valid: bool
    time_valid: bool
    not_revoked: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "approval_id_valid": self.approval_id_valid,
            "signatures_valid": self.signatures_valid,
            "trusted_signer_present": self.trusted_signer_present,
            "binding_valid": self.binding_valid,
            "time_valid": self.time_valid,
            "not_revoked": self.not_revoked,
            "errors": list(self.errors),
        }


def issue_replay_approval(
    *,
    bundle_id: str,
    action_set_digest: str,
    issuer: str,
    environment: str,
    reason_digest: str,
    issued_at: str,
    expires_at: str,
    signing_keys: Iterable[SigningKey],
) -> ReplayApproval:
    """Create a signed approval; timestamps and reason are explicit caller inputs."""

    _validate_text(issuer, "issuer")
    _validate_text(environment, "environment")
    _validate_bundle_id(bundle_id)
    _validate_digest(action_set_digest, "action_set_digest")
    _validate_digest(reason_digest, "reason_digest")
    issued = _timestamp(issued_at, "issued_at")
    expires = _timestamp(expires_at, "expires_at")
    if expires <= issued:
        raise ReplayInputError("expires_at must be later than issued_at")
    keys = tuple(signing_keys)
    if not keys:
        raise ReplayInputError("at least one approval signing key is required")
    material = _approval_material(
        bundle_id=bundle_id,
        action_set_digest=action_set_digest,
        issuer=issuer,
        environment=environment,
        reason_digest=reason_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        revoked=False,
    )
    digest = _approval_digest(material)
    return ReplayApproval(
        approval_id=f"gbx:replay-approval:sha256:{digest}",
        bundle_id=bundle_id,
        action_set_digest=action_set_digest,
        policy_version=APPROVAL_POLICY_VERSION,
        issuer=issuer,
        environment=environment,
        scope="REPLAY_ACTION_SET",
        reason_digest=reason_digest,
        issued_at=issued_at,
        expires_at=expires_at,
        revoked=False,
        signatures=tuple(_sign(digest, key) for key in keys),
    )


def verify_replay_approval(
    approval: ReplayApproval,
    *,
    expected_bundle_id: str,
    expected_action_set_digest: str,
    expected_environment: str,
    evaluated_at: str,
    trusted_key_ids: frozenset[str],
) -> ApprovalVerification:
    """Verify approval content, exact action binding, trusted signer, and lifetime."""

    errors: list[str] = []
    material = _approval_material(
        bundle_id=approval.bundle_id,
        action_set_digest=approval.action_set_digest,
        issuer=approval.issuer,
        environment=approval.environment,
        reason_digest=approval.reason_digest,
        issued_at=approval.issued_at,
        expires_at=approval.expires_at,
        revoked=approval.revoked,
    )
    digest = _approval_digest(material)
    expected_id = f"gbx:replay-approval:sha256:{digest}"
    approval_id_valid = hmac.compare_digest(expected_id, approval.approval_id)
    if not approval_id_valid:
        errors.append("approval ID does not match its canonical material")

    signature_results = tuple(_verify_signature(item, digest) for item in approval.signatures)
    signatures_valid = bool(signature_results) and all(signature_results)
    if not signatures_valid:
        errors.append("approval signature verification failed")
    trusted_signer_present = any(
        item.key_id in trusted_key_ids and valid
        for item, valid in zip(approval.signatures, signature_results, strict=True)
    )
    if not trusted_signer_present:
        errors.append("approval has no valid signature from a trusted key ID")

    binding_valid = (
        approval.policy_version == APPROVAL_POLICY_VERSION
        and approval.scope == "REPLAY_ACTION_SET"
        and approval.bundle_id == expected_bundle_id
        and hmac.compare_digest(approval.action_set_digest, expected_action_set_digest)
        and approval.environment == expected_environment
    )
    if not binding_valid:
        errors.append("approval does not bind the requested bundle, actions, or environment")

    evaluated = _timestamp(evaluated_at, "evaluated_at")
    issued = _timestamp(approval.issued_at, "issued_at")
    expires = _timestamp(approval.expires_at, "expires_at")
    time_valid = issued <= evaluated < expires
    if not time_valid:
        errors.append("approval is not valid at the evaluation time")
    not_revoked = not approval.revoked
    if not not_revoked:
        errors.append("approval is revoked")
    valid = (
        approval_id_valid
        and signatures_valid
        and trusted_signer_present
        and binding_valid
        and time_valid
        and not_revoked
    )
    return ApprovalVerification(
        valid=valid,
        approval_id_valid=approval_id_valid,
        signatures_valid=signatures_valid,
        trusted_signer_present=trusted_signer_present,
        binding_valid=binding_valid,
        time_valid=time_valid,
        not_revoked=not_revoked,
        errors=tuple(errors),
    )


def _approval_material(
    *,
    bundle_id: str,
    action_set_digest: str,
    issuer: str,
    environment: str,
    reason_digest: str,
    issued_at: str,
    expires_at: str,
    revoked: bool,
) -> dict[str, Any]:
    return {
        "bundle_id": bundle_id,
        "action_set_digest": _digest_object(action_set_digest),
        "policy_version": APPROVAL_POLICY_VERSION,
        "issuer": issuer,
        "environment": environment,
        "scope": "REPLAY_ACTION_SET",
        "reason_digest": _digest_object(reason_digest),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revoked": revoked,
    }


def _approval_digest(material: Mapping[str, Any]) -> str:
    return hashlib.sha256(_APPROVAL_DOMAIN + canonicalize(material)).hexdigest()


def _sign(digest: str, key: SigningKey) -> ApprovalSignature:
    public = key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = key.private_key.sign(_SIGNATURE_DOMAIN + bytes.fromhex(digest))
    return ApprovalSignature(
        algorithm="Ed25519",
        key_id=key.key_id,
        public_key=_base64url_encode(public),
        value=_base64url_encode(signature),
    )


def _verify_signature(signature: ApprovalSignature, digest: str) -> bool:
    try:
        if signature.algorithm != "Ed25519":
            return False
        public = Ed25519PublicKey.from_public_bytes(_base64url_decode(signature.public_key, 32))
        value = _base64url_decode(signature.value, 64)
        public.verify(value, _SIGNATURE_DOMAIN + bytes.fromhex(digest))
        return True
    except (InvalidSignature, ValueError):
        return False


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplayInputError(f"{name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplayInputError(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _validate_bundle_id(value: str) -> None:
    if not _BUNDLE_ID.fullmatch(value):
        raise ReplayInputError("bundle_id is invalid")


def _validate_digest(value: str, name: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ReplayInputError(f"{name} must be a lowercase SHA-256 digest")


def _validate_text(value: str, name: str) -> None:
    if not value:
        raise ReplayInputError(f"{name} must be non-empty")


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _base64url_decode(value: str, size: int) -> bytes:
    decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    if len(decoded) != size:
        raise ValueError("signature material has an invalid length")
    return decoded


__all__ = [
    "APPROVAL_POLICY_VERSION",
    "ApprovalSignature",
    "ApprovalVerification",
    "ReplayApproval",
    "issue_replay_approval",
    "verify_replay_approval",
]
