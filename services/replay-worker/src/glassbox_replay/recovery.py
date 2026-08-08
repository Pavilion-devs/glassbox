"""Signed, fail-closed handoff from completed invalidation to corrected replay."""

from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from glassbox_dbom import SigningKey, verify_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_invalidation import OutboxStatus, OutboxTask
from glassbox_policy import ImpactState
from glassbox_replay.bundle import verify_replay_bundle
from glassbox_replay.execution import ReplayExecutionError
from glassbox_replay.models import ReplayInputError, ReplayMode

RECOVERY_AUTHORIZATION_POLICY_VERSION = "glassbox.recovery-authorization.v1"
_AUTHORIZATION_DOMAIN = b"glassbox.recovery.authorization.v1\0"
_SIGNATURE_DOMAIN = b"glassbox.recovery.authorization.signature.v1\0"


@dataclass(frozen=True)
class RecoverySignature:
    """One embedded Ed25519 operator signature."""

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
class RecoveryAuthorization:
    """Immutable authorization for one stale campaign and one corrected bundle."""

    authorization_id: str
    campaign_id: str
    incident_urn: str
    change_event_id: str
    source_receipt_id: str
    source_payload_digest: str
    bundle_id: str
    mode: str
    finding_state: str
    finding_reason_code: str
    matched_evidence_ids: tuple[str, ...]
    campaign_policy_version: str
    campaign_attempt_count: int
    writeback_evidence_digest: str
    issuer: str
    issued_at: str
    expires_at: str
    revoked: bool
    signatures: tuple[RecoverySignature, ...]
    policy_version: str = RECOVERY_AUTHORIZATION_POLICY_VERSION
    scope: str = "CORRECTED_REPLAY_BUNDLE"

    @property
    def valid(self) -> bool:
        return self.authorization_id == _authorization_id(self._material())

    def to_dict(self) -> dict[str, Any]:
        return {
            "authorization_id": self.authorization_id,
            "campaign_id": self.campaign_id,
            "incident_urn": self.incident_urn,
            "change_event_id": self.change_event_id,
            "source_receipt_id": self.source_receipt_id,
            "source_payload_digest": _digest_object(self.source_payload_digest),
            "bundle_id": self.bundle_id,
            "mode": self.mode,
            "finding_state": self.finding_state,
            "finding_reason_code": self.finding_reason_code,
            "matched_evidence_ids": list(self.matched_evidence_ids),
            "campaign_policy_version": self.campaign_policy_version,
            "campaign_attempt_count": self.campaign_attempt_count,
            "writeback_evidence_digest": _digest_object(self.writeback_evidence_digest),
            "issuer": self.issuer,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "revoked": self.revoked,
            "policy_version": self.policy_version,
            "scope": self.scope,
            "signatures": [item.to_dict() for item in self.signatures],
            "raw_content_returned": False,
        }

    def _material(self) -> dict[str, Any]:
        value = self.to_dict()
        value.pop("authorization_id")
        value.pop("signatures")
        value.pop("raw_content_returned")
        return value


@dataclass(frozen=True)
class RecoveryAuthorizationVerification:
    """Explicit cryptographic, trust, campaign, bundle, and lifetime gates."""

    valid: bool
    authorization_id_valid: bool
    signatures_valid: bool
    trusted_signer_present: bool
    operational_binding_valid: bool
    exact_binding_valid: bool
    time_valid: bool
    not_revoked: bool
    errors: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "authorization_id_valid": self.authorization_id_valid,
            "signatures_valid": self.signatures_valid,
            "trusted_signer_present": self.trusted_signer_present,
            "operational_binding_valid": self.operational_binding_valid,
            "exact_binding_valid": self.exact_binding_valid,
            "time_valid": self.time_valid,
            "not_revoked": self.not_revoked,
            "errors": list(self.errors),
            "raw_content_returned": False,
        }


def issue_recovery_authorization(
    task: OutboxTask,
    source_receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    issuer: str,
    issued_at: str,
    expires_at: str,
    signing_keys: Iterable[SigningKey],
) -> RecoveryAuthorization:
    """Authorize one exact corrected bundle only after verified campaign completion."""

    _nonempty(issuer, "issuer")
    issued = _timestamp(issued_at, "issued_at")
    expires = _timestamp(expires_at, "expires_at")
    if expires <= issued:
        raise ReplayInputError("expires_at must be later than issued_at")
    keys = tuple(signing_keys)
    if not keys:
        raise ReplayInputError("at least one recovery authorization signing key is required")
    facts = _recovery_facts(task, source_receipt, bundle)
    material: dict[str, Any] = {
        **facts,
        "source_payload_digest": _digest_object(facts["source_payload_digest"]),
        "writeback_evidence_digest": _digest_object(facts["writeback_evidence_digest"]),
        "issuer": issuer,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "revoked": False,
        "policy_version": RECOVERY_AUTHORIZATION_POLICY_VERSION,
        "scope": "CORRECTED_REPLAY_BUNDLE",
    }
    digest = _authorization_digest(material)
    return RecoveryAuthorization(
        authorization_id=f"gbx:recovery-authorization:sha256:{digest}",
        signatures=tuple(_sign(digest, key) for key in keys),
        **facts,
        issuer=issuer,
        issued_at=issued_at,
        expires_at=expires_at,
        revoked=False,
    )


def verify_recovery_authorization(
    authorization: RecoveryAuthorization,
    task: OutboxTask,
    source_receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    evaluated_at: str,
    trusted_signer_fingerprints: Mapping[str, str],
) -> RecoveryAuthorizationVerification:
    """Recheck live campaign evidence and exact signed bundle authorization."""

    errors: list[str] = []
    digest = _authorization_digest(authorization._material())
    authorization_id_valid = hmac.compare_digest(
        authorization.authorization_id,
        f"gbx:recovery-authorization:sha256:{digest}",
    )
    if not authorization_id_valid:
        errors.append("authorization ID does not match its canonical material")

    signature_results = tuple(_verify_signature(item, digest) for item in authorization.signatures)
    signatures_valid = bool(signature_results) and all(signature_results)
    if not signatures_valid:
        errors.append("recovery authorization signature verification failed")
    trusted_signer_present = any(
        valid
        and trusted_signer_fingerprints.get(signature.key_id)
        == _public_key_fingerprint(signature.public_key)
        for signature, valid in zip(
            authorization.signatures,
            signature_results,
            strict=True,
        )
    )
    if not trusted_signer_present:
        errors.append("authorization has no fingerprint-bound trusted signer")

    try:
        facts = _recovery_facts(task, source_receipt, bundle)
        operational_binding_valid = True
    except (ReplayExecutionError, ReplayInputError, ValueError):
        facts = {}
        operational_binding_valid = False
        errors.append("completed stale campaign evidence does not authorize recovery")
    expected = {
        **facts,
        "policy_version": RECOVERY_AUTHORIZATION_POLICY_VERSION,
        "scope": "CORRECTED_REPLAY_BUNDLE",
    }
    actual = {key: getattr(authorization, key) for key in expected}
    exact_binding_valid = operational_binding_valid and actual == expected
    if not exact_binding_valid:
        errors.append("authorization does not bind the exact campaign, receipt, and bundle")

    try:
        evaluated = _timestamp(evaluated_at, "evaluated_at")
        issued = _timestamp(authorization.issued_at, "issued_at")
        expires = _timestamp(authorization.expires_at, "expires_at")
        time_valid = issued <= evaluated < expires
    except ReplayInputError:
        time_valid = False
    if not time_valid:
        errors.append("recovery authorization is not valid at the evaluation time")
    not_revoked = not authorization.revoked
    if not not_revoked:
        errors.append("recovery authorization is revoked")

    valid = (
        authorization_id_valid
        and signatures_valid
        and trusted_signer_present
        and operational_binding_valid
        and exact_binding_valid
        and time_valid
        and not_revoked
    )
    return RecoveryAuthorizationVerification(
        valid=valid,
        authorization_id_valid=authorization_id_valid,
        signatures_valid=signatures_valid,
        trusted_signer_present=trusted_signer_present,
        operational_binding_valid=operational_binding_valid,
        exact_binding_valid=exact_binding_valid,
        time_valid=time_valid,
        not_revoked=not_revoked,
        errors=tuple(errors),
    )


def _recovery_facts(
    task: OutboxTask,
    source_receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
) -> dict[str, Any]:
    source_verification = verify_receipt(source_receipt, require_signature=True)
    if not source_verification.valid:
        raise ReplayExecutionError("recovery source receipt verification failed")
    bundle_verification = verify_replay_bundle(
        bundle,
        source_receipt=source_receipt,
        require_signature=True,
        require_source_signature=True,
    )
    if not bundle_verification.valid:
        raise ReplayExecutionError("recovery replay bundle verification failed")
    if task.status is not OutboxStatus.COMPLETED:
        raise ReplayExecutionError("recovery requires a completed invalidation campaign")
    if task.write_evidence is None or not task.write_evidence.valid:
        raise ReplayExecutionError("recovery requires verified DataHub writeback evidence")
    receipt_id = _text(source_receipt, "receipt_id")
    findings = tuple(item for item in task.campaign.assessments if item.receipt_id == receipt_id)
    if len(findings) != 1:
        raise ReplayExecutionError("campaign must contain exactly one source receipt finding")
    finding = findings[0]
    if finding.state is not ImpactState.STALE or not finding.matched_evidence_ids:
        raise ReplayExecutionError("only an exact STALE finding can authorize corrected replay")
    if finding.document_urn not in task.write_evidence.quarantined_documents:
        raise ReplayExecutionError("source receipt quarantine was not directly verified")
    if bundle.get("mode") != ReplayMode.CORRECTED.value:
        raise ReplayExecutionError("campaign recovery requires a CORRECTED replay bundle")

    context = _list_of_mappings(bundle, "context")
    source_evidence = {
        _text(item, "evidence_id"): item for item in _list_of_mappings(source_receipt, "evidence")
    }
    corrected_evidence = {
        _text(item, "evidence_id")
        for item in context
        if item.get("origin") == "CONTEXT_REPLACEMENT"
    }
    matched = set(finding.matched_evidence_ids)
    if corrected_evidence != matched:
        raise ReplayExecutionError("corrected context must exactly match stale evidence")
    for item in context:
        evidence_id = _text(item, "evidence_id")
        if evidence_id not in matched:
            continue
        original = source_evidence.get(evidence_id)
        if (
            original is None
            or _nested_digest(item, "original_representation_digest")
            != _nested_digest(original, "representation_digest")
            or _nested_digest(item, "active_representation_digest")
            == _nested_digest(item, "original_representation_digest")
            or not isinstance(item.get("verification_authority"), str)
        ):
            raise ReplayExecutionError("corrected context source binding is invalid")
    recipe = _mapping(bundle, "recipe")
    source_actions = {
        _text(item, "action_id"): item for item in _list_of_mappings(source_receipt, "actions")
    }
    action_evidence: set[str] = set()
    for action in _list_of_mappings(recipe, "actions"):
        raw = action.get("input_evidence_ids", [])
        if not isinstance(raw, list) or not all(isinstance(item, str) for item in raw):
            raise ReplayExecutionError("corrected action input evidence binding is invalid")
        action_evidence.update(raw)
        if raw:
            action_id = _text(action, "action_id")
            original_action = source_actions.get(action_id)
            if (
                original_action is None
                or action.get("input_origin") != "CONTEXT_REPLACEMENT"
                or _nested_digest(action, "original_input_digest")
                != _nested_digest(original_action, "input_digest")
                or _nested_digest(action, "input_digest")
                == _nested_digest(action, "original_input_digest")
            ):
                raise ReplayExecutionError("corrected action input source binding is invalid")
    if action_evidence != matched:
        raise ReplayExecutionError("corrected action inputs must exactly match stale evidence")

    integrity = _mapping(source_receipt, "integrity")
    source_digest = _nested_digest(integrity, "payload_digest")
    writeback_material = {
        "incident_aspects": sorted(task.write_evidence.incident_aspects),
        "target_summary_verified": task.write_evidence.target_summary_verified,
        "quarantined_documents": sorted(task.write_evidence.quarantined_documents),
    }
    return {
        "campaign_id": task.campaign.campaign_id,
        "incident_urn": task.campaign.incident_urn,
        "change_event_id": task.campaign.change.event_id,
        "source_receipt_id": receipt_id,
        "source_payload_digest": source_digest,
        "bundle_id": _text(bundle, "bundle_id"),
        "mode": ReplayMode.CORRECTED.value,
        "finding_state": finding.state.value,
        "finding_reason_code": finding.reason_code,
        "matched_evidence_ids": tuple(sorted(finding.matched_evidence_ids)),
        "campaign_policy_version": task.campaign.policy_version,
        "campaign_attempt_count": task.attempt_count,
        "writeback_evidence_digest": hashlib.sha256(canonicalize(writeback_material)).hexdigest(),
    }


def _authorization_digest(material: Mapping[str, Any]) -> str:
    return hashlib.sha256(_AUTHORIZATION_DOMAIN + canonicalize(material)).hexdigest()


def _authorization_id(material: Mapping[str, Any]) -> str:
    return f"gbx:recovery-authorization:sha256:{_authorization_digest(material)}"


def _sign(digest: str, key: SigningKey) -> RecoverySignature:
    public = key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    value = key.private_key.sign(_SIGNATURE_DOMAIN + bytes.fromhex(digest))
    return RecoverySignature(
        algorithm="Ed25519",
        key_id=key.key_id,
        public_key=_base64url_encode(public),
        value=_base64url_encode(value),
    )


def _verify_signature(signature: RecoverySignature, digest: str) -> bool:
    try:
        if signature.algorithm != "Ed25519":
            return False
        public = Ed25519PublicKey.from_public_bytes(_base64url_decode(signature.public_key, 32))
        value = _base64url_decode(signature.value, 64)
        public.verify(value, _SIGNATURE_DOMAIN + bytes.fromhex(digest))
        return True
    except (InvalidSignature, ValueError):
        return False


def _public_key_fingerprint(value: str) -> str | None:
    try:
        return hashlib.sha256(_base64url_decode(value, 32)).hexdigest()
    except ValueError:
        return None


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplayInputError(f"{name} must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplayInputError(f"{name} must include a timezone")
    return parsed.astimezone(UTC)


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayExecutionError(f"{key} must be an object")
    return selected


def _list_of_mappings(value: Mapping[str, Any], key: str) -> tuple[Mapping[str, Any], ...]:
    selected = value.get(key)
    if not isinstance(selected, list) or not all(isinstance(item, Mapping) for item in selected):
        raise ReplayExecutionError(f"{key} must be an array of objects")
    return tuple(selected)


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayExecutionError(f"{key} must be a non-empty string")
    return selected


def _nested_digest(value: Mapping[str, Any], key: str) -> str:
    selected = _mapping(value, key)
    if selected.get("algorithm") != "sha256":
        raise ReplayExecutionError(f"{key} must use sha256")
    return _text(selected, "value")


def _digest_object(value: str) -> dict[str, str]:
    return {"algorithm": "sha256", "value": value}


def _nonempty(value: str, name: str) -> None:
    if not value:
        raise ReplayInputError(f"{name} must be non-empty")


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _base64url_decode(value: str, size: int) -> bytes:
    decoded = base64.b64decode(
        value + "=" * (-len(value) % 4),
        altchars=b"-_",
        validate=True,
    )
    if len(decoded) != size:
        raise ValueError("signature material has an invalid length")
    return decoded


__all__ = [
    "RECOVERY_AUTHORIZATION_POLICY_VERSION",
    "RecoveryAuthorization",
    "RecoveryAuthorizationVerification",
    "RecoverySignature",
    "issue_recovery_authorization",
    "verify_recovery_authorization",
]
