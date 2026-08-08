"""Signed, content-addressed transfer of trusted receipts between state engines."""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator, FormatChecker

from glassbox_dbom import SignerStatus, SignerTrustPolicy, SigningKey
from glassbox_dbom.canonical import canonicalize
from glassbox_dbom.errors import CanonicalizationError
from glassbox_invalidation.transactional_protocol import TransactionalInvalidationStore
from glassbox_invalidation.transactional_store import (
    OutboxTask,
    OwnerRoutingTask,
    ReceiptPublicationTask,
    TransactionalIntegrityReport,
    _campaign_to_dict,
    _evidence_to_dict,
    _lineage_to_dict,
    _publication_evidence_to_dict,
    _routing_evidence_to_dict,
)
from glassbox_policy import (
    FieldCoverage,
    FieldLineageProof,
    PolicyInputError,
    ReceiptDependencyProfile,
)

STATE_TRANSFER_SPEC_VERSION = "0.1.0"
_BUNDLE_PREFIX = "gbx:state-transfer:sha256:"
_PAYLOAD_DOMAIN = b"glassbox.state-transfer.payload.v1\0"
_SIGNATURE_DOMAIN = b"glassbox.state-transfer.signature.v1\0"
_SCHEMA_RELATIVE_PATH = (
    Path("schemas") / "state-transfer" / STATE_TRANSFER_SPEC_VERSION / "schema.json"
)
_PACKAGED_SCHEMA_RELATIVE_PATH = (
    Path("schemas") / "state-transfer" / STATE_TRANSFER_SPEC_VERSION / "schema.json"
)
_MAX_BUNDLE_BYTES = 128 * 1024 * 1024


class StateTransferError(RuntimeError):
    """A state-transfer artifact or operation failed closed."""


@dataclass(frozen=True)
class StateTransferSignatureResult:
    """Raw-free verification result for one embedded transfer signature."""

    key_id: str
    public_key_sha256: str | None
    cryptographically_valid: bool
    trusted: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "public_key_sha256": self.public_key_sha256,
            "cryptographically_valid": self.cryptographically_valid,
            "trusted": self.trusted,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class StateTransferVerification:
    """Deterministic envelope, authority, and receipt-admission verification."""

    schema_valid: bool
    payload_digest_valid: bool
    bundle_id_valid: bool
    receipt_set_valid: bool
    archive_counts_valid: bool
    minimum_trusted_signatures: int
    signatures: tuple[StateTransferSignatureResult, ...]
    errors: tuple[str, ...]

    @property
    def trusted_signature_count(self) -> int:
        return sum(item.trusted for item in self.signatures)

    @property
    def valid(self) -> bool:
        return (
            self.schema_valid
            and self.payload_digest_valid
            and self.bundle_id_valid
            and self.receipt_set_valid
            and self.archive_counts_valid
            and bool(self.signatures)
            and all(item.cryptographically_valid for item in self.signatures)
            and self.trusted_signature_count >= self.minimum_trusted_signatures
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "schema_valid": self.schema_valid,
            "payload_digest_valid": self.payload_digest_valid,
            "bundle_id_valid": self.bundle_id_valid,
            "receipt_set_valid": self.receipt_set_valid,
            "archive_counts_valid": self.archive_counts_valid,
            "minimum_trusted_signatures": self.minimum_trusted_signatures,
            "trusted_signature_count": self.trusted_signature_count,
            "signatures": [item.to_dict() for item in self.signatures],
            "errors": list(self.errors),
            "raw_content_returned": False,
        }


@dataclass(frozen=True)
class StateTransferImportReport:
    """Raw-free result of one atomic receipt activation."""

    bundle_id: str
    source_engine: str
    source_schema_version: str
    receipts: int
    inserted: int
    reused: int
    target: TransactionalIntegrityReport

    @property
    def valid(self) -> bool:
        return self.inserted + self.reused == self.receipts

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "bundle_id": self.bundle_id,
            "source": {
                "engine": self.source_engine,
                "schema_version": self.source_schema_version,
            },
            "receipts": {
                "total": self.receipts,
                "inserted": self.inserted,
                "reused": self.reused,
            },
            "target": {
                "receipts": self.target.receipts,
                "dependencies": self.target.dependencies,
                "receipt_publication_tasks": self.target.receipt_publication_tasks,
            },
            "operational_archive_activated": False,
            "publication_obligations_created": self.inserted,
            "raw_content_returned": False,
        }


def build_state_transfer_bundle(
    store: TransactionalInvalidationStore,
    *,
    source_engine: str,
    source_schema_version: str,
    signing_keys: Sequence[SigningKey],
    bundle_trust_policy: SignerTrustPolicy,
    receipt_trust_policy: SignerTrustPolicy | None,
    evaluated_at: datetime | None = None,
) -> dict[str, Any]:
    """Verify state and build a deterministic signed receipt-transfer artifact."""

    if source_engine not in {"SQLITE", "POSTGRESQL"}:
        raise StateTransferError("state-transfer source engine is unsupported")
    if not source_schema_version or len(source_schema_version) > 32:
        raise StateTransferError("state-transfer source schema version is invalid")
    if not signing_keys:
        raise StateTransferError("state-transfer export requires at least one signing key")
    if len(signing_keys) > 16:
        raise StateTransferError("state-transfer signing-key count exceeds the limit")
    key_ids = [item.key_id for item in signing_keys]
    if len(key_ids) != len(set(key_ids)):
        raise StateTransferError("state-transfer signing key IDs must be unique")
    for key in signing_keys:
        bundle_trust_policy.require_active_signing_key(key, evaluated_at=evaluated_at)

    integrity = store.verify_integrity()
    profiles = store.all_profiles()
    receipts: list[dict[str, object]] = []
    for profile in sorted(profiles, key=lambda item: item.receipt_id):
        receipt = store.get_receipt(profile.receipt_id)
        if receipt is None:
            raise StateTransferError("verified source receipt disappeared during export")
        receipts.append(
            {
                "receipt": copy.deepcopy(dict(receipt)),
                "field_lineage": _lineage_to_dict(profile.field_lineage),
                "superseded_by": profile.superseded_by,
            }
        )

    payload: dict[str, Any] = {
        "spec_version": STATE_TRANSFER_SPEC_VERSION,
        "source": {
            "engine": source_engine,
            "schema_version": source_schema_version,
            "integrity_verified": True,
            "import_scope": "RECEIPTS_ONLY",
            "counts": _integrity_counts(integrity),
        },
        "receipts": receipts,
        "operational_archive": _operational_archive(store),
    }
    digest = state_transfer_payload_digest(payload)
    payload["bundle_id"] = f"{_BUNDLE_PREFIX}{digest}"
    payload["integrity"] = {
        "canonicalization": "RFC8785",
        "payload_digest": {"algorithm": "sha256", "value": digest},
        "signatures": [_create_signature(digest, key) for key in signing_keys],
    }
    validate_state_transfer_bundle(payload)
    verification = verify_state_transfer_bundle(
        payload,
        bundle_trust_policy=bundle_trust_policy,
        receipt_trust_policy=receipt_trust_policy,
        evaluated_at=evaluated_at,
    )
    if not verification.valid:
        raise StateTransferError("newly built state-transfer bundle failed verification")
    return payload


def verify_state_transfer_bundle(
    bundle: Mapping[str, Any],
    *,
    bundle_trust_policy: SignerTrustPolicy,
    receipt_trust_policy: SignerTrustPolicy | None,
    evaluated_at: datetime | None = None,
) -> StateTransferVerification:
    """Verify bundle integrity, export authority, and current receipt admission."""

    errors: list[str] = []
    try:
        validate_state_transfer_bundle(bundle)
        schema_valid = True
    except StateTransferError:
        schema_valid = False
        errors.append("SCHEMA_INVALID")

    try:
        expected_digest = state_transfer_payload_digest(bundle)
        canonical_payload_valid = True
    except CanonicalizationError:
        expected_digest = "0" * 64
        canonical_payload_valid = False
        errors.append("PAYLOAD_CANONICALIZATION_INVALID")
    integrity = bundle.get("integrity")
    integrity_mapping = integrity if isinstance(integrity, Mapping) else {}
    recorded_digest = _nested_digest(integrity_mapping, "payload_digest")
    payload_digest_valid = (
        canonical_payload_valid
        and recorded_digest is not None
        and hmac.compare_digest(expected_digest, recorded_digest)
    )
    if not payload_digest_valid:
        errors.append("PAYLOAD_DIGEST_INVALID")
    expected_id = f"{_BUNDLE_PREFIX}{expected_digest}"
    bundle_id = bundle.get("bundle_id")
    bundle_id_valid = (
        canonical_payload_valid
        and isinstance(bundle_id, str)
        and hmac.compare_digest(expected_id, bundle_id)
    )
    if not bundle_id_valid:
        errors.append("BUNDLE_ID_INVALID")

    signatures = _verify_signatures(
        integrity_mapping,
        expected_digest,
        policy=bundle_trust_policy,
        evaluated_at=evaluated_at,
    )
    if not signatures:
        errors.append("SIGNATURE_REQUIRED")
    if any(not item.cryptographically_valid for item in signatures):
        errors.append("SIGNATURE_INVALID")
    trusted_count = sum(item.trusted for item in signatures)
    if trusted_count < bundle_trust_policy.minimum_trusted_signatures:
        errors.append("TRUSTED_SIGNATURE_THRESHOLD_NOT_MET")

    receipt_set_valid = _verify_receipt_set(
        bundle,
        receipt_trust_policy=receipt_trust_policy,
    )
    if not receipt_set_valid:
        errors.append("RECEIPT_SET_INVALID")
    archive_counts_valid = _verify_archive_counts(bundle)
    if not archive_counts_valid:
        errors.append("ARCHIVE_COUNTS_INVALID")
    return StateTransferVerification(
        schema_valid=schema_valid,
        payload_digest_valid=payload_digest_valid,
        bundle_id_valid=bundle_id_valid,
        receipt_set_valid=receipt_set_valid,
        archive_counts_valid=archive_counts_valid,
        minimum_trusted_signatures=bundle_trust_policy.minimum_trusted_signatures,
        signatures=signatures,
        errors=tuple(sorted(set(errors))),
    )


def import_state_transfer_bundle(
    store: TransactionalInvalidationStore,
    bundle: Mapping[str, Any],
    *,
    bundle_trust_policy: SignerTrustPolicy,
    receipt_trust_policy: SignerTrustPolicy,
    evaluated_at: datetime | None = None,
) -> StateTransferImportReport:
    """Atomically activate all transferred receipts under current admission policy."""

    verification = verify_state_transfer_bundle(
        bundle,
        bundle_trust_policy=bundle_trust_policy,
        receipt_trust_policy=receipt_trust_policy,
        evaluated_at=evaluated_at,
    )
    if not verification.valid:
        raise StateTransferError(
            "state-transfer import verification failed (" + ",".join(verification.errors) + ")"
        )
    registrations = _registrations(bundle)
    outcomes = store.register_many(registrations)
    target = store.verify_integrity()
    if len(outcomes) != len(registrations):  # pragma: no cover - protocol contract
        raise StateTransferError("state-transfer target returned an incomplete batch result")
    source = _mapping(bundle.get("source"), "state-transfer source")
    return StateTransferImportReport(
        bundle_id=_text(bundle, "bundle_id"),
        source_engine=_text(source, "engine"),
        source_schema_version=_text(source, "schema_version"),
        receipts=len(registrations),
        inserted=sum(outcomes),
        reused=len(outcomes) - sum(outcomes),
        target=target,
    )


def state_transfer_payload_material(bundle: Mapping[str, Any]) -> dict[str, Any]:
    """Return the exact material committed by the state-transfer payload digest."""

    material = copy.deepcopy(dict(bundle))
    material.pop("bundle_id", None)
    material.pop("integrity", None)
    return material


def state_transfer_payload_digest(bundle: Mapping[str, Any]) -> str:
    """Return the domain-separated canonical payload digest."""

    material = canonicalize(state_transfer_payload_material(bundle))
    return hashlib.sha256(_PAYLOAD_DOMAIN + material).hexdigest()


def load_state_transfer_schema(path: Path | None = None) -> dict[str, Any]:
    """Load the normative state-transfer schema from source, wheel, or a path."""

    if path is not None:
        return _read_schema(path)
    repository = Path(__file__).resolve().parents[4] / _SCHEMA_RELATIVE_PATH
    if repository.is_file():
        return _read_schema(repository)
    packaged = resources.files("glassbox_invalidation").joinpath(
        str(_PACKAGED_SCHEMA_RELATIVE_PATH)
    )
    with packaged.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise StateTransferError("state-transfer schema root must be an object")
    return value


def validate_state_transfer_bundle(
    bundle: Mapping[str, Any],
    *,
    schema: Mapping[str, Any] | None = None,
) -> None:
    """Validate the normative envelope and raise deterministic bounded failures."""

    selected = dict(schema) if schema is not None else load_state_transfer_schema()
    validator = Draft202012Validator(selected, format_checker=FormatChecker())
    failures = sorted(validator.iter_errors(bundle), key=lambda item: list(item.path))
    if failures:
        raise StateTransferError("state-transfer bundle failed schema validation")


def load_state_transfer_bundle(path: Path) -> dict[str, Any]:
    """Load one bounded regular-file bundle without following symbolic links."""

    encoded = _read_bounded_regular_file(path)
    try:
        value = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateTransferError("state-transfer bundle is not valid JSON") from exc
    if not isinstance(value, dict):
        raise StateTransferError("state-transfer bundle root must be an object")
    return value


def write_state_transfer_bundle(path: Path, bundle: Mapping[str, Any]) -> None:
    """Create one private bundle file atomically and refuse overwrites."""

    validate_state_transfer_bundle(bundle)
    try:
        expected_digest = state_transfer_payload_digest(bundle)
    except CanonicalizationError as exc:
        raise StateTransferError("state-transfer payload is not canonicalizable") from exc
    integrity = _mapping(bundle.get("integrity"), "state-transfer integrity")
    recorded_digest = _nested_digest(integrity, "payload_digest")
    bundle_id = bundle.get("bundle_id")
    if (
        recorded_digest is None
        or not hmac.compare_digest(expected_digest, recorded_digest)
        or not isinstance(bundle_id, str)
        or not hmac.compare_digest(f"{_BUNDLE_PREFIX}{expected_digest}", bundle_id)
    ):
        raise StateTransferError("state-transfer output failed content-address verification")
    if not path.parent.is_dir():
        raise StateTransferError("state-transfer output parent directory does not exist")
    encoded = (json.dumps(bundle, indent=2, sort_keys=True) + "\n").encode()
    if len(encoded) > _MAX_BUNDLE_BYTES:
        raise StateTransferError("state-transfer bundle exceeds the file-size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise StateTransferError("state-transfer output must be a new file") from exc
    try:
        try:
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except (OSError, StateTransferError) as exc:
        try:
            path.unlink()
        except OSError:
            pass
        raise StateTransferError("state-transfer bundle write failed") from exc


def _operational_archive(store: TransactionalInvalidationStore) -> dict[str, object]:
    return {
        "activated_on_import": False,
        "receipt_publication_tasks": [
            _publication_task_to_dict(item) for item in store.list_receipt_publication_tasks()
        ],
        "campaign_tasks": [_campaign_task_to_dict(item) for item in store.list_tasks()],
        "owner_routing_tasks": [
            _routing_task_to_dict(item) for item in store.list_owner_routing_tasks()
        ],
        "audit_records": [item.to_dict() for item in store.read_audit_records()],
    }


def _publication_task_to_dict(task: ReceiptPublicationTask) -> dict[str, object]:
    return {
        "receipt_id": task.receipt_id,
        "status": task.status.value,
        "attempt_count": task.attempt_count,
        "lease_owner": task.lease_owner,
        "lease_expires_at_ms": task.lease_expires_at_ms,
        "last_error_type": task.last_error_type,
        "publication_evidence": (
            _publication_evidence_to_dict(task.publication_evidence)
            if task.publication_evidence is not None
            else None
        ),
    }


def _campaign_task_to_dict(task: OutboxTask) -> dict[str, object]:
    return {
        "campaign": _campaign_to_dict(task.campaign),
        "status": task.status.value,
        "attempt_count": task.attempt_count,
        "lease_owner": task.lease_owner,
        "lease_expires_at_ms": task.lease_expires_at_ms,
        "last_error_type": task.last_error_type,
        "write_evidence": (
            _evidence_to_dict(task.write_evidence) if task.write_evidence is not None else None
        ),
    }


def _routing_task_to_dict(task: OwnerRoutingTask) -> dict[str, object]:
    return {
        "campaign_id": task.campaign_id,
        "status": task.status.value,
        "attempt_count": task.attempt_count,
        "lease_owner": task.lease_owner,
        "lease_expires_at_ms": task.lease_expires_at_ms,
        "last_error_type": task.last_error_type,
        "delivery_evidence": (
            _routing_evidence_to_dict(task.delivery_evidence)
            if task.delivery_evidence is not None
            else None
        ),
    }


def _integrity_counts(report: TransactionalIntegrityReport) -> dict[str, int]:
    return {
        "receipts": report.receipts,
        "dependencies": report.dependencies,
        "campaigns": report.campaigns,
        "audit_records": report.audit_records,
        "owner_routing_tasks": report.owner_routing_tasks,
        "receipt_publication_tasks": report.receipt_publication_tasks,
    }


def _verify_archive_counts(bundle: Mapping[str, Any]) -> bool:
    try:
        source = _mapping(bundle.get("source"), "state-transfer source")
        counts = _mapping(source.get("counts"), "state-transfer source counts")
        archive = _mapping(bundle.get("operational_archive"), "operational archive")
        receipts = bundle.get("receipts")
        if not isinstance(receipts, list):
            return False
        return (
            counts.get("receipts") == len(receipts)
            and counts.get("receipt_publication_tasks")
            == len(_list(archive, "receipt_publication_tasks"))
            and counts.get("campaigns") == len(_list(archive, "campaign_tasks"))
            and counts.get("owner_routing_tasks") == len(_list(archive, "owner_routing_tasks"))
            and counts.get("audit_records") == len(_list(archive, "audit_records"))
            and archive.get("activated_on_import") is False
        )
    except StateTransferError:
        return False


def _verify_receipt_set(
    bundle: Mapping[str, Any],
    *,
    receipt_trust_policy: SignerTrustPolicy | None,
) -> bool:
    try:
        registrations = _registrations(bundle)
        identifiers: list[str] = []
        dependency_count = 0
        for receipt, lineage, superseded_by in registrations:
            profile = ReceiptDependencyProfile.from_receipt(
                receipt,
                field_lineage=lineage,
                superseded_by=superseded_by,
                require_signature=True,
                signer_trust_policy=receipt_trust_policy,
            )
            identifiers.append(profile.receipt_id)
            dependency_count += len(profile.dependencies)
        if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
            return False
        source = _mapping(bundle.get("source"), "state-transfer source")
        counts = _mapping(source.get("counts"), "state-transfer source counts")
        return counts.get("dependencies") == dependency_count
    except (CanonicalizationError, PolicyInputError, StateTransferError):
        return False


def _registrations(
    bundle: Mapping[str, Any],
) -> tuple[tuple[Mapping[str, Any], FieldLineageProof, str | None], ...]:
    raw_receipts = bundle.get("receipts")
    if not isinstance(raw_receipts, list):
        raise StateTransferError("state-transfer receipts must be an array")
    registrations: list[tuple[Mapping[str, Any], FieldLineageProof, str | None]] = []
    for value in raw_receipts:
        entry = _mapping(value, "state-transfer receipt entry")
        receipt = _mapping(entry.get("receipt"), "state-transfer receipt")
        lineage = _parse_lineage(entry.get("field_lineage"))
        superseded_by = entry.get("superseded_by")
        if superseded_by is not None and not isinstance(superseded_by, str):
            raise StateTransferError("state-transfer superseded_by is invalid")
        registrations.append((copy.deepcopy(dict(receipt)), lineage, superseded_by))
    return tuple(registrations)


def _parse_lineage(value: object) -> FieldLineageProof:
    selected = _mapping(value, "state-transfer field lineage")
    coverage = selected.get("coverage")
    rule_id = selected.get("rule_id")
    wildcard = selected.get("wildcard_query")
    if not isinstance(coverage, str):
        raise StateTransferError("state-transfer field-lineage coverage is invalid")
    if rule_id is not None and not isinstance(rule_id, str):
        raise StateTransferError("state-transfer field-lineage rule ID is invalid")
    if wildcard is not None and not isinstance(wildcard, bool):
        raise StateTransferError("state-transfer wildcard flag is invalid")
    try:
        return FieldLineageProof(
            coverage=FieldCoverage(coverage),
            rule_id=rule_id,
            wildcard_query=wildcard,
        )
    except (ValueError, PolicyInputError) as exc:
        raise StateTransferError("state-transfer field-lineage proof is invalid") from exc


def _create_signature(digest: str, key: SigningKey) -> dict[str, str]:
    public_key = key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    signature = key.private_key.sign(_SIGNATURE_DOMAIN + bytes.fromhex(digest))
    return {
        "algorithm": "Ed25519",
        "key_id": key.key_id,
        "public_key": _base64url_encode(public_key),
        "value": _base64url_encode(signature),
    }


def _verify_signatures(
    integrity: Mapping[str, Any],
    digest: str,
    *,
    policy: SignerTrustPolicy,
    evaluated_at: datetime | None,
) -> tuple[StateTransferSignatureResult, ...]:
    raw_signatures = integrity.get("signatures")
    if not isinstance(raw_signatures, list):
        return ()
    configured = {item.key_id: item for item in policy.signers}
    now = _aware_utc(evaluated_at or datetime.now(UTC))
    results: list[StateTransferSignatureResult] = []
    seen: set[str] = set()
    for raw in raw_signatures:
        if not isinstance(raw, Mapping):
            results.append(_invalid_signature("<malformed>", "SIGNATURE_MALFORMED"))
            continue
        key_id = raw.get("key_id")
        display_id = key_id if isinstance(key_id, str) else "<malformed>"
        if display_id in seen:
            results.append(_invalid_signature(display_id, "DUPLICATE_KEY_ID"))
            continue
        seen.add(display_id)
        try:
            if raw.get("algorithm") != "Ed25519":
                raise ValueError("algorithm")
            public_key = _base64url_decode(_text(raw, "public_key"), 32)
            signature = _base64url_decode(_text(raw, "value"), 64)
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                signature,
                _SIGNATURE_DOMAIN + bytes.fromhex(digest),
            )
        except (InvalidSignature, StateTransferError, ValueError):
            results.append(_invalid_signature(display_id, "SIGNATURE_INVALID"))
            continue
        fingerprint = hashlib.sha256(public_key).hexdigest()
        signer = configured.get(display_id)
        reason = "TRUSTED"
        if signer is None:
            reason = "UNKNOWN_KEY_ID"
        elif not hmac.compare_digest(fingerprint, signer.public_key_sha256):
            reason = "PUBLIC_KEY_MISMATCH"
        elif signer.status is SignerStatus.REVOKED:
            reason = "SIGNER_REVOKED"
        elif signer.status is SignerStatus.RETIRED:
            reason = "SIGNER_RETIRED"
        elif now < signer.starts_at:
            reason = "BEFORE_VALIDITY_WINDOW"
        elif signer.ends_at is not None and now >= signer.ends_at:
            reason = "AFTER_VALIDITY_WINDOW"
        results.append(
            StateTransferSignatureResult(
                key_id=display_id,
                public_key_sha256=fingerprint,
                cryptographically_valid=True,
                trusted=reason == "TRUSTED",
                reason=reason,
            )
        )
    return tuple(results)


def _invalid_signature(key_id: str, reason: str) -> StateTransferSignatureResult:
    return StateTransferSignatureResult(
        key_id=key_id,
        public_key_sha256=None,
        cryptographically_valid=False,
        trusted=False,
        reason=reason,
    )


def _read_bounded_regular_file(path: Path) -> bytes:
    if path.is_symlink():
        raise StateTransferError("state-transfer path must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise StateTransferError("state-transfer file is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise StateTransferError("state-transfer path must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_BUNDLE_BYTES:
            raise StateTransferError("state-transfer file size is outside the limit")
        chunks: list[bytes] = []
        remaining = _MAX_BUNDLE_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
    except OSError as exc:
        raise StateTransferError("state-transfer file could not be read") from exc
    finally:
        os.close(descriptor)
    if len(encoded) != metadata.st_size:
        raise StateTransferError("state-transfer file changed while it was being read")
    return encoded


def _read_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StateTransferError("state-transfer schema is not valid JSON") from exc
    if not isinstance(value, dict):
        raise StateTransferError("state-transfer schema root must be an object")
    return value


def _nested_digest(value: Mapping[str, Any], key: str) -> str | None:
    nested = value.get(key)
    if not isinstance(nested, Mapping):
        return None
    selected = nested.get("value")
    return selected if isinstance(selected, str) else None


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StateTransferError(f"{label} must be an object")
    return value


def _list(value: Mapping[str, Any], key: str) -> list[object]:
    selected = value.get(key)
    if not isinstance(selected, list):
        raise StateTransferError(f"state-transfer field {key!r} must be an array")
    return selected


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise StateTransferError(f"state-transfer field {key!r} must be non-empty")
    return selected


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _base64url_decode(value: str, expected_bytes: int) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (TypeError, ValueError) as exc:
        raise StateTransferError("state-transfer signature encoding is invalid") from exc
    if len(decoded) != expected_bytes or _base64url_encode(decoded) != value:
        raise StateTransferError("state-transfer signature encoding is non-canonical")
    return decoded


def _aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise StateTransferError("state-transfer evaluation time must include a timezone")
    return value.astimezone(UTC)


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - operating-system contract
            raise StateTransferError("state-transfer write made no forward progress")
        remaining = remaining[written:]


__all__ = [
    "STATE_TRANSFER_SPEC_VERSION",
    "StateTransferError",
    "StateTransferImportReport",
    "StateTransferSignatureResult",
    "StateTransferVerification",
    "build_state_transfer_bundle",
    "import_state_transfer_bundle",
    "load_state_transfer_bundle",
    "load_state_transfer_schema",
    "state_transfer_payload_digest",
    "state_transfer_payload_material",
    "validate_state_transfer_bundle",
    "verify_state_transfer_bundle",
    "write_state_transfer_bundle",
]
