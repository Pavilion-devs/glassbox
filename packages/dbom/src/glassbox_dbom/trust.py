"""Operator-controlled trust policy for DBOM receipt signers and key rotation."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from importlib import resources
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from jsonschema import Draft202012Validator, FormatChecker

from glassbox_dbom.errors import DBOMError
from glassbox_dbom.integrity import SigningKey, VerificationReport, verify_receipt

TRUST_POLICY_SCHEMA_VERSION = "glassbox.signer-trust.v1"
_SCHEMA_VERSION = "0.1.0"
_SCHEMA_RELATIVE_PATH = Path("schemas") / "signer-trust" / _SCHEMA_VERSION / "schema.json"
_MAX_POLICY_BYTES = 1024 * 1024


class SignerTrustError(DBOMError):
    """A signer policy or receipt authorization decision failed closed."""


class SignerStatus(StrEnum):
    """Operator-controlled lifecycle state for one receipt signing key."""

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


class SignerTrustMode(StrEnum):
    """Whether a receipt is entering state now or being read from immutable history."""

    ADMISSION = "ADMISSION"
    HISTORICAL = "HISTORICAL"


class SignerTrustReason(StrEnum):
    """Closed reason codes safe to expose in raw-free diagnostics."""

    TRUSTED = "TRUSTED"
    INTEGRITY_INVALID = "INTEGRITY_INVALID"
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    UNKNOWN_KEY_ID = "UNKNOWN_KEY_ID"
    PUBLIC_KEY_MISMATCH = "PUBLIC_KEY_MISMATCH"
    SIGNER_RETIRED = "SIGNER_RETIRED"
    SIGNER_REVOKED = "SIGNER_REVOKED"
    BEFORE_VALIDITY_WINDOW = "BEFORE_VALIDITY_WINDOW"
    AFTER_VALIDITY_WINDOW = "AFTER_VALIDITY_WINDOW"
    RECEIPT_TIME_INVALID = "RECEIPT_TIME_INVALID"


@dataclass(frozen=True)
class TrustedSigner:
    """One fingerprint-bound Ed25519 signer and its rotation window."""

    key_id: str
    public_key: str
    public_key_sha256: str
    status: SignerStatus
    not_before: str
    not_after: str | None

    def __post_init__(self) -> None:
        raw_public_key = _decode_public_key(self.public_key)
        fingerprint = hashlib.sha256(raw_public_key).hexdigest()
        if not hmac.compare_digest(fingerprint, self.public_key_sha256):
            raise SignerTrustError("trusted signer public-key fingerprint does not match")
        starts_at = _parse_timestamp(self.not_before, "trusted signer not_before")
        if self.not_after is not None:
            ends_at = _parse_timestamp(self.not_after, "trusted signer not_after")
            if ends_at <= starts_at:
                raise SignerTrustError("trusted signer not_after must be later than not_before")

    @property
    def starts_at(self) -> datetime:
        return _parse_timestamp(self.not_before, "trusted signer not_before")

    @property
    def ends_at(self) -> datetime | None:
        if self.not_after is None:
            return None
        return _parse_timestamp(self.not_after, "trusted signer not_after")


@dataclass(frozen=True)
class SignatureTrustResult:
    """Trust result for one receipt signature without exposing public-key material."""

    key_id: str
    public_key_sha256: str | None
    trusted: bool
    reason: SignerTrustReason

    def to_dict(self) -> dict[str, object]:
        return {
            "key_id": self.key_id,
            "public_key_sha256": self.public_key_sha256,
            "trusted": self.trusted,
            "reason": self.reason.value,
        }


@dataclass(frozen=True)
class SignerTrustReport:
    """Cryptographic and operator-trust result for one receipt."""

    policy_id: str
    mode: SignerTrustMode
    authorization_time: str | None
    minimum_trusted_signatures: int
    integrity: VerificationReport
    signatures: tuple[SignatureTrustResult, ...]

    @property
    def trusted_signature_count(self) -> int:
        return sum(item.trusted for item in self.signatures)

    @property
    def valid(self) -> bool:
        return (
            self.integrity.valid and self.trusted_signature_count >= self.minimum_trusted_signatures
        )

    @property
    def failure_codes(self) -> tuple[str, ...]:
        failures: set[str] = set()
        if not self.integrity.valid:
            failures.add(SignerTrustReason.INTEGRITY_INVALID.value)
        if self.trusted_signature_count < self.minimum_trusted_signatures:
            failures.update(item.reason.value for item in self.signatures if not item.trusted)
            failures.add("TRUSTED_SIGNATURE_THRESHOLD_NOT_MET")
        return tuple(sorted(failures))

    def to_dict(self) -> dict[str, object]:
        """Return bounded trust evidence without receipt bodies or public keys."""

        return {
            "valid": self.valid,
            "policy_id": self.policy_id,
            "mode": self.mode.value,
            "authorization_time": self.authorization_time,
            "minimum_trusted_signatures": self.minimum_trusted_signatures,
            "trusted_signature_count": self.trusted_signature_count,
            "integrity": {
                "valid": self.integrity.valid,
                "schema": self.integrity.schema_valid,
                "payload_digest": self.integrity.payload_digest_valid,
                "receipt_id": self.integrity.receipt_id_valid,
                "merkle_root": self.integrity.merkle_root_valid,
                "signature_count": len(self.integrity.signatures),
                "all_present_signatures": all(item.valid for item in self.integrity.signatures),
            },
            "signatures": [item.to_dict() for item in self.signatures],
            "failure_codes": list(self.failure_codes),
            "raw_content_returned": False,
        }


@dataclass(frozen=True)
class SignerAdmissionEvidence:
    """Checksummed state evidence that trusted admission occurred before persistence."""

    policy_id: str
    minimum_trusted_signatures: int
    trusted_signers: tuple[tuple[str, str], ...]

    def __post_init__(self) -> None:
        if not self.policy_id or self.policy_id != self.policy_id.strip():
            raise SignerTrustError("signer admission policy ID must be non-empty and trimmed")
        if self.minimum_trusted_signatures < 1:
            raise SignerTrustError("signer admission threshold must be positive")
        if len(self.trusted_signers) < self.minimum_trusted_signatures:
            raise SignerTrustError("signer admission evidence does not meet its threshold")
        if self.trusted_signers != tuple(sorted(self.trusted_signers)):
            raise SignerTrustError("signer admission identities must be canonically sorted")
        if len(self.trusted_signers) != len(set(self.trusted_signers)):
            raise SignerTrustError("signer admission identities must be unique")
        for key_id, fingerprint in self.trusted_signers:
            if not key_id or key_id != key_id.strip():
                raise SignerTrustError("signer admission key ID is invalid")
            if len(fingerprint) != 64 or any(
                character not in "0123456789abcdef" for character in fingerprint
            ):
                raise SignerTrustError("signer admission fingerprint is invalid")

    @classmethod
    def from_report(cls, report: SignerTrustReport) -> SignerAdmissionEvidence:
        """Create evidence only from a successful current-time admission report."""

        if report.mode is not SignerTrustMode.ADMISSION or not report.valid:
            raise SignerTrustError("signer admission evidence requires valid admission trust")
        identities = tuple(
            sorted(
                (item.key_id, item.public_key_sha256)
                for item in report.signatures
                if item.trusted and item.public_key_sha256 is not None
            )
        )
        return cls(
            policy_id=report.policy_id,
            minimum_trusted_signatures=report.minimum_trusted_signatures,
            trusted_signers=identities,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SignerAdmissionEvidence:
        """Strictly decode the internal state-record representation."""

        expected = {
            "policy_id",
            "minimum_trusted_signatures",
            "trusted_signers",
        }
        if set(value) != expected:
            raise SignerTrustError("signer admission evidence has unknown or missing fields")
        raw_identities = value.get("trusted_signers")
        if not isinstance(raw_identities, list):
            raise SignerTrustError("signer admission trusted_signers must be an array")
        identities: list[tuple[str, str]] = []
        for item in raw_identities:
            if not isinstance(item, Mapping) or set(item) != {
                "key_id",
                "public_key_sha256",
            }:
                raise SignerTrustError("signer admission identity is invalid")
            identities.append(
                (
                    _required_string(item, "key_id"),
                    _required_string(item, "public_key_sha256"),
                )
            )
        return cls(
            policy_id=_required_string(value, "policy_id"),
            minimum_trusted_signatures=_required_int(value, "minimum_trusted_signatures"),
            trusted_signers=tuple(identities),
        )

    def verify_receipt_binding(self, receipt: Mapping[str, Any]) -> None:
        """Require every attested identity to be a valid signature on this receipt."""

        integrity = verify_receipt(receipt, require_signature=True)
        if not integrity.valid:
            raise SignerTrustError("signer admission receipt integrity is invalid")
        raw_signatures = _signature_mappings(receipt)
        observed: set[tuple[str, str]] = set()
        for index, result in enumerate(integrity.signatures):
            raw_signature = raw_signatures[index] if index < len(raw_signatures) else None
            if not result.valid or raw_signature is None:
                continue
            public_key = raw_signature.get("public_key")
            if isinstance(public_key, str):
                observed.add(
                    (result.key_id, hashlib.sha256(_decode_public_key(public_key)).hexdigest())
                )
        if not set(self.trusted_signers).issubset(observed):
            raise SignerTrustError("signer admission evidence is not bound to receipt signatures")

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "minimum_trusted_signatures": self.minimum_trusted_signatures,
            "trusted_signers": [
                {"key_id": key_id, "public_key_sha256": fingerprint}
                for key_id, fingerprint in self.trusted_signers
            ],
        }


@dataclass(frozen=True)
class SignerTrustPolicy:
    """Closed trusted-signer registry with overlap-safe rotation semantics."""

    policy_id: str
    minimum_trusted_signatures: int
    signers: tuple[TrustedSigner, ...]
    schema_version: str = TRUST_POLICY_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != TRUST_POLICY_SCHEMA_VERSION:
            raise SignerTrustError("trusted signer policy schema version is unsupported")
        if not self.policy_id or self.policy_id != self.policy_id.strip():
            raise SignerTrustError("trusted signer policy_id must be non-empty and trimmed")
        if self.minimum_trusted_signatures < 1:
            raise SignerTrustError("minimum trusted signatures must be positive")
        if self.minimum_trusted_signatures > len(self.signers):
            raise SignerTrustError("minimum trusted signatures exceeds configured signers")
        key_ids = [item.key_id for item in self.signers]
        fingerprints = [item.public_key_sha256 for item in self.signers]
        if len(key_ids) != len(set(key_ids)):
            raise SignerTrustError("trusted signer key IDs must be unique")
        if len(fingerprints) != len(set(fingerprints)):
            raise SignerTrustError("trusted signer public-key fingerprints must be unique")

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> SignerTrustPolicy:
        """Validate the normative JSON contract and construct an immutable policy."""

        failures = _schema_failures(value)
        if failures:
            raise SignerTrustError(
                "trusted signer policy failed schema validation: " + "; ".join(failures)
            )
        raw_signers = value["signers"]
        if not isinstance(raw_signers, list):  # pragma: no cover - schema gate
            raise SignerTrustError("trusted signer policy signers must be an array")
        signers = tuple(_parse_signer(item) for item in raw_signers)
        return cls(
            schema_version=_required_string(value, "schema_version"),
            policy_id=_required_string(value, "policy_id"),
            minimum_trusted_signatures=_required_int(value, "minimum_trusted_signatures"),
            signers=signers,
        )

    def verify_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        mode: SignerTrustMode = SignerTrustMode.ADMISSION,
        evaluated_at: datetime | None = None,
    ) -> SignerTrustReport:
        """Require valid receipt integrity plus the configured signer threshold."""

        integrity = verify_receipt(receipt, require_signature=True)
        authorization_time, authorization_timestamp = _authorization_time(
            receipt,
            mode=mode,
            evaluated_at=evaluated_at,
        )
        configured = {item.key_id: item for item in self.signers}
        raw_signatures = _signature_mappings(receipt)
        results: list[SignatureTrustResult] = []
        for index, signature_result in enumerate(integrity.signatures):
            raw_signature = raw_signatures[index] if index < len(raw_signatures) else None
            results.append(
                _evaluate_signature(
                    signature_result.key_id,
                    signature_result.valid,
                    raw_signature,
                    configured,
                    mode=mode,
                    authorization_time=authorization_time,
                )
            )
        if not integrity.signatures and authorization_time is None:
            results.append(
                SignatureTrustResult(
                    key_id="<none>",
                    public_key_sha256=None,
                    trusted=False,
                    reason=SignerTrustReason.RECEIPT_TIME_INVALID,
                )
            )
        return SignerTrustReport(
            policy_id=self.policy_id,
            mode=mode,
            authorization_time=authorization_timestamp,
            minimum_trusted_signatures=self.minimum_trusted_signatures,
            integrity=integrity,
            signatures=tuple(results),
        )

    def require_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        mode: SignerTrustMode = SignerTrustMode.ADMISSION,
        evaluated_at: datetime | None = None,
    ) -> SignerTrustReport:
        """Return a valid trust report or raise a bounded failure."""

        report = self.verify_receipt(receipt, mode=mode, evaluated_at=evaluated_at)
        if not report.valid:
            codes = ",".join(report.failure_codes) or "SIGNER_TRUST_FAILED"
            raise SignerTrustError(f"receipt signer trust failed ({codes})")
        return report

    def require_active_signing_key(
        self,
        signing_key: SigningKey,
        *,
        evaluated_at: datetime | None = None,
    ) -> str:
        """Prove a configured private signer is currently authorized before startup."""

        now = _aware_utc(evaluated_at or datetime.now(UTC), "signing-key evaluation time")
        public_key = signing_key.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        fingerprint = hashlib.sha256(public_key).hexdigest()
        configured = next(
            (item for item in self.signers if item.key_id == signing_key.key_id), None
        )
        if configured is None:
            raise SignerTrustError("configured signing key ID is not trusted")
        if not hmac.compare_digest(fingerprint, configured.public_key_sha256):
            raise SignerTrustError("configured signing key does not match trusted fingerprint")
        reason = _lifecycle_reason(configured, mode=SignerTrustMode.ADMISSION, at=now)
        if reason is not SignerTrustReason.TRUSTED:
            raise SignerTrustError(f"configured signing key is not active ({reason.value})")
        return fingerprint

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "policy_id": self.policy_id,
            "minimum_trusted_signatures": self.minimum_trusted_signatures,
            "signers": [
                {
                    "key_id": item.key_id,
                    "public_key": item.public_key,
                    "public_key_sha256": item.public_key_sha256,
                    "status": item.status.value,
                    "not_before": item.not_before,
                    "not_after": item.not_after,
                }
                for item in self.signers
            ],
        }


def signing_key_fingerprint(signing_key: SigningKey) -> str:
    """Return the lowercase SHA-256 fingerprint of an Ed25519 signing public key."""

    public_key = signing_key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return hashlib.sha256(public_key).hexdigest()


def signing_key_public_key(signing_key: SigningKey) -> str:
    """Return the canonical unpadded base64url public key for policy enrollment."""

    public_key = signing_key.private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _base64url_encode(public_key)


def signing_key_from_base64url(key_id: str, value: str) -> SigningKey:
    """Decode one canonical raw Ed25519 private key without exposing its bytes."""

    padding = "=" * (-len(value) % 4)
    try:
        raw = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise SignerTrustError("signing key is not valid base64url") from exc
    if len(raw) != 32 or _base64url_encode(raw) != value:
        raise SignerTrustError("signing key must be a canonical base64url Ed25519 private key")
    try:
        private_key = Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:  # pragma: no cover - length currently defines the encoding
        raise SignerTrustError("signing key is not a valid Ed25519 private key") from exc
    return SigningKey(key_id, private_key)


def load_signer_trust_policy(path: Path) -> SignerTrustPolicy:
    """Load one bounded regular file without following symlink races."""

    if path.is_symlink():
        raise SignerTrustError("trusted signer policy path must not be a symbolic link")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        if path.is_symlink():
            raise SignerTrustError(
                "trusted signer policy path must not be a symbolic link"
            ) from exc
        raise SignerTrustError("trusted signer policy file is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SignerTrustError("trusted signer policy path must be a regular file")
        if metadata.st_size <= 0 or metadata.st_size > _MAX_POLICY_BYTES:
            raise SignerTrustError("trusted signer policy size is outside the supported bounds")
        chunks: list[bytes] = []
        remaining = _MAX_POLICY_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
    except OSError as exc:
        raise SignerTrustError("trusted signer policy could not be read") from exc
    finally:
        os.close(descriptor)
    if len(encoded) != metadata.st_size:
        raise SignerTrustError("trusted signer policy changed while it was being read")
    try:
        value = json.loads(encoded)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignerTrustError("trusted signer policy is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise SignerTrustError("trusted signer policy root must be an object")
    return SignerTrustPolicy.from_dict(value)


def load_signer_trust_schema(path: Path | None = None) -> dict[str, Any]:
    """Load the normative policy schema from source, wheel, or an explicit path."""

    if path is not None:
        return _read_schema(path)
    repository_path = Path(__file__).resolve().parents[4] / _SCHEMA_RELATIVE_PATH
    if repository_path.is_file():
        return _read_schema(repository_path)
    packaged = resources.files("glassbox_dbom").joinpath(str(_SCHEMA_RELATIVE_PATH))
    with packaged.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise SignerTrustError("trusted signer schema root must be an object")
    return value


def _read_schema(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignerTrustError("trusted signer schema is not valid JSON") from exc
    if not isinstance(value, dict):
        raise SignerTrustError("trusted signer schema root must be an object")
    return value


def _schema_failures(value: Mapping[str, Any]) -> tuple[str, ...]:
    validator = Draft202012Validator(load_signer_trust_schema(), format_checker=FormatChecker())
    failures: list[str] = []
    for error in sorted(validator.iter_errors(value), key=lambda item: list(item.path)):
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        failures.append(f"{location}: {error.message}")
    return tuple(failures)


def _parse_signer(value: object) -> TrustedSigner:
    if not isinstance(value, Mapping):  # pragma: no cover - schema gate
        raise SignerTrustError("trusted signer entry must be an object")
    not_after = value.get("not_after")
    return TrustedSigner(
        key_id=_required_string(value, "key_id"),
        public_key=_required_string(value, "public_key"),
        public_key_sha256=_required_string(value, "public_key_sha256"),
        status=SignerStatus(_required_string(value, "status")),
        not_before=_required_string(value, "not_before"),
        not_after=not_after if isinstance(not_after, str) else None,
    )


def _authorization_time(
    receipt: Mapping[str, Any],
    *,
    mode: SignerTrustMode,
    evaluated_at: datetime | None,
) -> tuple[datetime | None, str | None]:
    if mode is SignerTrustMode.ADMISSION:
        selected = _aware_utc(evaluated_at or datetime.now(UTC), "admission evaluation time")
        return selected, _timestamp(selected)
    run = receipt.get("run")
    ended_at = run.get("ended_at") if isinstance(run, Mapping) else None
    if not isinstance(ended_at, str):
        return None, None
    try:
        selected = _parse_timestamp(ended_at, "receipt ended_at")
    except SignerTrustError:
        return None, None
    return selected, _timestamp(selected)


def _signature_mappings(receipt: Mapping[str, Any]) -> tuple[Mapping[str, Any] | None, ...]:
    integrity = receipt.get("integrity")
    signatures = integrity.get("signatures") if isinstance(integrity, Mapping) else None
    if not isinstance(signatures, list):
        return ()
    return tuple(item if isinstance(item, Mapping) else None for item in signatures)


def _evaluate_signature(
    key_id: str,
    cryptographically_valid: bool,
    raw_signature: Mapping[str, Any] | None,
    configured: Mapping[str, TrustedSigner],
    *,
    mode: SignerTrustMode,
    authorization_time: datetime | None,
) -> SignatureTrustResult:
    if not cryptographically_valid or raw_signature is None:
        return SignatureTrustResult(
            key_id=key_id,
            public_key_sha256=None,
            trusted=False,
            reason=SignerTrustReason.SIGNATURE_INVALID,
        )
    raw_public_key = raw_signature.get("public_key")
    try:
        fingerprint = (
            hashlib.sha256(_decode_public_key(raw_public_key)).hexdigest()
            if isinstance(raw_public_key, str)
            else None
        )
    except SignerTrustError:
        fingerprint = None
    signer = configured.get(key_id)
    if signer is None:
        return SignatureTrustResult(
            key_id=key_id,
            public_key_sha256=fingerprint,
            trusted=False,
            reason=SignerTrustReason.UNKNOWN_KEY_ID,
        )
    if fingerprint is None or not hmac.compare_digest(fingerprint, signer.public_key_sha256):
        return SignatureTrustResult(
            key_id=key_id,
            public_key_sha256=fingerprint,
            trusted=False,
            reason=SignerTrustReason.PUBLIC_KEY_MISMATCH,
        )
    if authorization_time is None:
        reason = SignerTrustReason.RECEIPT_TIME_INVALID
    else:
        reason = _lifecycle_reason(signer, mode=mode, at=authorization_time)
    return SignatureTrustResult(
        key_id=key_id,
        public_key_sha256=fingerprint,
        trusted=reason is SignerTrustReason.TRUSTED,
        reason=reason,
    )


def _lifecycle_reason(
    signer: TrustedSigner,
    *,
    mode: SignerTrustMode,
    at: datetime,
) -> SignerTrustReason:
    if signer.status is SignerStatus.REVOKED:
        return SignerTrustReason.SIGNER_REVOKED
    if mode is SignerTrustMode.ADMISSION and signer.status is SignerStatus.RETIRED:
        return SignerTrustReason.SIGNER_RETIRED
    if at < signer.starts_at:
        return SignerTrustReason.BEFORE_VALIDITY_WINDOW
    ends_at = signer.ends_at
    if ends_at is not None and at >= ends_at:
        return SignerTrustReason.AFTER_VALIDITY_WINDOW
    return SignerTrustReason.TRUSTED


def _decode_public_key(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise SignerTrustError("trusted signer public key is not valid base64url") from exc
    if len(decoded) != 32:
        raise SignerTrustError("trusted signer Ed25519 public key must be 32 bytes")
    try:
        Ed25519PublicKey.from_public_bytes(decoded)
    except ValueError as exc:  # pragma: no cover - length currently defines Ed25519 encoding
        raise SignerTrustError("trusted signer public key is invalid") from exc
    if _base64url_encode(decoded) != value:
        raise SignerTrustError("trusted signer public key is not canonical base64url")
    return decoded


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _parse_timestamp(value: str, label: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SignerTrustError(f"{label} must be an RFC 3339 timestamp") from exc
    return _aware_utc(parsed, label)


def _aware_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise SignerTrustError(f"{label} must include a timezone")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str):  # pragma: no cover - schema gate
        raise SignerTrustError(f"trusted signer policy field {key!r} must be a string")
    return selected


def _required_int(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if not isinstance(selected, int) or isinstance(selected, bool):  # pragma: no cover
        raise SignerTrustError(f"trusted signer policy field {key!r} must be an integer")
    return selected


__all__ = [
    "SignatureTrustResult",
    "SignerAdmissionEvidence",
    "SignerStatus",
    "SignerTrustError",
    "SignerTrustMode",
    "SignerTrustPolicy",
    "SignerTrustReason",
    "SignerTrustReport",
    "TrustedSigner",
    "load_signer_trust_policy",
    "load_signer_trust_schema",
    "signing_key_fingerprint",
    "signing_key_from_base64url",
    "signing_key_public_key",
]
