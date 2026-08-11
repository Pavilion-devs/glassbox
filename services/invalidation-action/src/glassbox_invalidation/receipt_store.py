"""Verified append-only receipt store and reverse-influence candidate index."""

from __future__ import annotations

import copy
import hashlib
import json
import os
from collections.abc import Mapping
from pathlib import Path
from threading import Lock
from typing import Any

from glassbox_dbom.canonical import canonicalize
from glassbox_dbom.trust import (
    SignerAdmissionEvidence,
    SignerTrustError,
    SignerTrustMode,
    SignerTrustPolicy,
)
from glassbox_policy import (
    FieldCoverage,
    FieldLineageProof,
    NormalizedChange,
    PolicyInputError,
    ReceiptDependencyProfile,
)

_STORE_DOMAIN = b"glassbox.receipt-dependency-store.v1\0"


class ReceiptStoreError(RuntimeError):
    """Raised when the durable dependency index cannot be trusted."""


class VerifiedReceiptStore:
    """Persist sealed DBOMs and build a precise in-memory reverse index."""

    def __init__(
        self,
        path: Path,
        *,
        sync: bool = True,
        require_signature: bool = True,
        signer_trust_policy: SignerTrustPolicy | None = None,
    ) -> None:
        if not path.parent.is_dir():
            raise ReceiptStoreError(f"receipt-store parent directory does not exist: {path.parent}")
        if path.exists() and not path.is_file():
            raise ReceiptStoreError(f"receipt-store path is not a regular file: {path}")
        self.path = path
        self.sync = sync
        self.require_signature = require_signature
        self.signer_trust_policy = signer_trust_policy
        self._lock = Lock()
        self._profiles, self._record_digests, self._receipts = self._read()

    def register(
        self,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
        superseded_by: str | None = None,
    ) -> bool:
        """Verify and append a receipt once; conflicts fail instead of overwriting."""

        proof = field_lineage or FieldLineageProof()
        receipt_id = _receipt_id(receipt)
        with self._lock:
            existing = self._record_digests.get(receipt_id)
            if existing is not None:
                existing_profile = self._profiles[receipt_id]
                existing_receipt = self._receipts[receipt_id]
                if (
                    canonicalize(existing_receipt) == canonicalize(receipt)
                    and existing_profile.field_lineage == proof
                    and existing_profile.superseded_by == superseded_by
                ):
                    return False
                raise ReceiptStoreError(
                    f"receipt {receipt_id} already has conflicting dependency metadata"
                )
            admission = _admission_evidence(self.signer_trust_policy, receipt)
            profile = ReceiptDependencyProfile.from_receipt(
                receipt,
                field_lineage=proof,
                superseded_by=superseded_by,
                require_signature=self.require_signature,
                signer_trust_policy=self.signer_trust_policy,
                signer_trust_mode=(
                    SignerTrustMode.HISTORICAL
                    if self.signer_trust_policy is not None
                    else SignerTrustMode.ADMISSION
                ),
            )
            material = {
                "receipt": copy.deepcopy(dict(receipt)),
                "field_lineage": _lineage_to_dict(proof),
                "superseded_by": superseded_by,
                "signer_admission": (admission.to_dict() if admission is not None else None),
            }
            record_digest = hashlib.sha256(_STORE_DOMAIN + canonicalize(material)).hexdigest()
            envelope = {"material": material, "sha256": record_digest}
            descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                _write_all(descriptor, canonicalize(envelope) + b"\n")
                if self.sync:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._profiles[profile.receipt_id] = profile
            self._record_digests[profile.receipt_id] = record_digest
            self._receipts[profile.receipt_id] = copy.deepcopy(dict(receipt))
            return True

    def all_profiles(self) -> tuple[ReceiptDependencyProfile, ...]:
        return tuple(self._profiles[key] for key in sorted(self._profiles))

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None:
        """Return a defensive copy of one verified stored artifact, when present."""

        receipt = self._receipts.get(receipt_id)
        return copy.deepcopy(receipt) if receipt is not None else None

    def candidates(self, change: NormalizedChange) -> tuple[ReceiptDependencyProfile, ...]:
        """Select exact-asset receipts plus unresolved receipts that cannot be excluded."""

        candidates = []
        for profile in self.all_profiles():
            exact_asset = any(
                dependency.datahub_urn == change.entity_urn for dependency in profile.dependencies
            )
            unresolved = any(not dependency.resolved for dependency in profile.dependencies)
            if exact_asset or unresolved:
                candidates.append(profile)
        return tuple(candidates)

    def _read(
        self,
    ) -> tuple[
        dict[str, ReceiptDependencyProfile],
        dict[str, str],
        dict[str, dict[str, Any]],
    ]:
        if not self.path.exists():
            return {}, {}, {}
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            raise ReceiptStoreError("receipt store has a truncated trailing record")
        profiles: dict[str, ReceiptDependencyProfile] = {}
        record_digests: dict[str, str] = {}
        receipts: dict[str, dict[str, Any]] = {}
        for line_number, line in enumerate(data.splitlines(), start=1):
            try:
                envelope = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ReceiptStoreError(
                    f"receipt store line {line_number} is not valid JSON"
                ) from exc
            if not isinstance(envelope, Mapping):
                raise ReceiptStoreError(f"receipt store line {line_number} must be an object")
            material = envelope.get("material")
            recorded_digest = envelope.get("sha256")
            if not isinstance(material, Mapping) or not isinstance(recorded_digest, str):
                raise ReceiptStoreError(f"receipt store line {line_number} has an invalid envelope")
            expected = hashlib.sha256(_STORE_DOMAIN + canonicalize(material)).hexdigest()
            if recorded_digest != expected:
                raise ReceiptStoreError(f"receipt store line {line_number} failed its checksum")
            receipt = material.get("receipt")
            if not isinstance(receipt, Mapping):
                raise ReceiptStoreError(
                    f"receipt store line {line_number} receipt must be an object"
                )
            try:
                _verify_admission_evidence(
                    material.get("signer_admission"),
                    receipt,
                    signer_trust_policy=self.signer_trust_policy,
                )
                profile = ReceiptDependencyProfile.from_receipt(
                    receipt,
                    field_lineage=_parse_lineage(material.get("field_lineage")),
                    superseded_by=_optional_text(material, "superseded_by", line_number),
                    require_signature=self.require_signature,
                    signer_trust_policy=self.signer_trust_policy,
                    signer_trust_mode=SignerTrustMode.HISTORICAL,
                )
            except (PolicyInputError, SignerTrustError) as exc:
                raise ReceiptStoreError(
                    f"receipt store line {line_number} contains an invalid receipt"
                ) from exc
            if profile.receipt_id in profiles:
                raise ReceiptStoreError(f"receipt store line {line_number} duplicates a receipt ID")
            profiles[profile.receipt_id] = profile
            record_digests[profile.receipt_id] = recorded_digest
            receipts[profile.receipt_id] = copy.deepcopy(dict(receipt))
        return profiles, record_digests, receipts


def _lineage_to_dict(proof: FieldLineageProof) -> dict[str, object]:
    return {
        "coverage": proof.coverage.value,
        "rule_id": proof.rule_id,
        "wildcard_query": proof.wildcard_query,
    }


def _parse_lineage(value: object) -> FieldLineageProof:
    if not isinstance(value, Mapping):
        raise ReceiptStoreError("field_lineage must be an object")
    coverage = value.get("coverage")
    rule_id = value.get("rule_id")
    wildcard_query = value.get("wildcard_query")
    if not isinstance(coverage, str):
        raise ReceiptStoreError("field_lineage coverage must be a string")
    if rule_id is not None and not isinstance(rule_id, str):
        raise ReceiptStoreError("field_lineage rule_id must be a string or null")
    if wildcard_query is not None and not isinstance(wildcard_query, bool):
        raise ReceiptStoreError("field_lineage wildcard_query must be a boolean or null")
    try:
        return FieldLineageProof(
            coverage=FieldCoverage(coverage),
            rule_id=rule_id,
            wildcard_query=wildcard_query,
        )
    except (ValueError, PolicyInputError) as exc:
        raise ReceiptStoreError("field_lineage proof is invalid") from exc


def _optional_text(value: Mapping[str, Any], key: str, line_number: int) -> str | None:
    selected = value.get(key)
    if selected is not None and (not isinstance(selected, str) or not selected):
        raise ReceiptStoreError(
            f"receipt store line {line_number} field {key!r} must be non-empty or null"
        )
    return selected


def _receipt_id(receipt: Mapping[str, Any]) -> str:
    value = receipt.get("receipt_id")
    if not isinstance(value, str) or not value:
        raise ReceiptStoreError("receipt ID must be a non-empty string")
    return value


def _admission_evidence(
    signer_trust_policy: SignerTrustPolicy | None,
    receipt: Mapping[str, Any],
) -> SignerAdmissionEvidence | None:
    if signer_trust_policy is None:
        return None
    report = signer_trust_policy.verify_receipt(
        receipt,
        mode=SignerTrustMode.ADMISSION,
    )
    if not report.valid:
        codes = ",".join(report.failure_codes) or "SIGNER_TRUST_FAILED"
        raise PolicyInputError(f"refusing untrusted receipt: {codes}")
    return SignerAdmissionEvidence.from_report(report)


def _verify_admission_evidence(
    value: object,
    receipt: Mapping[str, Any],
    *,
    signer_trust_policy: SignerTrustPolicy | None,
) -> None:
    if value is None:
        if signer_trust_policy is not None:
            raise SignerTrustError("stored receipt has no trusted admission evidence")
        return
    if not isinstance(value, Mapping):
        raise SignerTrustError("stored signer admission evidence must be an object")
    evidence = SignerAdmissionEvidence.from_dict(value)
    evidence.verify_receipt_binding(receipt)


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - defensive operating-system contract check
            raise ReceiptStoreError("receipt store append made no forward progress")
        remaining = remaining[written:]
