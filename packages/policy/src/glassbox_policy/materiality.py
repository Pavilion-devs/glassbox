"""Deterministic materiality classification for verified GlassBox receipts."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from glassbox_dbom import (
    SignerTrustMode,
    SignerTrustPolicy,
    verify_receipt,
)

POLICY_VERSION = "glassbox.materiality.v1"
_RECEIPT_PREFIX = "gbx:receipt:sha256:"
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class PolicyInputError(ValueError):
    """Raised when provenance or change input cannot support an honest decision."""


class ChangeKind(StrEnum):
    """Normalized upstream changes understood by materiality policy v1."""

    SCHEMA_FIELD_ADDED = "SCHEMA_FIELD_ADDED"
    SCHEMA_FIELD_REMOVED = "SCHEMA_FIELD_REMOVED"
    SCHEMA_FIELD_RENAMED = "SCHEMA_FIELD_RENAMED"
    SCHEMA_FIELD_TYPE_CHANGED = "SCHEMA_FIELD_TYPE_CHANGED"
    SCHEMA_CHANGED = "SCHEMA_CHANGED"
    ASSET_DEPRECATED = "ASSET_DEPRECATED"
    GLOSSARY_DEFINITION_CHANGED = "GLOSSARY_DEFINITION_CHANGED"
    OWNERSHIP_CHANGED = "OWNERSHIP_CHANGED"
    FRESHNESS_INCIDENT = "FRESHNESS_INCIDENT"
    ASSERTION_FAILED = "ASSERTION_FAILED"
    DOCUMENT_SUPERSEDED = "DOCUMENT_SUPERSEDED"
    COMPONENT_DEPRECATED = "COMPONENT_DEPRECATED"
    DESCRIPTION_FORMATTING_CHANGED = "DESCRIPTION_FORMATTING_CHANGED"
    UNKNOWN = "UNKNOWN"


class EvidenceState(StrEnum):
    """Provenance certainty copied without promotion from the DBOM."""

    OBSERVED = "OBSERVED"
    DECLARED = "DECLARED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class EvidenceRole(StrEnum):
    """The influence role recorded by one DBOM evidence item."""

    INPUT = "INPUT"
    REFERENCE = "REFERENCE"
    CONSTRAINT = "CONSTRAINT"
    POLICY = "POLICY"
    MEMORY = "MEMORY"
    OUTPUT_TARGET = "OUTPUT_TARGET"


class FieldCoverage(StrEnum):
    """Strength of the receipt's externally established field-lineage proof."""

    NONE = "NONE"
    PARTIAL = "PARTIAL"
    COMPLETE = "COMPLETE"


class ImpactState(StrEnum):
    """Deterministic validity state for a prior consequential output."""

    UNAFFECTED = "UNAFFECTED"
    STALE = "STALE"
    AT_RISK = "AT_RISK"
    UNKNOWN = "UNKNOWN"
    SUPERSEDED = "SUPERSEDED"


@dataclass(frozen=True)
class FieldLineageProof:
    """Versioned positive evidence about field-level dependency completeness."""

    coverage: FieldCoverage = FieldCoverage.NONE
    rule_id: str | None = None
    wildcard_query: bool | None = None

    def __post_init__(self) -> None:
        if self.coverage is FieldCoverage.COMPLETE and not self.rule_id:
            raise PolicyInputError("complete field coverage requires a non-empty rule_id")
        if self.rule_id is not None:
            _require_nonempty(self.rule_id, "field lineage rule_id")

    @property
    def proves_field_absence(self) -> bool:
        return self.coverage is FieldCoverage.COMPLETE and self.wildcard_query is False


@dataclass(frozen=True)
class EvidenceDependency:
    """One dependency extracted from a cryptographically verified receipt."""

    evidence_id: str
    datahub_urn: str | None
    schema_field_urn: str | None
    state: EvidenceState
    role: EvidenceRole
    observed_at: str | None
    representation_digest: str | None

    def __post_init__(self) -> None:
        _require_nonempty(self.evidence_id, "evidence_id")
        _optional_urn(self.datahub_urn, "evidence DataHub URN")
        _optional_urn(self.schema_field_urn, "evidence schema-field URN")
        _optional_timestamp(self.observed_at, "evidence observed_at")
        _optional_digest(self.representation_digest, "evidence representation digest")

    @property
    def resolved(self) -> bool:
        return self.datahub_urn is not None and self.state is not EvidenceState.UNKNOWN


@dataclass(frozen=True)
class ReceiptDependencyProfile:
    """Policy-safe dependency projection of one verified append-only receipt."""

    receipt_id: str
    document_urn: str
    ended_at: str
    dependencies: tuple[EvidenceDependency, ...]
    field_lineage: FieldLineageProof = FieldLineageProof()
    superseded_by: str | None = None

    def __post_init__(self) -> None:
        expected_document_urn = _receipt_document_urn(self.receipt_id)
        if self.document_urn != expected_document_urn:
            message = (
                f"receipt document URN {self.document_urn!r} does not match "
                f"{expected_document_urn!r}"
            )
            raise PolicyInputError(message)
        _require_timestamp(self.ended_at, "receipt ended_at")
        if self.superseded_by is not None:
            _receipt_document_urn(self.superseded_by)
        evidence_ids = [item.evidence_id for item in self.dependencies]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise PolicyInputError("receipt dependency evidence IDs must be unique")

    @classmethod
    def from_receipt(
        cls,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
        superseded_by: str | None = None,
        require_signature: bool = True,
        signer_trust_policy: SignerTrustPolicy | None = None,
        signer_trust_mode: SignerTrustMode = SignerTrustMode.ADMISSION,
    ) -> ReceiptDependencyProfile:
        """Verify a receipt before projecting only its influence evidence."""

        if signer_trust_policy is not None:
            trust_report = signer_trust_policy.verify_receipt(
                receipt,
                mode=signer_trust_mode,
            )
            if not trust_report.valid:
                details = ",".join(trust_report.failure_codes) or "SIGNER_TRUST_FAILED"
                raise PolicyInputError(f"refusing untrusted receipt: {details}")
        else:
            report = verify_receipt(receipt, require_signature=require_signature)
            if not report.valid:
                details = "; ".join(report.errors) or "verification failed"
                raise PolicyInputError(f"refusing unverified receipt: {details}")
        receipt_id = _required_string(receipt, "receipt_id")
        run = _required_mapping(receipt, "run")
        raw_evidence = _required_sequence(receipt, "evidence")
        dependencies = tuple(
            sorted(
                (_parse_evidence(item) for item in raw_evidence), key=lambda item: item.evidence_id
            )
        )
        return cls(
            receipt_id=receipt_id,
            document_urn=_receipt_document_urn(receipt_id),
            ended_at=_required_string(run, "ended_at"),
            dependencies=dependencies,
            field_lineage=field_lineage or FieldLineageProof(),
            superseded_by=superseded_by,
        )


@dataclass(frozen=True)
class NormalizedChange:
    """Closed, replay-safe representation of one upstream metadata change."""

    event_id: str
    entity_urn: str
    aspect_name: str
    kind: ChangeKind
    occurred_at: str
    schema_field_urn: str | None = None
    before_digest: str | None = None
    after_digest: str | None = None

    def __post_init__(self) -> None:
        _require_nonempty(self.event_id, "change event_id")
        _require_urn(self.entity_urn, "changed entity URN")
        _require_nonempty(self.aspect_name, "changed aspect_name")
        _require_timestamp(self.occurred_at, "change occurred_at")
        _optional_urn(self.schema_field_urn, "changed schema-field URN")
        _optional_digest(self.before_digest, "change before digest")
        _optional_digest(self.after_digest, "change after digest")
        if self.kind in _FIELD_CHANGES and self.schema_field_urn is None:
            raise PolicyInputError(f"{self.kind.value} requires schema_field_urn")


@dataclass(frozen=True)
class ImpactAssessment:
    """Auditable output of exactly one materiality policy evaluation."""

    receipt_id: str
    document_urn: str
    state: ImpactState
    reason_code: str
    matched_evidence_ids: tuple[str, ...] = ()
    policy_version: str = POLICY_VERSION

    @property
    def quarantine_required(self) -> bool:
        return self.state in {ImpactState.STALE, ImpactState.AT_RISK, ImpactState.UNKNOWN}


_FIELD_CHANGES = frozenset(
    {
        ChangeKind.SCHEMA_FIELD_ADDED,
        ChangeKind.SCHEMA_FIELD_REMOVED,
        ChangeKind.SCHEMA_FIELD_RENAMED,
        ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
    }
)
_MATERIAL_FIELD_CHANGES = _FIELD_CHANGES - {ChangeKind.SCHEMA_FIELD_ADDED}
_MATERIAL_ASSET_CHANGES = frozenset(
    {
        ChangeKind.SCHEMA_CHANGED,
        ChangeKind.ASSET_DEPRECATED,
        ChangeKind.ASSERTION_FAILED,
        ChangeKind.DOCUMENT_SUPERSEDED,
        ChangeKind.COMPONENT_DEPRECATED,
    }
)


def classify_materiality(
    profile: ReceiptDependencyProfile, change: NormalizedChange
) -> ImpactAssessment:
    """Classify one verified receipt without side effects or hidden inference."""

    if profile.superseded_by is not None:
        return _assessment(profile, ImpactState.SUPERSEDED, "RECEIPT_ALREADY_SUPERSEDED")
    if not profile.dependencies:
        return _assessment(profile, ImpactState.UNKNOWN, "NO_RECORDED_DEPENDENCIES")

    entity_matches = tuple(
        item for item in profile.dependencies if item.datahub_urn == change.entity_urn
    )
    exact_field_matches = tuple(
        item
        for item in entity_matches
        if change.schema_field_urn is not None and item.schema_field_urn == change.schema_field_urn
    )

    if exact_field_matches:
        snapshot_safe = tuple(
            item for item in exact_field_matches if _proves_post_change_snapshot(item, change)
        )
        exposed = tuple(item for item in exact_field_matches if item not in snapshot_safe)
        if exposed:
            return _classify_exact_dependencies(profile, change, exposed)
        return _assessment(
            profile,
            ImpactState.UNAFFECTED,
            "MATCHED_POST_CHANGE_SNAPSHOT",
            exact_field_matches,
        )

    if entity_matches:
        return _classify_entity_match(profile, change, entity_matches)

    unresolved = tuple(item for item in profile.dependencies if not item.resolved)
    if unresolved:
        return _assessment(
            profile,
            ImpactState.UNKNOWN,
            "UNRESOLVED_DEPENDENCY_PREVENTS_ASSET_EXCLUSION",
            unresolved,
        )
    return _assessment(
        profile, ImpactState.UNAFFECTED, "CHANGED_ASSET_NOT_IN_RESOLVED_INFLUENCE_SET"
    )


def classify_receipts(
    profiles: Sequence[ReceiptDependencyProfile], change: NormalizedChange
) -> tuple[ImpactAssessment, ...]:
    """Traverse a receipt set in deterministic content-address order."""

    receipt_ids = [profile.receipt_id for profile in profiles]
    if len(receipt_ids) != len(set(receipt_ids)):
        raise PolicyInputError("reverse-influence input contains duplicate receipt IDs")
    return tuple(
        classify_materiality(profile, change)
        for profile in sorted(profiles, key=lambda item: item.receipt_id)
    )


def _classify_exact_dependencies(
    profile: ReceiptDependencyProfile,
    change: NormalizedChange,
    dependencies: tuple[EvidenceDependency, ...],
) -> ImpactAssessment:
    unknown = tuple(item for item in dependencies if item.state is EvidenceState.UNKNOWN)
    if unknown:
        return _assessment(profile, ImpactState.UNKNOWN, "EXACT_DEPENDENCY_STATE_UNKNOWN", unknown)

    observed = tuple(item for item in dependencies if item.state is EvidenceState.OBSERVED)
    if observed:
        if change.kind is ChangeKind.OWNERSHIP_CHANGED:
            return _assessment(
                profile, ImpactState.UNAFFECTED, "OWNERSHIP_CHANGE_ROUTING_ONLY", observed
            )
        if change.kind is ChangeKind.DESCRIPTION_FORMATTING_CHANGED:
            return _assessment(
                profile, ImpactState.UNAFFECTED, "DESCRIPTION_FORMATTING_NON_MATERIAL", observed
            )
        if change.kind is ChangeKind.SCHEMA_FIELD_ADDED:
            return _assessment(
                profile, ImpactState.AT_RISK, "FIELD_ADDITION_MAY_AFFECT_WILDCARD", observed
            )
        if change.kind is ChangeKind.GLOSSARY_DEFINITION_CHANGED:
            constraints = tuple(
                item
                for item in observed
                if item.role in {EvidenceRole.CONSTRAINT, EvidenceRole.POLICY}
            )
            if constraints:
                return _assessment(
                    profile, ImpactState.STALE, "OBSERVED_SEMANTIC_CONSTRAINT_CHANGED", constraints
                )
            return _assessment(
                profile, ImpactState.AT_RISK, "SEMANTIC_REFERENCE_MATERIALITY_UNPROVEN", observed
            )
        if change.kind is ChangeKind.FRESHNESS_INCIDENT:
            constraints = tuple(
                item
                for item in observed
                if item.role in {EvidenceRole.CONSTRAINT, EvidenceRole.POLICY}
            )
            if constraints:
                return _assessment(
                    profile,
                    ImpactState.STALE,
                    "OBSERVED_FRESHNESS_CONSTRAINT_VIOLATED",
                    constraints,
                )
            return _assessment(
                profile, ImpactState.AT_RISK, "FRESHNESS_REQUIREMENT_NOT_RECORDED", observed
            )
        if change.kind in _MATERIAL_FIELD_CHANGES | _MATERIAL_ASSET_CHANGES:
            return _assessment(
                profile, ImpactState.STALE, "OBSERVED_MATERIAL_DEPENDENCY_CHANGED", observed
            )
        return _assessment(profile, ImpactState.UNKNOWN, "UNSUPPORTED_CHANGE_MATERIALITY", observed)

    return _assessment(
        profile,
        ImpactState.AT_RISK,
        "MATCHED_DEPENDENCY_NOT_OBSERVED",
        dependencies,
    )


def _classify_entity_match(
    profile: ReceiptDependencyProfile,
    change: NormalizedChange,
    entity_matches: tuple[EvidenceDependency, ...],
) -> ImpactAssessment:
    unknown = tuple(item for item in entity_matches if item.state is EvidenceState.UNKNOWN)
    if unknown:
        return _assessment(
            profile, ImpactState.UNKNOWN, "MATCHED_ASSET_DEPENDENCY_STATE_UNKNOWN", unknown
        )

    if change.kind in _FIELD_CHANGES:
        if profile.field_lineage.proves_field_absence:
            return _assessment(
                profile,
                ImpactState.UNAFFECTED,
                "COMPLETE_FIELD_LINEAGE_PROVES_FIELD_UNUSED",
                entity_matches,
            )
        return _assessment(
            profile,
            ImpactState.AT_RISK,
            "FIELD_LINEAGE_INCOMPLETE_OR_WILDCARD_UNKNOWN",
            entity_matches,
        )

    if change.kind is ChangeKind.OWNERSHIP_CHANGED:
        return _assessment(
            profile, ImpactState.UNAFFECTED, "OWNERSHIP_CHANGE_ROUTING_ONLY", entity_matches
        )
    if change.kind is ChangeKind.DESCRIPTION_FORMATTING_CHANGED:
        return _assessment(
            profile, ImpactState.UNAFFECTED, "DESCRIPTION_FORMATTING_NON_MATERIAL", entity_matches
        )
    return _classify_exact_dependencies(profile, change, entity_matches)


def _proves_post_change_snapshot(dependency: EvidenceDependency, change: NormalizedChange) -> bool:
    return (
        dependency.state is EvidenceState.OBSERVED
        and dependency.observed_at is not None
        and change.after_digest is not None
        and dependency.representation_digest == change.after_digest
        and _parse_timestamp(dependency.observed_at) >= _parse_timestamp(change.occurred_at)
    )


def _assessment(
    profile: ReceiptDependencyProfile,
    state: ImpactState,
    reason_code: str,
    matched: Sequence[EvidenceDependency] = (),
) -> ImpactAssessment:
    return ImpactAssessment(
        receipt_id=profile.receipt_id,
        document_urn=profile.document_urn,
        state=state,
        reason_code=reason_code,
        matched_evidence_ids=tuple(sorted(item.evidence_id for item in matched)),
    )


def _parse_evidence(value: object) -> EvidenceDependency:
    if not isinstance(value, Mapping):
        raise PolicyInputError("receipt evidence items must be objects")
    digest = value.get("representation_digest")
    digest_value: str | None = None
    if digest is not None:
        if not isinstance(digest, Mapping):
            raise PolicyInputError("evidence representation_digest must be an object or null")
        digest_value = _required_string(digest, "value")
    try:
        state = EvidenceState(_required_string(value, "state"))
        role = EvidenceRole(_required_string(value, "role"))
    except ValueError as exc:  # defensive against independently constructed mappings
        raise PolicyInputError(str(exc)) from exc
    return EvidenceDependency(
        evidence_id=_required_string(value, "evidence_id"),
        datahub_urn=_optional_string(value, "datahub_urn"),
        schema_field_urn=_optional_string(value, "schema_field_urn"),
        state=state,
        role=role,
        observed_at=_optional_string(value, "observed_at"),
        representation_digest=digest_value,
    )


def _receipt_document_urn(receipt_id: str) -> str:
    if not receipt_id.startswith(_RECEIPT_PREFIX):
        raise PolicyInputError("receipt_id is not a GlassBox SHA-256 content address")
    digest = receipt_id.removeprefix(_RECEIPT_PREFIX)
    _require_digest(digest, "receipt digest")
    return f"urn:li:document:glassbox.receipt.{digest}"


def _required_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise PolicyInputError(f"{key} must be an object")
    return selected


def _required_sequence(value: Mapping[str, Any], key: str) -> Sequence[object]:
    selected = value.get(key)
    if not isinstance(selected, list):
        raise PolicyInputError(f"{key} must be an array")
    return selected


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str):
        raise PolicyInputError(f"{key} must be a string")
    _require_nonempty(selected, key)
    return selected


def _optional_string(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is None:
        return None
    if not isinstance(selected, str):
        raise PolicyInputError(f"{key} must be a string or null")
    _require_nonempty(selected, key)
    return selected


def _require_nonempty(value: str, label: str) -> None:
    if not value or value != value.strip():
        raise PolicyInputError(f"{label} must be a non-empty trimmed string")


def _require_urn(value: str, label: str) -> None:
    _require_nonempty(value, label)
    if not value.startswith("urn:li:"):
        raise PolicyInputError(f"{label} must be a DataHub URN")


def _optional_urn(value: str | None, label: str) -> None:
    if value is not None:
        _require_urn(value, label)


def _require_digest(value: str, label: str) -> None:
    if _SHA256_PATTERN.fullmatch(value) is None:
        raise PolicyInputError(f"{label} must be a lowercase SHA-256 digest")


def _optional_digest(value: str | None, label: str) -> None:
    if value is not None:
        _require_digest(value, label)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyInputError(f"invalid RFC 3339 timestamp: {value!r}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise PolicyInputError(f"timestamp must include an offset: {value!r}")
    return parsed


def _require_timestamp(value: str, label: str) -> None:
    _require_nonempty(value, label)
    _parse_timestamp(value)


def _optional_timestamp(value: str | None, label: str) -> None:
    if value is not None:
        _require_timestamp(value, label)
