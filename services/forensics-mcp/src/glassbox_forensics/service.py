"""Protocol-neutral read-only forensics over verified receipt dependency profiles."""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from glassbox_dbom import (
    SignerTrustMode,
    SignerTrustPolicy,
    verify_receipt,
)
from glassbox_policy import (
    ImpactAssessment,
    ImpactState,
    InvalidationCampaign,
    NormalizedChange,
    ReceiptDependencyProfile,
    classify_materiality,
    classify_receipts,
)

CONTRACT_VERSION = "glassbox.forensics.v1"
DEFAULT_RESULT_LIMIT = 100
MAX_RESULT_LIMIT = 200
_REVIEW_STATES = frozenset({ImpactState.STALE, ImpactState.AT_RISK, ImpactState.UNKNOWN})
_CAMPAIGN_PREFIX = "gbx:invalidation:sha256:"


class ForensicsInputError(ValueError):
    """Raised when a bounded public forensics input is invalid."""


class ForensicsNotFoundError(LookupError):
    """Raised when the requested receipt is not in the configured evidence scope."""


class ReceiptProfileReader(Protocol):
    """Minimal deterministic index required by the forensics service."""

    def all_profiles(self) -> tuple[ReceiptDependencyProfile, ...]: ...


class ReceiptArtifactReader(Protocol):
    """Optional source for fresh integrity verification of a stored DBOM."""

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None: ...


@dataclass(frozen=True)
class PersistedCampaign:
    """Bounded verified view of one campaign processed by the live Action."""

    campaign: InvalidationCampaign
    workflow_status: str
    attempt_count: int
    datahub_writeback_verified: bool
    last_error_recorded: bool


class CampaignFindingReader(Protocol):
    """Read-only campaign view over the Action's durable state."""

    def get_campaign(self, campaign_id: str) -> PersistedCampaign | None: ...

    def all_campaigns(self) -> tuple[PersistedCampaign, ...]: ...


@dataclass(frozen=True)
class PersistedReceiptPublication:
    """Bounded projection of one durable receipt-publication obligation."""

    receipt_id: str
    workflow_status: str
    attempt_count: int
    last_error_recorded: bool
    document_urn: str | None
    aspect_names: tuple[str, ...]
    emission_count: int | None
    durability_authority: str


class ReceiptPublicationReader(Protocol):
    """Read-only projection over durable receipt-publication state."""

    def get_publication(self, receipt_id: str) -> PersistedReceiptPublication | None: ...


class ForensicsService:
    """Answer forensic questions without returning raw prompts, outputs, or values."""

    def __init__(
        self,
        profiles: ReceiptProfileReader,
        *,
        artifacts: ReceiptArtifactReader | None = None,
        findings: CampaignFindingReader | None = None,
        publications: ReceiptPublicationReader | None = None,
        require_signature: bool = True,
        signer_trust_policy: SignerTrustPolicy | None = None,
    ) -> None:
        self._profiles = profiles
        self._artifacts = artifacts
        self._findings = findings
        self._publications = publications
        self._require_signature = require_signature
        self._signer_trust_policy = signer_trust_policy

    def verify_decision_receipt(self, receipt_id: str) -> dict[str, object]:
        """Freshly verify a stored artifact and return only bounded check results."""

        self._require_receipt_id(receipt_id)
        if self._artifacts is None:
            return {
                "contract_version": CONTRACT_VERSION,
                "receipt_id": receipt_id,
                "verification_state": "ARTIFACT_UNAVAILABLE",
                "valid": None,
                "failure_codes": ["ARTIFACT_READER_NOT_CONFIGURED"],
            }
        receipt = self._artifacts.get_receipt(receipt_id)
        if receipt is None:
            raise ForensicsNotFoundError("receipt is outside the configured evidence scope")
        trust = (
            self._signer_trust_policy.verify_receipt(
                receipt,
                mode=SignerTrustMode.HISTORICAL,
            )
            if self._signer_trust_policy is not None
            else None
        )
        report = (
            trust.integrity
            if trust is not None
            else verify_receipt(receipt, require_signature=self._require_signature)
        )
        failure_codes = []
        if not report.schema_valid:
            failure_codes.append("SCHEMA_INVALID")
        if not report.payload_digest_valid:
            failure_codes.append("PAYLOAD_DIGEST_INVALID")
        if not report.receipt_id_valid:
            failure_codes.append("RECEIPT_ID_INVALID")
        if not report.merkle_root_valid:
            failure_codes.append("MERKLE_ROOT_INVALID")
        if report.signature_required and not report.signatures:
            failure_codes.append("SIGNATURE_MISSING")
        if any(not item.valid for item in report.signatures):
            failure_codes.append("SIGNATURE_INVALID")
        if trust is not None:
            failure_codes.extend(trust.failure_codes)
        valid = trust.valid if trust is not None else report.valid
        return {
            "contract_version": CONTRACT_VERSION,
            "receipt_id": receipt_id,
            "verification_state": "VERIFIED_NOW" if valid else "FAILED",
            "valid": valid,
            "checks": {
                "schema": report.schema_valid,
                "payload_digest": report.payload_digest_valid,
                "receipt_id": report.receipt_id_valid,
                "merkle_root": report.merkle_root_valid,
                "signature_required": report.signature_required,
                "signature_count": len(report.signatures),
                "all_present_signatures": all(item.valid for item in report.signatures),
                "trusted_signer_policy": trust is not None,
                "trusted_signature_count": (
                    trust.trusted_signature_count if trust is not None else None
                ),
                "minimum_trusted_signatures": (
                    trust.minimum_trusted_signatures if trust is not None else None
                ),
            },
            "failure_codes": sorted(set(failure_codes)),
        }

    def get_decision_influence(self, receipt_id: str) -> dict[str, object]:
        """Return the safe influence projection for one verified receipt profile."""

        profile = self._find_profile(receipt_id)
        integrity = self._profile_integrity(receipt_id)
        dependencies = [
            {
                "evidence_id": item.evidence_id,
                "datahub_urn": item.datahub_urn,
                "schema_field_urn": item.schema_field_urn,
                "state": item.state.value,
                "role": item.role.value,
                "observed_at": item.observed_at,
                "representation_digest": item.representation_digest,
            }
            for item in profile.dependencies
        ]
        resolved = sum(item.resolved for item in profile.dependencies)
        if not dependencies:
            dependency_resolution = "NO_RECORDED_DEPENDENCIES"
        elif resolved == len(dependencies):
            dependency_resolution = "COMPLETE"
        else:
            dependency_resolution = "INCOMPLETE"
        return {
            "contract_version": CONTRACT_VERSION,
            "receipt_id": profile.receipt_id,
            "document_urn": profile.document_urn,
            "ended_at": profile.ended_at,
            "superseded_by": profile.superseded_by,
            "integrity": integrity,
            "completeness": {
                "scope": "CONFIGURED_RECEIPT_INDEX",
                "dependency_resolution": dependency_resolution,
                "resolved_dependencies": resolved,
                "recorded_dependencies": len(dependencies),
                "field_lineage_coverage": profile.field_lineage.coverage.value,
                "field_lineage_rule_id": profile.field_lineage.rule_id,
                "wildcard_query": profile.field_lineage.wildcard_query,
            },
            "dependencies": dependencies,
            "raw_content_returned": False,
        }

    def get_decision_publication(self, receipt_id: str) -> dict[str, object]:
        """Return sealed durable publication evidence without querying DataHub."""

        profile = self._find_profile(receipt_id)
        if self._publications is None:
            return {
                "contract_version": CONTRACT_VERSION,
                "scope": "CONFIGURED_PUBLICATION_STORE",
                "receipt_id": profile.receipt_id,
                "availability": "PUBLICATION_STORE_NOT_CONFIGURED",
                "raw_content_returned": False,
            }
        publication = self._publications.get_publication(receipt_id)
        if publication is None:
            return {
                "contract_version": CONTRACT_VERSION,
                "scope": "CONFIGURED_PUBLICATION_STORE",
                "receipt_id": profile.receipt_id,
                "availability": "PUBLICATION_NOT_STAGED",
                "raw_content_returned": False,
            }
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_PUBLICATION_STORE",
            "receipt_id": profile.receipt_id,
            "availability": "AVAILABLE",
            "durability": {
                "authority": publication.durability_authority,
                "workflow_status": publication.workflow_status,
                "attempt_count": publication.attempt_count,
                "last_error_recorded": publication.last_error_recorded,
                "sealed_evidence": publication.document_urn is not None,
            },
            "datahub": {
                "document_urn": publication.document_urn,
                "aspect_names": list(publication.aspect_names),
                "aspect_count": len(publication.aspect_names),
                "emission_count": publication.emission_count,
            },
            "raw_content_returned": False,
        }

    def classify_decision_impact(
        self, receipt_id: str, change: NormalizedChange
    ) -> dict[str, object]:
        """Run the canonical materiality policy for one receipt and one change."""

        profile = self._find_profile(receipt_id)
        assessment = classify_materiality(profile, change)
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_RECEIPT_INDEX",
            "change": _change_to_dict(change),
            "assessment": _assessment_to_dict(assessment),
            "decision_authority": "DETERMINISTIC_POLICY",
            "raw_content_returned": False,
        }

    def list_affected_decisions(
        self,
        change: NormalizedChange,
        *,
        limit: int = DEFAULT_RESULT_LIMIT,
    ) -> dict[str, object]:
        """List all stale/at-risk/unknown decisions, with bounded returned detail."""

        if isinstance(limit, bool) or not 1 <= limit <= MAX_RESULT_LIMIT:
            raise ForensicsInputError(f"limit must be between 1 and {MAX_RESULT_LIMIT}")
        profiles = self._profiles.all_profiles()
        assessments = classify_receipts(profiles, change)
        review = tuple(item for item in assessments if item.state in _REVIEW_STATES)
        counts = Counter(item.state.value for item in assessments)
        returned = review[:limit]
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_RECEIPT_INDEX",
            "scan_complete": True,
            "profiles_scanned": len(profiles),
            "change": _change_to_dict(change),
            "state_counts": {key: counts[key] for key in sorted(counts)},
            "review_required_total": len(review),
            "returned": len(returned),
            "truncated": len(returned) < len(review),
            "assessments": [_assessment_to_dict(item) for item in returned],
            "decision_authority": "DETERMINISTIC_POLICY",
            "raw_content_returned": False,
        }

    def get_invalidation_campaign(self, campaign_id: str) -> dict[str, object]:
        """Return the persisted result of one change processed by the live Action."""

        self._require_campaign_id(campaign_id)
        if self._findings is None:
            return {
                "contract_version": CONTRACT_VERSION,
                "scope": "CONFIGURED_CAMPAIGN_STORE",
                "campaign_id": campaign_id,
                "availability": "CAMPAIGN_STORE_NOT_CONFIGURED",
                "raw_content_returned": False,
            }
        campaign = self._findings.get_campaign(campaign_id)
        if campaign is None:
            raise ForensicsNotFoundError("campaign is outside the configured live-state scope")
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_CAMPAIGN_STORE",
            "availability": "AVAILABLE",
            "campaign": _persisted_campaign_to_dict(campaign),
            "raw_content_returned": False,
        }

    def list_decision_findings(
        self,
        receipt_id: str,
        *,
        limit: int = DEFAULT_RESULT_LIMIT,
    ) -> dict[str, object]:
        """Return persisted Action findings for one verified decision receipt."""

        profile = self._find_profile(receipt_id)
        if isinstance(limit, bool) or not 1 <= limit <= MAX_RESULT_LIMIT:
            raise ForensicsInputError(f"limit must be between 1 and {MAX_RESULT_LIMIT}")
        if self._findings is None:
            return {
                "contract_version": CONTRACT_VERSION,
                "scope": "CONFIGURED_CAMPAIGN_STORE",
                "receipt_id": profile.receipt_id,
                "availability": "CAMPAIGN_STORE_NOT_CONFIGURED",
                "scan_complete": False,
                "campaigns_scanned": 0,
                "findings_total": 0,
                "returned": 0,
                "truncated": False,
                "findings": [],
                "raw_content_returned": False,
            }
        campaigns = self._findings.all_campaigns()
        matched = [
            (item, assessment)
            for item in campaigns
            for assessment in item.campaign.assessments
            if assessment.receipt_id == receipt_id
        ]
        matched.sort(
            key=lambda pair: (
                pair[0].campaign.change.occurred_at,
                pair[0].campaign.campaign_id,
            ),
            reverse=True,
        )
        returned = [
            {
                "campaign_id": item.campaign.campaign_id,
                "incident_urn": item.campaign.incident_urn,
                "change": _change_to_dict(item.campaign.change),
                "assessment": _assessment_to_dict(assessment),
                "processing": _processing_to_dict(item),
            }
            for item, assessment in matched[:limit]
        ]
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_CAMPAIGN_STORE",
            "receipt_id": profile.receipt_id,
            "availability": "AVAILABLE",
            "scan_complete": True,
            "campaigns_scanned": len(campaigns),
            "findings_total": len(matched),
            "returned": len(returned),
            "truncated": len(returned) < len(matched),
            "findings": returned,
            "raw_content_returned": False,
        }

    def get_console_overview(self) -> dict[str, object]:
        """Return a bounded operational summary without inventing decision state."""

        profiles = self._profiles.all_profiles()
        campaigns = self._findings.all_campaigns() if self._findings is not None else ()
        latest = _latest_assessments(campaigns)
        states = Counter(
            _profile_state(profile, latest.get(profile.receipt_id)) for profile in profiles
        )
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_EVIDENCE_STORES",
            "availability": {
                "receipt_index": "AVAILABLE",
                "campaign_store": ("AVAILABLE" if self._findings is not None else "NOT_CONFIGURED"),
            },
            "counts": {
                "receipts": len(profiles),
                "dependencies": sum(len(profile.dependencies) for profile in profiles),
                "unresolved_dependencies": sum(
                    not dependency.resolved
                    for profile in profiles
                    for dependency in profile.dependencies
                ),
                "campaigns": len(campaigns),
                "review_required": sum(
                    states[state.value]
                    for state in sorted(_REVIEW_STATES, key=lambda item: item.value)
                ),
            },
            "state_counts": {key: states[key] for key in sorted(states)},
            "raw_content_returned": False,
        }

    def list_decisions(
        self,
        *,
        query: str | None = None,
        limit: int = DEFAULT_RESULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, object]:
        """List safe receipt projections for the operator console."""

        _require_page(limit=limit, offset=offset)
        selected_query = query.strip().lower() if query is not None else ""
        profiles = self._profiles.all_profiles()
        campaigns = self._findings.all_campaigns() if self._findings is not None else ()
        latest = _latest_assessments(campaigns)
        decisions = [
            _decision_summary(profile, latest.get(profile.receipt_id)) for profile in profiles
        ]
        if selected_query:
            decisions = [
                item
                for item in decisions
                if selected_query in _searchable_decision_text(item).lower()
            ]
        decisions.sort(
            key=lambda item: (str(item["ended_at"]), str(item["receipt_id"])),
            reverse=True,
        )
        returned = decisions[offset : offset + limit]
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_RECEIPT_INDEX",
            "availability": "AVAILABLE",
            "total": len(decisions),
            "offset": offset,
            "returned": len(returned),
            "truncated": offset + len(returned) < len(decisions),
            "decisions": returned,
            "raw_content_returned": False,
        }

    def list_invalidation_campaigns(
        self,
        *,
        limit: int = DEFAULT_RESULT_LIMIT,
        offset: int = 0,
    ) -> dict[str, object]:
        """List persisted Action campaigns without exposing raw event bodies."""

        _require_page(limit=limit, offset=offset)
        if self._findings is None:
            return {
                "contract_version": CONTRACT_VERSION,
                "scope": "CONFIGURED_CAMPAIGN_STORE",
                "availability": "CAMPAIGN_STORE_NOT_CONFIGURED",
                "total": 0,
                "offset": offset,
                "returned": 0,
                "truncated": False,
                "campaigns": [],
                "raw_content_returned": False,
            }
        campaigns = sorted(
            self._findings.all_campaigns(),
            key=lambda item: (item.campaign.change.occurred_at, item.campaign.campaign_id),
            reverse=True,
        )
        returned = campaigns[offset : offset + limit]
        return {
            "contract_version": CONTRACT_VERSION,
            "scope": "CONFIGURED_CAMPAIGN_STORE",
            "availability": "AVAILABLE",
            "total": len(campaigns),
            "offset": offset,
            "returned": len(returned),
            "truncated": offset + len(returned) < len(campaigns),
            "campaigns": [_persisted_campaign_to_dict(item) for item in returned],
            "raw_content_returned": False,
        }

    def _profile_integrity(self, receipt_id: str) -> dict[str, object]:
        if self._artifacts is None:
            return {
                "state": "VERIFIED_AT_INGESTION",
                "signature_required_at_query": self._require_signature,
                "trusted_signer_required_at_query": self._signer_trust_policy is not None,
                "fresh_verification": False,
            }
        report = self.verify_decision_receipt(receipt_id)
        return {
            "state": report["verification_state"],
            "signature_required_at_query": self._require_signature,
            "trusted_signer_required_at_query": self._signer_trust_policy is not None,
            "fresh_verification": True,
        }

    def _find_profile(self, receipt_id: str) -> ReceiptDependencyProfile:
        self._require_receipt_id(receipt_id)
        for profile in self._profiles.all_profiles():
            if profile.receipt_id == receipt_id:
                return profile
        raise ForensicsNotFoundError("receipt is outside the configured evidence scope")

    @staticmethod
    def _require_receipt_id(receipt_id: str) -> None:
        prefix = "gbx:receipt:sha256:"
        digest = receipt_id.removeprefix(prefix)
        if (
            not receipt_id.startswith(prefix)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ForensicsInputError("receipt_id must be a GlassBox SHA-256 content address")

    @staticmethod
    def _require_campaign_id(campaign_id: str) -> None:
        digest = campaign_id.removeprefix(_CAMPAIGN_PREFIX)
        if (
            not campaign_id.startswith(_CAMPAIGN_PREFIX)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ForensicsInputError("campaign_id must be a GlassBox SHA-256 content address")


def _assessment_to_dict(assessment: ImpactAssessment) -> dict[str, object]:
    return {
        "receipt_id": assessment.receipt_id,
        "document_urn": assessment.document_urn,
        "state": assessment.state.value,
        "reason_code": assessment.reason_code,
        "matched_evidence_ids": list(assessment.matched_evidence_ids),
        "policy_version": assessment.policy_version,
        "quarantine_required": assessment.quarantine_required,
    }


def _change_to_dict(change: NormalizedChange) -> dict[str, object]:
    return {
        "event_id": change.event_id,
        "entity_urn": change.entity_urn,
        "aspect_name": change.aspect_name,
        "kind": change.kind.value,
        "occurred_at": change.occurred_at,
        "schema_field_urn": change.schema_field_urn,
        "before_digest": change.before_digest,
        "after_digest": change.after_digest,
    }


def _persisted_campaign_to_dict(value: PersistedCampaign) -> dict[str, object]:
    return {
        "campaign_id": value.campaign.campaign_id,
        "incident_urn": value.campaign.incident_urn,
        "change": _change_to_dict(value.campaign.change),
        "policy_version": value.campaign.policy_version,
        "assessments": [_assessment_to_dict(item) for item in value.campaign.assessments],
        "processing": _processing_to_dict(value),
    }


def _processing_to_dict(value: PersistedCampaign) -> dict[str, object]:
    if not value.campaign.quarantined:
        writeback_state = "NOT_REQUIRED"
    elif value.datahub_writeback_verified:
        writeback_state = "VERIFIED"
    else:
        writeback_state = "PENDING"
    return {
        "workflow_status": value.workflow_status,
        "attempt_count": value.attempt_count,
        "datahub_writeback_state": writeback_state,
        "last_error_recorded": value.last_error_recorded,
    }


def _latest_assessments(
    campaigns: tuple[PersistedCampaign, ...],
) -> dict[str, tuple[PersistedCampaign, ImpactAssessment]]:
    latest: dict[str, tuple[PersistedCampaign, ImpactAssessment]] = {}
    ordered = sorted(
        campaigns,
        key=lambda item: (item.campaign.change.occurred_at, item.campaign.campaign_id),
        reverse=True,
    )
    for campaign in ordered:
        for assessment in campaign.campaign.assessments:
            latest.setdefault(assessment.receipt_id, (campaign, assessment))
    return latest


def _profile_state(
    profile: ReceiptDependencyProfile,
    latest: tuple[PersistedCampaign, ImpactAssessment] | None,
) -> str:
    if profile.superseded_by is not None:
        return ImpactState.SUPERSEDED.value
    if latest is None:
        return "NO_RECORDED_FINDING"
    return latest[1].state.value


def _decision_summary(
    profile: ReceiptDependencyProfile,
    latest: tuple[PersistedCampaign, ImpactAssessment] | None,
) -> dict[str, object]:
    dependencies = [
        {
            "evidence_id": item.evidence_id,
            "datahub_urn": item.datahub_urn,
            "schema_field_urn": item.schema_field_urn,
            "state": item.state.value,
            "role": item.role.value,
        }
        for item in profile.dependencies
    ]
    finding = None
    if latest is not None:
        campaign, assessment = latest
        finding = {
            "campaign_id": campaign.campaign.campaign_id,
            "incident_urn": campaign.campaign.incident_urn,
            "occurred_at": campaign.campaign.change.occurred_at,
            "assessment": _assessment_to_dict(assessment),
            "processing": _processing_to_dict(campaign),
        }
    return {
        "receipt_id": profile.receipt_id,
        "document_urn": profile.document_urn,
        "ended_at": profile.ended_at,
        "superseded_by": profile.superseded_by,
        "state": _profile_state(profile, latest),
        "dependency_count": len(dependencies),
        "resolved_dependency_count": sum(item.resolved for item in profile.dependencies),
        "field_lineage_coverage": profile.field_lineage.coverage.value,
        "wildcard_query": profile.field_lineage.wildcard_query,
        "dependencies": dependencies,
        "latest_finding": finding,
    }


def _searchable_decision_text(value: Mapping[str, object]) -> str:
    dependencies = value.get("dependencies")
    safe_parts = [str(value.get("receipt_id", "")), str(value.get("document_urn", ""))]
    if isinstance(dependencies, list):
        for dependency in dependencies:
            if isinstance(dependency, Mapping):
                safe_parts.extend(
                    (
                        str(dependency.get("datahub_urn", "")),
                        str(dependency.get("schema_field_urn", "")),
                    )
                )
    return " ".join(safe_parts)


def _require_page(*, limit: int, offset: int) -> None:
    if isinstance(limit, bool) or not 1 <= limit <= MAX_RESULT_LIMIT:
        raise ForensicsInputError(f"limit must be between 1 and {MAX_RESULT_LIMIT}")
    if isinstance(offset, bool) or offset < 0:
        raise ForensicsInputError("offset must be a non-negative integer")
