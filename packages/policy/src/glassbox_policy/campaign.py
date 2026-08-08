"""Content-addressed invalidation campaigns built from pure policy decisions."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from glassbox_dbom.canonical import canonicalize
from glassbox_policy.materiality import (
    POLICY_VERSION,
    ImpactAssessment,
    NormalizedChange,
    ReceiptDependencyProfile,
    classify_receipts,
)


@dataclass(frozen=True)
class InvalidationWriteEvidence:
    """Authoritative persistence evidence returned by a campaign adapter."""

    incident_aspects: tuple[str, ...]
    target_summary_verified: bool
    quarantined_documents: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return {"incidentInfo", "incidentKey"}.issubset(
            self.incident_aspects
        ) and self.target_summary_verified


@dataclass(frozen=True)
class InvalidationCampaign:
    """One deterministic campaign and its complete classification audit."""

    campaign_id: str
    incident_urn: str
    change: NormalizedChange
    assessments: tuple[ImpactAssessment, ...]
    policy_version: str = POLICY_VERSION

    @property
    def quarantined(self) -> tuple[ImpactAssessment, ...]:
        return tuple(item for item in self.assessments if item.quarantine_required)


def create_campaign(
    change: NormalizedChange,
    profiles: tuple[ReceiptDependencyProfile, ...],
) -> InvalidationCampaign:
    """Create the same campaign ID and verdicts for every redelivery."""

    campaign_id, incident_urn = campaign_identity(change)
    return InvalidationCampaign(
        campaign_id=campaign_id,
        incident_urn=incident_urn,
        change=change,
        assessments=classify_receipts(profiles, change),
    )


def campaign_identity(change: NormalizedChange) -> tuple[str, str]:
    """Return the deterministic campaign and incident identities for a change."""

    material = {
        "policy_version": POLICY_VERSION,
        "event_id": change.event_id,
        "entity_urn": change.entity_urn,
        "aspect_name": change.aspect_name,
        "kind": change.kind.value,
        "occurred_at": change.occurred_at,
        "schema_field_urn": change.schema_field_urn,
        "before_digest": change.before_digest,
        "after_digest": change.after_digest,
    }
    digest = hashlib.sha256(canonicalize(material)).hexdigest()
    return (
        f"gbx:invalidation:sha256:{digest}",
        f"urn:li:incident:glassbox.invalidation.{digest}",
    )
