"""Idempotent invalidation campaign orchestration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from glassbox_invalidation.audit_log import (
    AuditPhase,
    CampaignAuditSink,
    campaign_audit_record,
)
from glassbox_policy import (
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    ReceiptDependencyProfile,
    create_campaign,
)


class InvalidationActionError(RuntimeError):
    """Raised when classification succeeded but writeback did not verify."""


class InvalidationBackend(Protocol):
    """Mutation transport; it receives verdicts but owns no policy."""

    def upsert_campaign(self, campaign: InvalidationCampaign) -> None: ...

    def direct_verify(self, campaign: InvalidationCampaign) -> InvalidationWriteEvidence: ...


class OwnerRouter(Protocol):
    """Optional delivery adapter with caller-provided idempotency identity."""

    def route(self, campaign: InvalidationCampaign, *, idempotency_key: str) -> tuple[str, ...]: ...


class NullOwnerRouter:
    """Explicitly configured no-delivery router for local and library use."""

    def route(self, campaign: InvalidationCampaign, *, idempotency_key: str) -> tuple[str, ...]:
        del campaign, idempotency_key
        return ()


@dataclass(frozen=True)
class InvalidationActionReport:
    """Complete outcome of one event delivery."""

    campaign: InvalidationCampaign
    emissions: int
    write_evidence: InvalidationWriteEvidence | None
    routed_destinations: tuple[str, ...]
    reused_completion: bool = False
    reused_routing: bool = False

    @property
    def no_op(self) -> bool:
        return not self.campaign.quarantined

    @property
    def valid(self) -> bool:
        if self.no_op:
            return self.emissions == 0 and self.write_evidence is None
        return (
            self.emissions == (0 if self.reused_completion else 2)
            and self.write_evidence is not None
            and self.write_evidence.valid
            and self.write_evidence.quarantined_documents
            == tuple(item.document_urn for item in self.campaign.quarantined)
        )


class InvalidationAction:
    """Classify, upsert twice, verify directly, audit, then route."""

    def __init__(
        self,
        backend: InvalidationBackend,
        audit_sink: CampaignAuditSink,
        *,
        owner_router: OwnerRouter | None = None,
    ) -> None:
        self._backend = backend
        self._audit_sink = audit_sink
        self._owner_router = owner_router or NullOwnerRouter()

    def process(
        self,
        change: NormalizedChange,
        profiles: tuple[ReceiptDependencyProfile, ...],
    ) -> InvalidationActionReport:
        campaign = create_campaign(change, profiles)
        self._audit_sink.record(
            campaign_audit_record(campaign, AuditPhase.CLASSIFIED, detail="policy-complete")
        )
        if not campaign.quarantined:
            return InvalidationActionReport(
                campaign=campaign,
                emissions=0,
                write_evidence=None,
                routed_destinations=(),
            )

        try:
            self._backend.upsert_campaign(campaign)
            self._backend.upsert_campaign(campaign)
            evidence = self._backend.direct_verify(campaign)
            if not evidence.valid:
                raise InvalidationActionError("DataHub direct verification was incomplete")
            expected_documents = tuple(item.document_urn for item in campaign.quarantined)
            if evidence.quarantined_documents != expected_documents:
                raise InvalidationActionError(
                    "DataHub quarantine readback did not match the campaign"
                )
        except Exception as exc:
            self._audit_sink.record(
                campaign_audit_record(
                    campaign,
                    AuditPhase.DATAHUB_FAILED,
                    detail=f"failure:{type(exc).__name__}",
                )
            )
            if isinstance(exc, InvalidationActionError):
                raise
            raise InvalidationActionError("DataHub campaign writeback failed") from exc

        self._audit_sink.record(
            campaign_audit_record(campaign, AuditPhase.DATAHUB_VERIFIED, detail="direct-readback")
        )
        destinations = self._owner_router.route(
            campaign,
            idempotency_key=campaign.campaign_id,
        )
        report = InvalidationActionReport(
            campaign=campaign,
            emissions=2,
            write_evidence=evidence,
            routed_destinations=destinations,
        )
        if not report.valid:  # pragma: no cover - defensive invariant
            raise InvalidationActionError("invalid action report after verified writeback")
        return report
