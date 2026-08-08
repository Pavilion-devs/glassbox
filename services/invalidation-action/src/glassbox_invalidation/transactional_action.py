"""Synchronous verified execution backed by the transactional campaign outbox."""

from __future__ import annotations

import time
from collections.abc import Callable

from glassbox_invalidation.action import (
    InvalidationActionError,
    InvalidationActionReport,
    InvalidationBackend,
    NullOwnerRouter,
    OwnerRouter,
)
from glassbox_invalidation.transactional_protocol import TransactionalInvalidationStore
from glassbox_invalidation.transactional_store import (
    OutboxStatus,
)
from glassbox_policy import (
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    ReceiptDependencyProfile,
    create_campaign,
)


class TransactionalInvalidationAction:
    """Stage, lease, execute, and verify campaigns before the source can acknowledge."""

    def __init__(
        self,
        backend: InvalidationBackend,
        store: TransactionalInvalidationStore,
        *,
        worker_id: str,
        lease_duration_ms: int = 60_000,
        claim_timeout_seconds: float = 10.0,
        claim_poll_seconds: float = 0.05,
        owner_router: OwnerRouter | None = None,
        wall_clock_ms: Callable[[], int] | None = None,
        monotonic: Callable[[], float] | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        if not worker_id:
            raise ValueError("worker_id must be non-empty")
        if lease_duration_ms <= 0:
            raise ValueError("lease_duration_ms must be positive")
        if claim_timeout_seconds <= 0:
            raise ValueError("claim_timeout_seconds must be positive")
        if claim_poll_seconds <= 0:
            raise ValueError("claim_poll_seconds must be positive")
        self._backend = backend
        self._store = store
        self._worker_id = worker_id
        self._lease_duration_ms = lease_duration_ms
        self._claim_timeout_seconds = claim_timeout_seconds
        self._claim_poll_seconds = claim_poll_seconds
        self._owner_router = owner_router or NullOwnerRouter()
        self._wall_clock_ms = wall_clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._monotonic = monotonic or time.monotonic
        self._sleep = sleep or time.sleep

    def process(
        self,
        change: NormalizedChange,
        profiles: tuple[ReceiptDependencyProfile, ...],
    ) -> InvalidationActionReport:
        campaign = create_campaign(change, profiles)
        self._store.stage_campaign(campaign)
        if not campaign.quarantined:
            return InvalidationActionReport(
                campaign=campaign,
                emissions=0,
                write_evidence=None,
                routed_destinations=(),
            )

        deadline = self._monotonic() + self._claim_timeout_seconds
        while True:
            task = self._store.get_task(campaign.campaign_id)
            if task is None:  # pragma: no cover - stage and read share one database
                raise InvalidationActionError("staged campaign disappeared from the outbox")
            if task.status is OutboxStatus.COMPLETED:
                return self._reuse_completed(campaign, task.write_evidence)
            claim = self._store.claim(
                campaign.campaign_id,
                worker_id=self._worker_id,
                now_ms=self._wall_clock_ms(),
                lease_duration_ms=self._lease_duration_ms,
            )
            if claim is not None and claim.lease_owner == self._worker_id:
                return self._execute_claim(campaign)
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise InvalidationActionError(
                    "campaign remained leased by another worker past the claim timeout"
                )
            self._sleep(min(self._claim_poll_seconds, remaining))

    def _execute_claim(self, campaign: InvalidationCampaign) -> InvalidationActionReport:
        try:
            self._backend.upsert_campaign(campaign)
            self._renew(campaign)
            self._backend.upsert_campaign(campaign)
            self._renew(campaign)
            evidence = self._backend.direct_verify(campaign)
            self._validate_evidence(campaign, evidence)
            self._store.complete(campaign, evidence, worker_id=self._worker_id)
        except Exception as exc:
            current = self._store.get_task(campaign.campaign_id)
            if current is not None and current.status is OutboxStatus.COMPLETED:
                return self._reuse_completed(campaign, current.write_evidence)
            try:
                self._store.release(
                    campaign,
                    worker_id=self._worker_id,
                    error_type=type(exc).__name__,
                )
            except Exception as release_error:
                raise InvalidationActionError(
                    "campaign writeback failed and its outbox lease could not be released"
                ) from release_error
            if isinstance(exc, InvalidationActionError):
                raise
            raise InvalidationActionError("DataHub campaign writeback failed") from exc

        destinations, reused_routing = self._route_owner(campaign)
        report = InvalidationActionReport(
            campaign=campaign,
            emissions=2,
            write_evidence=evidence,
            routed_destinations=destinations,
            reused_routing=reused_routing,
        )
        if not report.valid:  # pragma: no cover - defensive invariant
            raise InvalidationActionError("invalid transactional action report")
        return report

    def _reuse_completed(
        self,
        campaign: InvalidationCampaign,
        stored_evidence: InvalidationWriteEvidence | None,
    ) -> InvalidationActionReport:
        if stored_evidence is None:
            raise InvalidationActionError("completed campaign has no stored write evidence")
        evidence = self._backend.direct_verify(campaign)
        self._validate_evidence(campaign, evidence)
        if evidence != stored_evidence:
            raise InvalidationActionError(
                "current DataHub readback differs from sealed outbox write evidence"
            )
        destinations, reused_routing = self._route_owner(campaign)
        report = InvalidationActionReport(
            campaign=campaign,
            emissions=0,
            write_evidence=evidence,
            routed_destinations=destinations,
            reused_completion=True,
            reused_routing=reused_routing,
        )
        if not report.valid:  # pragma: no cover - defensive invariant
            raise InvalidationActionError("invalid reused transactional report")
        return report

    def _route_owner(self, campaign: InvalidationCampaign) -> tuple[tuple[str, ...], bool]:
        deadline = self._monotonic() + self._claim_timeout_seconds
        while True:
            task = self._store.get_owner_routing_task(campaign.campaign_id)
            if task is None:
                raise InvalidationActionError(
                    "verified campaign has no durable owner-routing obligation"
                )
            if task.status is OutboxStatus.COMPLETED:
                return (), True
            claim = self._store.claim_owner_routing(
                campaign.campaign_id,
                worker_id=self._worker_id,
                now_ms=self._wall_clock_ms(),
                lease_duration_ms=self._lease_duration_ms,
            )
            if claim is not None and claim.lease_owner == self._worker_id:
                break
            remaining = deadline - self._monotonic()
            if remaining <= 0:
                raise InvalidationActionError(
                    "owner routing remained leased by another worker past the claim timeout"
                )
            self._sleep(min(self._claim_poll_seconds, remaining))

        try:
            self._store.renew_owner_routing(
                campaign.campaign_id,
                worker_id=self._worker_id,
                now_ms=self._wall_clock_ms(),
                lease_duration_ms=self._lease_duration_ms,
            )
            destinations = self._owner_router.route(
                campaign,
                idempotency_key=campaign.campaign_id,
            )
            self._store.complete_owner_routing(
                campaign,
                destinations,
                worker_id=self._worker_id,
            )
            return destinations, False
        except Exception as exc:
            current = self._store.get_owner_routing_task(campaign.campaign_id)
            if current is not None and current.status is OutboxStatus.COMPLETED:
                return (), True
            try:
                self._store.release_owner_routing(
                    campaign,
                    worker_id=self._worker_id,
                    error_type=type(exc).__name__,
                )
            except Exception as release_error:
                raise InvalidationActionError(
                    "owner routing failed and its outbox lease could not be released"
                ) from release_error
            if isinstance(exc, InvalidationActionError):
                raise
            raise InvalidationActionError("owner routing failed") from exc

    def _renew(self, campaign: InvalidationCampaign) -> None:
        self._store.renew(
            campaign.campaign_id,
            worker_id=self._worker_id,
            now_ms=self._wall_clock_ms(),
            lease_duration_ms=self._lease_duration_ms,
        )

    @staticmethod
    def _validate_evidence(
        campaign: InvalidationCampaign,
        evidence: InvalidationWriteEvidence,
    ) -> None:
        expected = tuple(item.document_urn for item in campaign.quarantined)
        if not evidence.valid:
            raise InvalidationActionError("DataHub direct verification was incomplete")
        if evidence.quarantined_documents != expected:
            raise InvalidationActionError("DataHub quarantine readback did not match the campaign")


__all__ = ["TransactionalInvalidationAction"]
