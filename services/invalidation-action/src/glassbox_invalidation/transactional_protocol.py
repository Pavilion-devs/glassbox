"""Structural contract shared by transactional invalidation state adapters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Protocol

from glassbox_invalidation.audit_log import CampaignAuditRecord
from glassbox_invalidation.transactional_store import (
    OutboxTask,
    OwnerRoutingEvidence,
    OwnerRoutingTask,
    ReceiptPublicationEvidence,
    ReceiptPublicationTask,
    TransactionalIntegrityReport,
)
from glassbox_policy import (
    FieldLineageProof,
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    ReceiptDependencyProfile,
)


class TransactionalInvalidationStore(Protocol):
    """Behavioral parity contract for SQLite and server-database adapters."""

    def register(
        self,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
        superseded_by: str | None = None,
    ) -> bool: ...

    def register_many(
        self,
        registrations: Sequence[tuple[Mapping[str, Any], FieldLineageProof | None, str | None]],
    ) -> tuple[bool, ...]: ...

    def all_profiles(self) -> tuple[ReceiptDependencyProfile, ...]: ...

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None: ...

    def get_receipt_publication_task(self, receipt_id: str) -> ReceiptPublicationTask | None: ...

    def list_receipt_publication_tasks(self) -> tuple[ReceiptPublicationTask, ...]: ...

    def claim_receipt_publication(
        self,
        receipt_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> ReceiptPublicationTask | None: ...

    def renew_receipt_publication(
        self,
        receipt_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> ReceiptPublicationTask: ...

    def release_receipt_publication(
        self, receipt_id: str, *, worker_id: str, error_type: str
    ) -> None: ...

    def complete_receipt_publication(
        self,
        receipt_id: str,
        evidence: ReceiptPublicationEvidence,
        *,
        worker_id: str,
    ) -> bool: ...

    def candidates(self, change: NormalizedChange) -> tuple[ReceiptDependencyProfile, ...]: ...

    def stage_campaign(self, campaign: InvalidationCampaign) -> bool: ...

    def get_task(self, campaign_id: str) -> OutboxTask | None: ...

    def list_tasks(self) -> tuple[OutboxTask, ...]: ...

    def claim(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OutboxTask | None: ...

    def renew(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OutboxTask: ...

    def release(
        self,
        campaign: InvalidationCampaign,
        *,
        worker_id: str,
        error_type: str,
    ) -> None: ...

    def complete(
        self,
        campaign: InvalidationCampaign,
        evidence: InvalidationWriteEvidence,
        *,
        worker_id: str,
    ) -> bool: ...

    def get_owner_routing_task(self, campaign_id: str) -> OwnerRoutingTask | None: ...

    def list_owner_routing_tasks(self) -> tuple[OwnerRoutingTask, ...]: ...

    def claim_owner_routing(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OwnerRoutingTask | None: ...

    def renew_owner_routing(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OwnerRoutingTask: ...

    def release_owner_routing(
        self,
        campaign: InvalidationCampaign,
        *,
        worker_id: str,
        error_type: str,
    ) -> None: ...

    def complete_owner_routing(
        self,
        campaign: InvalidationCampaign,
        destinations: tuple[str, ...],
        *,
        worker_id: str,
    ) -> OwnerRoutingEvidence: ...

    def read_audit_records(self) -> tuple[CampaignAuditRecord, ...]: ...

    def verify_integrity(self) -> TransactionalIntegrityReport: ...


__all__ = ["TransactionalInvalidationStore"]
