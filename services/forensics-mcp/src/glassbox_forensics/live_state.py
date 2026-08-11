"""Read-only adapter over the invalidation Action's transactional state."""

from __future__ import annotations

from glassbox_forensics.service import PersistedCampaign, PersistedReceiptPublication
from glassbox_invalidation.transactional_protocol import TransactionalInvalidationStore
from glassbox_invalidation.transactional_store import OutboxTask, ReceiptPublicationTask


class TransactionalCampaignReader:
    """Project verified outbox tasks into the bounded forensics read model."""

    def __init__(self, store: TransactionalInvalidationStore) -> None:
        self._store = store

    def get_campaign(self, campaign_id: str) -> PersistedCampaign | None:
        task = self._store.get_task(campaign_id)
        return _campaign(task) if task is not None else None

    def all_campaigns(self) -> tuple[PersistedCampaign, ...]:
        return tuple(_campaign(task) for task in self._store.list_tasks())


class TransactionalReceiptPublicationReader:
    """Project sealed publication tasks into the bounded forensics read model."""

    def __init__(
        self,
        store: TransactionalInvalidationStore,
        *,
        durability_authority: str = "TRANSACTIONAL_STATE",
    ) -> None:
        self._store = store
        self._durability_authority = durability_authority

    def get_publication(self, receipt_id: str) -> PersistedReceiptPublication | None:
        task = self._store.get_receipt_publication_task(receipt_id)
        return (
            _publication(task, durability_authority=self._durability_authority)
            if task is not None
            else None
        )


def _campaign(task: OutboxTask) -> PersistedCampaign:
    return PersistedCampaign(
        campaign=task.campaign,
        workflow_status=task.status.value,
        attempt_count=task.attempt_count,
        datahub_writeback_verified=(task.write_evidence is not None and task.write_evidence.valid),
        last_error_recorded=task.last_error_type is not None,
    )


def _publication(
    task: ReceiptPublicationTask,
    *,
    durability_authority: str,
) -> PersistedReceiptPublication:
    evidence = task.publication_evidence
    return PersistedReceiptPublication(
        receipt_id=task.receipt_id,
        workflow_status=task.status.value,
        attempt_count=task.attempt_count,
        last_error_recorded=task.last_error_type is not None,
        document_urn=evidence.document_urn if evidence is not None else None,
        aspect_names=evidence.aspect_names if evidence is not None else (),
        emission_count=evidence.emission_count if evidence is not None else None,
        durability_authority=durability_authority,
    )


__all__ = ["TransactionalCampaignReader", "TransactionalReceiptPublicationReader"]
