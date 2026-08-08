"""Read-only adapter over the invalidation Action's transactional state."""

from __future__ import annotations

from glassbox_forensics.service import PersistedCampaign
from glassbox_invalidation.transactional_protocol import TransactionalInvalidationStore
from glassbox_invalidation.transactional_store import OutboxTask


class TransactionalCampaignReader:
    """Project verified outbox tasks into the bounded forensics read model."""

    def __init__(self, store: TransactionalInvalidationStore) -> None:
        self._store = store

    def get_campaign(self, campaign_id: str) -> PersistedCampaign | None:
        task = self._store.get_task(campaign_id)
        return _campaign(task) if task is not None else None

    def all_campaigns(self) -> tuple[PersistedCampaign, ...]:
        return tuple(_campaign(task) for task in self._store.list_tasks())


def _campaign(task: OutboxTask) -> PersistedCampaign:
    return PersistedCampaign(
        campaign=task.campaign,
        workflow_status=task.status.value,
        attempt_count=task.attempt_count,
        datahub_writeback_verified=(task.write_evidence is not None and task.write_evidence.valid),
        last_error_recorded=task.last_error_type is not None,
    )


__all__ = ["TransactionalCampaignReader"]
