"""Pinned DataHub 1.6 writeback for deterministic invalidation campaigns."""

from __future__ import annotations

from datetime import datetime
from importlib import metadata
from typing import Any

from glassbox_datahub.capability_probe import PINNED_DATAHUB_SDK_VERSION
from glassbox_policy import (
    ImpactState,
    InvalidationCampaign,
    InvalidationWriteEvidence,
)


class DataHubInvalidationError(RuntimeError):
    """Raised when DataHub cannot preserve or prove campaign state."""


class DataHubInvalidationBackend:  # pragma: no cover - live integration boundary
    """Stable-SDK adapter with fetch-merge-upsert and direct verification."""

    def __init__(
        self,
        *,
        server: str,
        token: str | None = None,
        actor_urn: str = "urn:li:corpuser:datahub",
        expected_sdk_version: str = PINNED_DATAHUB_SDK_VERSION,
    ) -> None:
        from datahub.ingestion.graph.client import DataHubGraph
        from datahub.ingestion.graph.config import DatahubClientConfig
        from datahub.metadata.schema_classes import (
            AuditStampClass,
            IncidentInfoClass,
            IncidentKeyClass,
            IncidentsSummaryClass,
            IncidentStatusClass,
        )
        from datahub.sdk.document import Document
        from datahub.sdk.main_client import DataHubClient

        self._graph = DataHubGraph(config=DatahubClientConfig(server=server, token=token))
        self._client = DataHubClient(graph=self._graph)
        self._AuditStamp = AuditStampClass
        self._IncidentInfo = IncidentInfoClass
        self._IncidentKey = IncidentKeyClass
        self._IncidentStatus = IncidentStatusClass
        self._IncidentsSummary = IncidentsSummaryClass
        self._Document = Document
        self._actor_urn = actor_urn
        self._expected_sdk_version = expected_sdk_version
        self.sdk_version = metadata.version("acryl-datahub")

    @classmethod
    def from_graph(
        cls,
        graph: Any,
        *,
        actor_urn: str = "urn:li:corpuser:datahub",
        expected_sdk_version: str = PINNED_DATAHUB_SDK_VERSION,
    ) -> DataHubInvalidationBackend:
        """Reuse the authenticated graph supplied by a DataHub Actions context."""

        from datahub.metadata.schema_classes import (
            AuditStampClass,
            IncidentInfoClass,
            IncidentKeyClass,
            IncidentsSummaryClass,
            IncidentStatusClass,
        )
        from datahub.sdk.document import Document
        from datahub.sdk.main_client import DataHubClient

        backend = cls.__new__(cls)
        backend._graph = graph
        backend._client = DataHubClient(graph=graph)
        backend._AuditStamp = AuditStampClass
        backend._IncidentInfo = IncidentInfoClass
        backend._IncidentKey = IncidentKeyClass
        backend._IncidentStatus = IncidentStatusClass
        backend._IncidentsSummary = IncidentsSummaryClass
        backend._Document = Document
        backend._actor_urn = actor_urn
        backend._expected_sdk_version = expected_sdk_version
        backend.sdk_version = metadata.version("acryl-datahub")
        return backend

    def test_connection(self) -> None:
        self._graph.test_connection()
        if self.sdk_version != self._expected_sdk_version:
            raise DataHubInvalidationError(
                f"SDK drift: expected {self._expected_sdk_version}, found {self.sdk_version}"
            )

    def upsert_campaign(self, campaign: InvalidationCampaign) -> None:
        if not campaign.quarantined:
            return
        created_at = _timestamp_millis(campaign.change.occurred_at)
        priority = _incident_priority(campaign)
        audit = self._AuditStamp(
            time=created_at,
            actor=self._actor_urn,
            message="GlassBox deterministic invalidation campaign",
        )
        status = self._IncidentStatus(
            state="ACTIVE",
            stage="TRIAGE",
            message="Awaiting deterministic replay or explicit operator resolution.",
            lastUpdated=audit,
        )
        incident_key = self._IncidentKey(id=_incident_id(campaign.incident_urn))
        incident_info = self._IncidentInfo(
            type="CUSTOM",
            customType="GLASSBOX_INVALIDATION",
            title=f"GlassBox invalidation {campaign.campaign_id[-12:]}",
            description=_incident_description(campaign),
            entities=[campaign.change.entity_urn],
            priority=priority,
            status=status,
            created=audit,
            startedAt=created_at,
        )
        self._emit_aspect(campaign.incident_urn, incident_key)
        self._emit_aspect(campaign.incident_urn, incident_info)

        current_summary = self._graph.get_aspect(
            campaign.change.entity_urn,
            self._IncidentsSummary,
        )
        merged_summary = merge_active_incident_summary(
            current_summary,
            incident_urn=campaign.incident_urn,
            created_at=created_at,
            priority=priority,
        )
        self._emit_aspect(campaign.change.entity_urn, merged_summary)

        for assessment in campaign.quarantined:
            document = self._get_document(assessment.document_urn)
            document.set_custom_properties(
                {
                    "glassbox.invalidation_state": assessment.state.value,
                    "glassbox.invalidation_campaign_urn": campaign.incident_urn,
                    "glassbox.invalidation_campaign_id": campaign.campaign_id,
                    "glassbox.invalidation_policy_version": campaign.policy_version,
                    "glassbox.invalidated_at": campaign.change.occurred_at,
                    "glassbox.invalidation_change_event_id": campaign.change.event_id,
                    "glassbox.invalidation_changed_entity_urn": campaign.change.entity_urn,
                    "glassbox.invalidation_change_kind": campaign.change.kind.value,
                    "glassbox.invalidation_reason_code": assessment.reason_code,
                }
            )
            self._client.entities.update(document)

    def direct_verify(self, campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
        raw_incident = self._graph.get_entity_raw(campaign.incident_urn)
        raw_aspects = raw_incident.get("aspects")
        incident_aspects = (
            tuple(sorted(key for key, value in raw_aspects.items() if value is not None))
            if isinstance(raw_aspects, dict)
            else ()
        )
        info = self._graph.get_aspect(campaign.incident_urn, self._IncidentInfo)
        key = self._graph.get_aspect(campaign.incident_urn, self._IncidentKey)
        incident_identity_valid = (
            info is not None
            and info.entities == [campaign.change.entity_urn]
            and info.customType == "GLASSBOX_INVALIDATION"
            and key is not None
            and key.id == _incident_id(campaign.incident_urn)
        )
        summary = self._graph.get_aspect(
            campaign.change.entity_urn,
            self._IncidentsSummary,
        )
        summary_valid = incident_identity_valid and _summary_contains(
            summary, campaign.incident_urn
        )

        verified_documents: list[str] = []
        for assessment in campaign.quarantined:
            document = self._get_document(assessment.document_urn)
            expected = {
                "glassbox.invalidation_state": assessment.state.value,
                "glassbox.invalidation_campaign_urn": campaign.incident_urn,
                "glassbox.invalidation_campaign_id": campaign.campaign_id,
                "glassbox.invalidation_policy_version": campaign.policy_version,
                "glassbox.invalidated_at": campaign.change.occurred_at,
                "glassbox.invalidation_change_event_id": campaign.change.event_id,
                "glassbox.invalidation_changed_entity_urn": campaign.change.entity_urn,
                "glassbox.invalidation_change_kind": campaign.change.kind.value,
                "glassbox.invalidation_reason_code": assessment.reason_code,
            }
            if all(
                document.custom_properties.get(key_name) == value
                for key_name, value in expected.items()
            ):
                verified_documents.append(assessment.document_urn)

        return InvalidationWriteEvidence(
            incident_aspects=incident_aspects,
            target_summary_verified=summary_valid,
            quarantined_documents=tuple(verified_documents),
        )

    def _emit_aspect(self, urn: str, aspect: Any) -> None:
        from datahub.emitter.mcp import MetadataChangeProposalWrapper

        self._graph.emit(MetadataChangeProposalWrapper(entityUrn=urn, aspect=aspect))

    def _get_document(self, urn: str) -> Any:
        from datahub.metadata.urns import DocumentUrn

        document = self._client.entities.get(DocumentUrn(urn))
        if document is None or not isinstance(document, self._Document):
            raise DataHubInvalidationError(f"receipt Document not found: {urn}")
        return document


def merge_active_incident_summary(
    current: Any,
    *,
    incident_urn: str,
    created_at: int,
    priority: int,
) -> Any:
    """Preserve existing summary state and add one deterministic active incident."""

    from datahub.metadata.schema_classes import (
        IncidentsSummaryClass,
        IncidentSummaryDetailsClass,
    )

    resolved = list(current.resolvedIncidents or []) if current is not None else []
    if incident_urn in resolved:
        raise DataHubInvalidationError(
            "refusing to reactivate an incident already present in resolved summary state"
        )
    resolved_details = list(current.resolvedIncidentDetails or []) if current is not None else []
    if any(item.urn == incident_urn for item in resolved_details):
        raise DataHubInvalidationError(
            "refusing to reactivate an incident already present in resolved detail state"
        )

    active = set(current.activeIncidents or []) if current is not None else set()
    active.add(incident_urn)
    details = {
        item.urn: item
        for item in (current.activeIncidentDetails or [] if current is not None else [])
    }
    details[incident_urn] = IncidentSummaryDetailsClass(
        urn=incident_urn,
        type="CUSTOM",
        createdAt=created_at,
        priority=priority,
    )
    return IncidentsSummaryClass(
        resolvedIncidents=sorted(set(resolved)),
        activeIncidents=sorted(active),
        resolvedIncidentDetails=sorted(resolved_details, key=lambda item: item.urn),
        activeIncidentDetails=[details[urn] for urn in sorted(details)],
    )


def _summary_contains(summary: Any, incident_urn: str) -> bool:
    return (
        summary is not None
        and incident_urn in (summary.activeIncidents or [])
        and any(item.urn == incident_urn for item in (summary.activeIncidentDetails or []))
    )


def _incident_priority(campaign: InvalidationCampaign) -> int:
    states = {item.state for item in campaign.quarantined}
    return 1 if states & {ImpactState.STALE, ImpactState.UNKNOWN} else 2


def _incident_id(incident_urn: str) -> str:
    prefix = "urn:li:incident:"
    if not incident_urn.startswith(prefix):
        raise DataHubInvalidationError("campaign incident URN has an invalid entity type")
    incident_id = incident_urn.removeprefix(prefix)
    if not incident_id:
        raise DataHubInvalidationError("campaign incident URN has an empty ID")
    return incident_id


def _timestamp_millis(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DataHubInvalidationError("campaign timestamp must include an offset")
    return int(parsed.timestamp() * 1000)


def _incident_description(campaign: InvalidationCampaign) -> str:
    counts: dict[str, int] = {}
    for assessment in campaign.assessments:
        counts[assessment.state.value] = counts.get(assessment.state.value, 0) + 1
    count_text = ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))
    field_text = campaign.change.schema_field_urn or "none"
    return (
        "Deterministic GlassBox invalidation campaign. No raw evidence values are stored.\n"
        f"Campaign: {campaign.campaign_id}\n"
        f"Change event: {campaign.change.event_id}\n"
        f"Change kind: {campaign.change.kind.value}\n"
        f"Schema field: {field_text}\n"
        f"Policy: {campaign.policy_version}\n"
        f"Classifications: {count_text}"
    )
