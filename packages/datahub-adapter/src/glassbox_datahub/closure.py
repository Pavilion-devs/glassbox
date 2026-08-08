"""Verified, idempotent DataHub incident closure after isolated supersession."""

from __future__ import annotations

import copy
import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Protocol

from glassbox_datahub.capability_probe import PINNED_DATAHUB_SDK_VERSION
from glassbox_datahub.receipt_emitter import receipt_document_urn
from glassbox_datahub.supersession import (
    supersession_document_urn,
    supersession_properties,
)
from glassbox_dbom.canonical import canonicalize
from glassbox_replay import RecoveryClosureRecord, SupersessionRecord


class RecoveryClosureError(RuntimeError):
    """Raised when recovery projection or incident resolution cannot be proven."""


@dataclass(frozen=True)
class RecoveryClosurePrerequisites:
    """Fresh server readback captured before any incident mutation."""

    incident_active: bool
    target_summary_active: bool
    supersession_verified: bool
    supersession_aspects: tuple[str, ...]
    source_receipt_verified: bool
    source_receipt_aspects: tuple[str, ...]
    replay_receipt_verified: bool
    replay_receipt_aspects: tuple[str, ...]
    receipt_entity_digests: tuple[tuple[str, str], ...]
    incident_already_closed_by_record: bool = False
    target_summary_resolved: bool = False

    @property
    def valid(self) -> bool:
        return (
            self.incident_active
            and self.target_summary_active
            and self.supersession_verified
            and bool(self.supersession_aspects)
            and self.source_receipt_verified
            and bool(self.source_receipt_aspects)
            and self.replay_receipt_verified
            and bool(self.replay_receipt_aspects)
            and len(self.receipt_entity_digests) == 2
        )

    @property
    def recoverable_completion(self) -> bool:
        """Whether a prior exact closure can be sealed after an uncertain crash."""

        return (
            self.incident_already_closed_by_record
            and self.target_summary_resolved
            and self.supersession_verified
            and bool(self.supersession_aspects)
            and self.source_receipt_verified
            and bool(self.source_receipt_aspects)
            and self.replay_receipt_verified
            and bool(self.replay_receipt_aspects)
            and len(self.receipt_entity_digests) == 2
        )


@dataclass(frozen=True)
class RecoveryClosureReadback:
    """Fresh server readback captured after the idempotent double-write."""

    incident_state: str
    incident_stage: str | None
    closure_id_verified: bool
    target_summary_resolved: bool
    supersession_verified: bool
    incident_aspects: tuple[str, ...]
    receipt_entity_digests: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class RecoveryClosureReport:
    """Evidence that DataHub resolved exactly one incident without rewriting receipts."""

    closure_id: str
    campaign_id: str
    incident_urn: str
    supersession_document_urn: str
    source_receipt_document_urn: str
    replay_receipt_document_urn: str
    incident_aspects: tuple[str, ...]
    target_summary_resolved: bool
    supersession_verified: bool
    receipt_documents_unchanged: bool
    emission_attempts: int = 2
    aspect_writes: int = 4
    reused_completion: bool = False

    @property
    def valid(self) -> bool:
        return (
            (
                (self.reused_completion and self.emission_attempts == 0 and self.aspect_writes == 0)
                or (
                    not self.reused_completion
                    and self.emission_attempts == 2
                    and self.aspect_writes == 4
                )
            )
            and bool(self.incident_aspects)
            and self.target_summary_resolved
            and self.supersession_verified
            and self.receipt_documents_unchanged
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "closure_id": self.closure_id,
            "campaign_id": self.campaign_id,
            "incident_urn": self.incident_urn,
            "supersession_document_urn": self.supersession_document_urn,
            "source_receipt_document_urn": self.source_receipt_document_urn,
            "replay_receipt_document_urn": self.replay_receipt_document_urn,
            "incident_aspects": list(self.incident_aspects),
            "target_summary_resolved": self.target_summary_resolved,
            "supersession_verified": self.supersession_verified,
            "receipt_documents_unchanged": self.receipt_documents_unchanged,
            "emission_attempts": self.emission_attempts,
            "aspect_writes": self.aspect_writes,
            "reused_completion": self.reused_completion,
            "raw_values_retained": False,
        }


class RecoveryClosureBackend(Protocol):
    """Narrow transport boundary for gated incident resolution."""

    def verify_closure_prerequisites(
        self,
        record: RecoveryClosureRecord,
        supersession: SupersessionRecord,
    ) -> RecoveryClosurePrerequisites: ...

    def upsert_recovery_closure(self, record: RecoveryClosureRecord) -> str: ...

    def direct_read_recovery_closure(
        self,
        record: RecoveryClosureRecord,
        supersession: SupersessionRecord,
    ) -> RecoveryClosureReadback: ...


class RecoveryClosureEmitter:
    """Fail closed unless preflight, both writes, and final direct readback agree."""

    def __init__(self, backend: RecoveryClosureBackend) -> None:
        self._backend = backend

    def close_verified(
        self,
        record: RecoveryClosureRecord,
        supersession: SupersessionRecord,
    ) -> RecoveryClosureReport:
        if not record.valid:
            raise RecoveryClosureError("refusing invalid recovery closure content address")
        if (
            not supersession.valid
            or record.supersession_id != supersession.supersession_id
            or record.source_receipt_id != supersession.source_receipt_id
            or record.replay_receipt_id != supersession.replay_receipt_id
            or record.execution_id != supersession.execution_id
        ):
            raise RecoveryClosureError("recovery closure supersession binding is invalid")
        expected_supersession_urn = supersession_document_urn(supersession.supersession_id)
        expected_source_urn = receipt_document_urn(record.source_receipt_id)
        expected_replay_urn = receipt_document_urn(record.replay_receipt_id)
        before = self._backend.verify_closure_prerequisites(record, supersession)
        if not before.valid and not before.recoverable_completion:
            raise RecoveryClosureError("DataHub recovery closure prerequisites did not verify")
        before_urns = {urn for urn, _ in before.receipt_entity_digests}
        if before_urns != {expected_source_urn, expected_replay_urn}:
            raise RecoveryClosureError("DataHub receipt prerequisite identities are invalid")

        if before.recoverable_completion:
            readback = self._backend.direct_read_recovery_closure(record, supersession)
            self._require_readback(readback)
            unchanged = before.receipt_entity_digests == readback.receipt_entity_digests
            if not unchanged:
                raise RecoveryClosureError("receipt Documents changed during incident closure")
            return RecoveryClosureReport(
                closure_id=record.closure_id,
                campaign_id=record.campaign_id,
                incident_urn=record.incident_urn,
                supersession_document_urn=expected_supersession_urn,
                source_receipt_document_urn=expected_source_urn,
                replay_receipt_document_urn=expected_replay_urn,
                incident_aspects=readback.incident_aspects,
                target_summary_resolved=readback.target_summary_resolved,
                supersession_verified=readback.supersession_verified,
                receipt_documents_unchanged=unchanged,
                emission_attempts=0,
                aspect_writes=0,
                reused_completion=True,
            )
        first = self._backend.upsert_recovery_closure(record)
        second = self._backend.upsert_recovery_closure(record)
        if first != second or first != record.incident_urn:
            raise RecoveryClosureError("DataHub recovery closure was not idempotent")
        readback = self._backend.direct_read_recovery_closure(record, supersession)
        self._require_readback(readback)
        unchanged = before.receipt_entity_digests == readback.receipt_entity_digests
        if not unchanged:
            raise RecoveryClosureError("receipt Documents changed during incident closure")
        return RecoveryClosureReport(
            closure_id=record.closure_id,
            campaign_id=record.campaign_id,
            incident_urn=record.incident_urn,
            supersession_document_urn=expected_supersession_urn,
            source_receipt_document_urn=expected_source_urn,
            replay_receipt_document_urn=expected_replay_urn,
            incident_aspects=readback.incident_aspects,
            target_summary_resolved=readback.target_summary_resolved,
            supersession_verified=readback.supersession_verified,
            receipt_documents_unchanged=unchanged,
        )

    @staticmethod
    def _require_readback(readback: RecoveryClosureReadback) -> None:
        if (
            readback.incident_state != "RESOLVED"
            or readback.incident_stage != "FIXED"
            or not readback.closure_id_verified
            or not readback.target_summary_resolved
            or not readback.supersession_verified
            or not readback.incident_aspects
        ):
            raise RecoveryClosureError("DataHub recovery closure direct readback did not verify")


class DataHubRecoveryClosureBackend:  # pragma: no cover - live integration boundary
    """Pinned DataHub adapter that resolves an incident only after fresh readback."""

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

        graph = DataHubGraph(config=DatahubClientConfig(server=server, token=token))
        self._initialize(
            graph,
            actor_urn=actor_urn,
            expected_sdk_version=expected_sdk_version,
        )

    @classmethod
    def from_graph(
        cls,
        graph: Any,
        *,
        actor_urn: str = "urn:li:corpuser:datahub",
        expected_sdk_version: str = PINNED_DATAHUB_SDK_VERSION,
    ) -> DataHubRecoveryClosureBackend:
        backend = cls.__new__(cls)
        backend._initialize(
            graph,
            actor_urn=actor_urn,
            expected_sdk_version=expected_sdk_version,
        )
        return backend

    def _initialize(
        self,
        graph: Any,
        *,
        actor_urn: str,
        expected_sdk_version: str,
    ) -> None:
        from datahub.metadata.schema_classes import (
            AuditStampClass,
            DocumentInfoClass,
            IncidentInfoClass,
            IncidentsSummaryClass,
            IncidentStatusClass,
        )

        self._graph = graph
        self._AuditStamp = AuditStampClass
        self._DocumentInfo = DocumentInfoClass
        self._IncidentInfo = IncidentInfoClass
        self._IncidentsSummary = IncidentsSummaryClass
        self._IncidentStatus = IncidentStatusClass
        self._actor_urn = actor_urn
        self._expected_sdk_version = expected_sdk_version
        self.sdk_version = metadata.version("acryl-datahub")

    def test_connection(self) -> None:
        self._graph.test_connection()
        if self.sdk_version != self._expected_sdk_version:
            raise RecoveryClosureError(
                f"SDK drift: expected {self._expected_sdk_version}, found {self.sdk_version}"
            )

    def verify_closure_prerequisites(
        self,
        record: RecoveryClosureRecord,
        supersession: SupersessionRecord,
    ) -> RecoveryClosurePrerequisites:
        info = self._graph.get_aspect(record.incident_urn, self._IncidentInfo)
        target_urn = _single_incident_entity(info)
        summary = (
            self._graph.get_aspect(target_urn, self._IncidentsSummary)
            if target_urn is not None
            else None
        )
        source_urn = receipt_document_urn(record.source_receipt_id)
        replay_urn = receipt_document_urn(record.replay_receipt_id)
        source_verified, source_aspects = self._verify_receipt_document(
            source_urn,
            record.source_receipt_id,
            incident_urn=record.incident_urn,
        )
        replay_verified, replay_aspects = self._verify_receipt_document(
            replay_urn,
            record.replay_receipt_id,
        )
        supersession_verified, supersession_aspects = self._verify_supersession(supersession)
        return RecoveryClosurePrerequisites(
            incident_active=(
                info is not None and info.status is not None and info.status.state == "ACTIVE"
            ),
            target_summary_active=_summary_is_active(summary, record.incident_urn),
            supersession_verified=supersession_verified,
            supersession_aspects=supersession_aspects,
            source_receipt_verified=source_verified,
            source_receipt_aspects=source_aspects,
            replay_receipt_verified=replay_verified,
            replay_receipt_aspects=replay_aspects,
            receipt_entity_digests=self._receipt_digests(source_urn, replay_urn),
            incident_already_closed_by_record=(
                info is not None
                and info.status is not None
                and info.status.state == "RESOLVED"
                and info.status.stage == "FIXED"
                and info.status.message == _closure_message(record.closure_id)
            ),
            target_summary_resolved=_summary_is_resolved(summary, record.incident_urn),
        )

    def upsert_recovery_closure(self, record: RecoveryClosureRecord) -> str:
        info = self._graph.get_aspect(record.incident_urn, self._IncidentInfo)
        target_urn = _single_incident_entity(info)
        if info is None or target_urn is None or info.status is None:
            raise RecoveryClosureError("DataHub incident is unavailable for recovery closure")
        expected_message = _closure_message(record.closure_id)
        if info.status.state == "RESOLVED" and (
            info.status.stage != "FIXED" or info.status.message != expected_message
        ):
            raise RecoveryClosureError("refusing to overwrite a different incident resolution")
        if info.status.state not in {"ACTIVE", "RESOLVED"}:
            raise RecoveryClosureError("DataHub incident has an unsupported state")
        updated = copy.deepcopy(info)
        updated.status = self._IncidentStatus(
            state="RESOLVED",
            stage="FIXED",
            message=expected_message,
            lastUpdated=self._AuditStamp(
                time=_timestamp_millis(record.closed_at),
                actor=self._actor_urn,
                message="GlassBox verified isolated replay recovery",
            ),
        )
        current_summary = self._graph.get_aspect(target_urn, self._IncidentsSummary)
        resolved_summary = merge_resolved_incident_summary(
            current_summary,
            incident_urn=record.incident_urn,
            resolved_at=_timestamp_millis(record.closed_at),
        )
        self._emit_aspect(record.incident_urn, updated)
        self._emit_aspect(target_urn, resolved_summary)
        return record.incident_urn

    def direct_read_recovery_closure(
        self,
        record: RecoveryClosureRecord,
        supersession: SupersessionRecord,
    ) -> RecoveryClosureReadback:
        info = self._graph.get_aspect(record.incident_urn, self._IncidentInfo)
        target_urn = _single_incident_entity(info)
        summary = (
            self._graph.get_aspect(target_urn, self._IncidentsSummary)
            if target_urn is not None
            else None
        )
        supersession_verified, _ = self._verify_supersession(supersession)
        source_urn = receipt_document_urn(record.source_receipt_id)
        replay_urn = receipt_document_urn(record.replay_receipt_id)
        return RecoveryClosureReadback(
            incident_state=(info.status.state if info is not None and info.status else "MISSING"),
            incident_stage=(info.status.stage if info is not None and info.status else None),
            closure_id_verified=(
                info is not None
                and info.status is not None
                and info.status.message == _closure_message(record.closure_id)
            ),
            target_summary_resolved=_summary_is_resolved(summary, record.incident_urn),
            supersession_verified=supersession_verified,
            incident_aspects=self._aspect_names(record.incident_urn),
            receipt_entity_digests=self._receipt_digests(source_urn, replay_urn),
        )

    def _verify_receipt_document(
        self,
        urn: str,
        receipt_id: str,
        *,
        incident_urn: str | None = None,
    ) -> tuple[bool, tuple[str, ...]]:
        info = self._graph.get_aspect(urn, self._DocumentInfo)
        properties = info.customProperties if info is not None else None
        valid = properties is not None and properties.get("glassbox.receipt_id") == receipt_id
        if incident_urn is not None:
            valid = bool(
                valid
                and properties is not None
                and properties.get("glassbox.invalidation_state") == "STALE"
                and properties.get("glassbox.invalidation_campaign_urn") == incident_urn
            )
        aspects = self._aspect_names(urn)
        return bool(valid and aspects), aspects

    def _verify_supersession(
        self,
        supersession: SupersessionRecord,
    ) -> tuple[bool, tuple[str, ...]]:
        urn = supersession_document_urn(supersession.supersession_id)
        info = self._graph.get_aspect(urn, self._DocumentInfo)
        properties = info.customProperties if info is not None else None
        expected = supersession_properties(supersession)
        aspects = self._aspect_names(urn)
        return (
            bool(
                properties is not None
                and aspects
                and all(properties.get(key) == value for key, value in expected.items())
            ),
            aspects,
        )

    def _receipt_digests(self, *urns: str) -> tuple[tuple[str, str], ...]:
        return tuple(sorted((urn, self._entity_digest(urn)) for urn in urns))

    def _entity_digest(self, urn: str) -> str:
        raw = self._graph.get_entity_raw(urn)
        if not isinstance(raw, Mapping) or not raw.get("aspects"):
            raise RecoveryClosureError(f"DataHub direct read returned no aspects for {urn}")
        return hashlib.sha256(canonicalize(raw)).hexdigest()

    def _aspect_names(self, urn: str) -> tuple[str, ...]:
        raw = self._graph.get_entity_raw(urn)
        aspects = raw.get("aspects") if isinstance(raw, Mapping) else None
        return (
            tuple(sorted(key for key, value in aspects.items() if value is not None))
            if isinstance(aspects, Mapping)
            else ()
        )

    def _emit_aspect(self, urn: str, aspect: Any) -> None:
        from datahub.emitter.mcp import MetadataChangeProposalWrapper

        self._graph.emit(MetadataChangeProposalWrapper(entityUrn=urn, aspect=aspect))


def merge_resolved_incident_summary(
    current: Any,
    *,
    incident_urn: str,
    resolved_at: int,
) -> Any:
    """Move exactly one incident from active to resolved while preserving all others."""

    from datahub.metadata.schema_classes import (
        IncidentsSummaryClass,
        IncidentSummaryDetailsClass,
    )

    if current is None:
        raise RecoveryClosureError("incident target has no incidents summary")
    active = set(current.activeIncidents or [])
    resolved = set(current.resolvedIncidents or [])
    active_details = {item.urn: item for item in (current.activeIncidentDetails or [])}
    resolved_details = {item.urn: item for item in (current.resolvedIncidentDetails or [])}
    active_detail = active_details.get(incident_urn)
    resolved_detail = resolved_details.get(incident_urn)
    if incident_urn in active and active_detail is not None:
        active.remove(incident_urn)
        del active_details[incident_urn]
        resolved.add(incident_urn)
        resolved_details[incident_urn] = IncidentSummaryDetailsClass(
            urn=active_detail.urn,
            type=active_detail.type,
            createdAt=active_detail.createdAt,
            resolvedAt=resolved_at,
            priority=active_detail.priority,
        )
    elif resolved_detail is not None:
        if resolved_detail.resolvedAt != resolved_at:
            raise RecoveryClosureError("incident was already resolved by a different event")
        active.discard(incident_urn)
        active_details.pop(incident_urn, None)
        resolved.add(incident_urn)
    else:
        raise RecoveryClosureError("incident is not present in active or resolved summary state")
    return IncidentsSummaryClass(
        resolvedIncidents=sorted(resolved),
        activeIncidents=sorted(active),
        resolvedIncidentDetails=[resolved_details[urn] for urn in sorted(resolved_details)],
        activeIncidentDetails=[active_details[urn] for urn in sorted(active_details)],
    )


def _summary_is_active(summary: Any, incident_urn: str) -> bool:
    return bool(
        summary is not None
        and incident_urn in (summary.activeIncidents or [])
        and incident_urn not in (summary.resolvedIncidents or [])
        and any(item.urn == incident_urn for item in (summary.activeIncidentDetails or []))
        and not any(item.urn == incident_urn for item in (summary.resolvedIncidentDetails or []))
    )


def _summary_is_resolved(summary: Any, incident_urn: str) -> bool:
    return bool(
        summary is not None
        and incident_urn not in (summary.activeIncidents or [])
        and any(
            item.urn == incident_urn and item.resolvedAt is not None
            for item in (summary.resolvedIncidentDetails or [])
        )
        and not any(item.urn == incident_urn for item in (summary.activeIncidentDetails or []))
    )


def _single_incident_entity(info: Any) -> str | None:
    entities = info.entities if info is not None else None
    return entities[0] if isinstance(entities, list) and len(entities) == 1 else None


def _timestamp_millis(value: str) -> int:
    from datetime import datetime

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RecoveryClosureError("closure timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RecoveryClosureError("closure timestamp must include an offset")
    return int(parsed.timestamp() * 1000)


def _closure_message(closure_id: str) -> str:
    return f"Recovered by verified GlassBox isolated replay: {closure_id}"


__all__ = [
    "DataHubRecoveryClosureBackend",
    "RecoveryClosureBackend",
    "RecoveryClosureEmitter",
    "RecoveryClosureError",
    "RecoveryClosurePrerequisites",
    "RecoveryClosureReadback",
    "RecoveryClosureReport",
    "merge_resolved_incident_summary",
]
