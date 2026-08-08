"""Invalidation action, append-only audit, and summary merge tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from datahub.metadata.schema_classes import (
    IncidentsSummaryClass,
    IncidentSummaryDetailsClass,
)

from glassbox_datahub import DataHubInvalidationError, merge_active_incident_summary
from glassbox_datahub import invalidation as invalidation_module
from glassbox_invalidation import (
    AppendOnlyCampaignAuditLog,
    AuditLogError,
    AuditPhase,
    InvalidationAction,
    InvalidationActionError,
)
from glassbox_policy import (
    ChangeKind,
    EvidenceDependency,
    EvidenceRole,
    EvidenceState,
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    ReceiptDependencyProfile,
    create_campaign,
)

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
OTHER_DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.customers,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},revenue)"


def _profile(*, entity_urn: str = DATASET) -> ReceiptDependencyProfile:
    receipt_digest = "a" * 64
    return ReceiptDependencyProfile(
        receipt_id=f"gbx:receipt:sha256:{receipt_digest}",
        document_urn=f"urn:li:document:glassbox.receipt.{receipt_digest}",
        ended_at="2026-08-06T00:00:02Z",
        dependencies=(
            EvidenceDependency(
                evidence_id="evidence-orders-001",
                datahub_urn=entity_urn,
                schema_field_urn=FIELD if entity_urn == DATASET else None,
                state=EvidenceState.OBSERVED,
                role=EvidenceRole.INPUT,
                observed_at="2026-08-06T00:00:01Z",
                representation_digest="b" * 64,
            ),
        ),
    )


def _change(*, entity_urn: str = DATASET) -> NormalizedChange:
    field = FIELD if entity_urn == DATASET else f"urn:li:schemaField:({entity_urn},id)"
    return NormalizedChange(
        event_id="mcl-orders-schema-0001",
        entity_urn=entity_urn,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-07T00:00:00Z",
        schema_field_urn=field,
    )


class FakeBackend:
    def __init__(
        self,
        *,
        invalid_readback: bool = False,
        mismatched_readback: bool = False,
        fail_write: bool = False,
    ) -> None:
        self.invalid_readback = invalid_readback
        self.mismatched_readback = mismatched_readback
        self.fail_write = fail_write
        self.upserts: list[InvalidationCampaign] = []

    def upsert_campaign(self, campaign: InvalidationCampaign) -> None:
        if self.fail_write:
            raise ConnectionError("synthetic failure with possibly sensitive details")
        self.upserts.append(campaign)

    def direct_verify(self, campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
        if self.invalid_readback:
            return InvalidationWriteEvidence((), False, ())
        if self.mismatched_readback:
            return InvalidationWriteEvidence(
                ("incidentInfo", "incidentKey"), True, ("urn:li:document:other",)
            )
        return InvalidationWriteEvidence(
            incident_aspects=("incidentInfo", "incidentKey"),
            target_summary_verified=True,
            quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
        )


class DeduplicatingRouter:
    def __init__(self) -> None:
        self.keys: set[str] = set()

    def route(self, campaign: InvalidationCampaign, *, idempotency_key: str) -> tuple[str, ...]:
        del campaign
        self.keys.add(idempotency_key)
        return ("owner:commerce",)


def test_action_writes_twice_verifies_audits_and_routes_idempotently(tmp_path: Path) -> None:
    backend = FakeBackend()
    router = DeduplicatingRouter()
    audit = AppendOnlyCampaignAuditLog(tmp_path / "campaigns.jsonl", sync=False)
    action = InvalidationAction(backend, audit, owner_router=router)

    first = action.process(_change(), (_profile(),))
    second = action.process(_change(), (_profile(),))

    assert first == second
    assert first.valid
    assert first.emissions == 2
    assert len(backend.upserts) == 4
    assert len({item.campaign_id for item in backend.upserts}) == 1
    assert router.keys == {first.campaign.campaign_id}
    records = audit.read_records()
    assert [item.phase for item in records] == [
        AuditPhase.CLASSIFIED,
        AuditPhase.DATAHUB_VERIFIED,
    ]
    assert records[0].impact_counts == (("STALE", 1),)


def test_positively_unaffected_campaign_is_audited_without_mutation(tmp_path: Path) -> None:
    backend = FakeBackend()
    audit = AppendOnlyCampaignAuditLog(tmp_path / "campaigns.jsonl", sync=False)
    action = InvalidationAction(backend, audit)

    report = action.process(_change(entity_urn=OTHER_DATASET), (_profile(),))

    assert report.no_op
    assert report.valid
    assert backend.upserts == []
    assert [item.phase for item in audit.read_records()] == [AuditPhase.CLASSIFIED]


@pytest.mark.parametrize(
    ("backend", "expected_message"),
    [
        (FakeBackend(invalid_readback=True), "direct verification"),
        (FakeBackend(mismatched_readback=True), "readback did not match"),
        (FakeBackend(fail_write=True), "campaign writeback failed"),
    ],
)
def test_write_failure_is_bounded_audited_and_never_routed(
    tmp_path: Path,
    backend: FakeBackend,
    expected_message: str,
) -> None:
    router = DeduplicatingRouter()
    audit = AppendOnlyCampaignAuditLog(tmp_path / "campaigns.jsonl", sync=False)

    with pytest.raises(InvalidationActionError, match=expected_message):
        InvalidationAction(backend, audit, owner_router=router).process(_change(), (_profile(),))

    records = audit.read_records()
    assert [item.phase for item in records] == [AuditPhase.CLASSIFIED, AuditPhase.DATAHUB_FAILED]
    assert "sensitive" not in records[-1].detail
    assert router.keys == set()


def test_audit_log_detects_truncation_tampering_and_duplicate_records(tmp_path: Path) -> None:
    path = tmp_path / "campaigns.jsonl"
    audit = AppendOnlyCampaignAuditLog(path, sync=False)
    action = InvalidationAction(FakeBackend(), audit)
    action.process(_change(), (_profile(),))
    original = path.read_bytes()

    path.write_bytes(original[:-1])
    with pytest.raises(AuditLogError, match="truncated"):
        AppendOnlyCampaignAuditLog(path, sync=False)

    path.write_bytes(original.replace(b"policy-complete", b"policy-tampered", 1))
    with pytest.raises(AuditLogError, match="checksum"):
        AppendOnlyCampaignAuditLog(path, sync=False)

    first_line = original.splitlines(keepends=True)[0]
    path.write_bytes(first_line + first_line)
    with pytest.raises(AuditLogError, match="duplicates"):
        AppendOnlyCampaignAuditLog(path, sync=False)


def test_summary_merge_preserves_unrelated_incidents_and_is_idempotent() -> None:
    existing_active = "urn:li:incident:existing.active"
    existing_resolved = "urn:li:incident:existing.resolved"
    campaign_incident = "urn:li:incident:glassbox.invalidation." + "c" * 64
    current = IncidentsSummaryClass(
        activeIncidents=[existing_active],
        resolvedIncidents=[existing_resolved],
        activeIncidentDetails=[
            IncidentSummaryDetailsClass(
                urn=existing_active,
                type="OPERATIONAL",
                createdAt=1,
                priority=3,
            )
        ],
        resolvedIncidentDetails=[
            IncidentSummaryDetailsClass(
                urn=existing_resolved,
                type="FIELD",
                createdAt=2,
                resolvedAt=3,
                priority=2,
            )
        ],
    )

    first = merge_active_incident_summary(
        current,
        incident_urn=campaign_incident,
        created_at=1786060800000,
        priority=1,
    )
    second = merge_active_incident_summary(
        first,
        incident_urn=campaign_incident,
        created_at=1786060800000,
        priority=1,
    )

    assert first.to_obj() == second.to_obj()
    assert first.activeIncidents == sorted([existing_active, campaign_incident])
    assert first.resolvedIncidents == [existing_resolved]
    assert [item.urn for item in first.activeIncidentDetails] == sorted(
        [existing_active, campaign_incident]
    )


def test_summary_merge_never_silently_reactivates_a_resolved_incident() -> None:
    incident = "urn:li:incident:glassbox.invalidation." + "d" * 64
    current = IncidentsSummaryClass(resolvedIncidents=[incident])

    with pytest.raises(DataHubInvalidationError, match="refusing to reactivate"):
        merge_active_incident_summary(
            current,
            incident_urn=incident,
            created_at=1786060800000,
            priority=1,
        )


def test_incident_helpers_are_deterministic_bounded_and_fail_closed() -> None:
    stale = create_campaign(_change(), (_profile(),))
    declared_dependency = EvidenceDependency(
        evidence_id="evidence-orders-001",
        datahub_urn=DATASET,
        schema_field_urn=FIELD,
        state=EvidenceState.DECLARED,
        role=EvidenceRole.INPUT,
        observed_at="2026-08-06T00:00:01Z",
        representation_digest="b" * 64,
    )
    at_risk = create_campaign(
        _change(),
        (
            ReceiptDependencyProfile(
                receipt_id="gbx:receipt:sha256:" + "c" * 64,
                document_urn="urn:li:document:glassbox.receipt." + "c" * 64,
                ended_at="2026-08-06T00:00:02Z",
                dependencies=(declared_dependency,),
            ),
        ),
    )

    assert invalidation_module._incident_priority(stale) == 1
    assert invalidation_module._incident_priority(at_risk) == 2
    assert invalidation_module._incident_id(stale.incident_urn) == stale.incident_urn.removeprefix(
        "urn:li:incident:"
    )
    assert invalidation_module._timestamp_millis("2026-08-07T00:00:00Z") == 1786060800000
    description = invalidation_module._incident_description(stale)
    assert stale.campaign_id in description
    assert "STALE=1" in description
    assert "raw evidence" in description.lower()

    with pytest.raises(DataHubInvalidationError, match="invalid entity type"):
        invalidation_module._incident_id("urn:li:dataset:wrong")
    with pytest.raises(DataHubInvalidationError, match="empty ID"):
        invalidation_module._incident_id("urn:li:incident:")
    with pytest.raises(DataHubInvalidationError, match="include an offset"):
        invalidation_module._timestamp_millis("2026-08-07T00:00:00")


def test_summary_helper_requires_both_deprecated_and_detailed_inverse_links() -> None:
    incident = "urn:li:incident:glassbox.invalidation." + "e" * 64
    detail = IncidentSummaryDetailsClass(
        urn=incident,
        type="CUSTOM",
        createdAt=1786060800000,
        priority=1,
    )

    assert invalidation_module._summary_contains(
        IncidentsSummaryClass(activeIncidents=[incident], activeIncidentDetails=[detail]),
        incident,
    )
    assert not invalidation_module._summary_contains(
        IncidentsSummaryClass(activeIncidents=[incident], activeIncidentDetails=[]),
        incident,
    )
    with pytest.raises(DataHubInvalidationError, match="resolved detail state"):
        merge_active_incident_summary(
            IncidentsSummaryClass(resolvedIncidentDetails=[detail]),
            incident_urn=incident,
            created_at=1786060800000,
            priority=1,
        )
