"""Read-only forensics service trust-boundary tests."""

from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey, seal_receipt
from glassbox_forensics import ForensicsInputError, ForensicsNotFoundError, ForensicsService
from glassbox_forensics.live_state import TransactionalCampaignReader
from glassbox_invalidation import SQLiteInvalidationStore, VerifiedReceiptStore
from glassbox_policy import (
    ChangeKind,
    InvalidationWriteEvidence,
    NormalizedChange,
    create_campaign,
)
from tests.helpers import receipt_payload

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},revenue)"


def _signed_receipt(*, secret: str | None = None) -> dict:
    payload = receipt_payload()
    payload["evidence"][0]["schema_field_urn"] = FIELD
    if secret is not None:
        payload["extensions"]["private_payload"] = secret
    key = SigningKey("forensics-test-key", Ed25519PrivateKey.generate())
    return seal_receipt(payload, signing_keys=[key])


def _service(tmp_path: Path, *receipts: dict) -> tuple[ForensicsService, VerifiedReceiptStore]:
    store = VerifiedReceiptStore(tmp_path / "receipts.jsonl", sync=False)
    for receipt in receipts:
        store.register(receipt)
    return ForensicsService(store, artifacts=store), store


def _change(*, field: str = FIELD) -> NormalizedChange:
    return NormalizedChange(
        event_id="mcl-schema-001",
        entity_urn=DATASET,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-07T00:00:00Z",
        schema_field_urn=field,
    )


def test_fresh_verification_and_influence_are_bounded_and_raw_free(tmp_path: Path) -> None:
    secret = "never-return-this-sensitive-extension"
    receipt = _signed_receipt(secret=secret)
    service, store = _service(tmp_path, receipt)
    receipt_id = receipt["receipt_id"]

    verification = service.verify_decision_receipt(receipt_id)
    influence = service.get_decision_influence(receipt_id)

    assert verification["verification_state"] == "VERIFIED_NOW"
    assert verification["valid"] is True
    assert influence["integrity"]["state"] == "VERIFIED_NOW"
    assert influence["completeness"]["dependency_resolution"] == "COMPLETE"
    assert influence["dependencies"][0]["schema_field_urn"] == FIELD
    assert influence["raw_content_returned"] is False
    assert secret not in repr(verification)
    assert secret not in repr(influence)

    stored = store.get_receipt(receipt_id)
    assert stored is not None
    stored["run"] = {}
    assert store.get_receipt(receipt_id)["run"]["run_id"] == "run-pricing-001"


def test_tampered_artifact_reports_failure_codes_without_schema_messages(tmp_path: Path) -> None:
    receipt = _signed_receipt(secret="do-not-echo")
    _, store = _service(tmp_path, receipt)
    tampered = copy.deepcopy(receipt)
    tampered["extensions"]["private_payload"] = "mutated-secret"

    class TamperedArtifacts:
        def get_receipt(self, receipt_id: str) -> dict | None:
            return tampered if receipt_id == receipt["receipt_id"] else None

    report = ForensicsService(store, artifacts=TamperedArtifacts()).verify_decision_receipt(
        receipt["receipt_id"]
    )

    assert report["verification_state"] == "FAILED"
    assert report["valid"] is False
    assert "PAYLOAD_DIGEST_INVALID" in report["failure_codes"]
    assert "mutated-secret" not in repr(report)


def test_impact_and_reverse_scan_use_canonical_policy_and_bounded_results(tmp_path: Path) -> None:
    first = _signed_receipt()
    second_payload = receipt_payload()
    second_payload["run"]["run_id"] = "run-pricing-002"
    second_payload["run"]["started_at"] = "2026-08-06T00:01:00Z"
    second_payload["run"]["ended_at"] = "2026-08-06T00:01:02Z"
    second_payload["evidence"][0]["evidence_id"] = "evidence-orders-002"
    second_payload["evidence"][0]["schema_field_urn"] = FIELD
    second = seal_receipt(
        second_payload,
        signing_keys=[SigningKey("second-key", Ed25519PrivateKey.generate())],
    )
    service, _ = _service(tmp_path, first, second)

    single = service.classify_decision_impact(first["receipt_id"], _change())
    reverse = service.list_affected_decisions(_change(), limit=1)

    assert single["assessment"]["state"] == "STALE"
    assert single["decision_authority"] == "DETERMINISTIC_POLICY"
    assert reverse["scan_complete"] is True
    assert reverse["profiles_scanned"] == 2
    assert reverse["state_counts"] == {"STALE": 2}
    assert reverse["review_required_total"] == 2
    assert reverse["returned"] == 1
    assert reverse["truncated"] is True
    assert len(reverse["assessments"]) == 1


def test_missing_receipt_and_invalid_public_inputs_fail_closed(tmp_path: Path) -> None:
    service, _ = _service(tmp_path)
    valid_missing = "gbx:receipt:sha256:" + "a" * 64

    with pytest.raises(ForensicsNotFoundError, match="configured evidence scope"):
        service.get_decision_influence(valid_missing)
    with pytest.raises(ForensicsInputError, match="content address"):
        service.verify_decision_receipt("../../receipt.json")
    with pytest.raises(ForensicsInputError, match="between 1 and 200"):
        service.list_affected_decisions(_change(), limit=0)


def test_live_campaign_findings_come_from_shared_transactional_state(tmp_path: Path) -> None:
    secret = "never-return-live-secret"
    receipt = _signed_receipt(secret=secret)
    store = SQLiteInvalidationStore(tmp_path / "live-state.sqlite3")
    store.register(receipt)
    campaign = create_campaign(_change(), store.all_profiles())
    store.stage_campaign(campaign)
    claimed = store.claim(
        campaign.campaign_id,
        worker_id="datahub-action",
        now_ms=1,
        lease_duration_ms=10_000,
    )
    assert claimed is not None
    store.complete(
        campaign,
        InvalidationWriteEvidence(
            incident_aspects=("incidentInfo", "incidentKey"),
            target_summary_verified=True,
            quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
        ),
        worker_id="datahub-action",
    )
    service = ForensicsService(
        store,
        artifacts=store,
        findings=TransactionalCampaignReader(store),
    )

    persisted = service.get_invalidation_campaign(campaign.campaign_id)
    findings = service.list_decision_findings(receipt["receipt_id"])

    assert persisted["availability"] == "AVAILABLE"
    assert persisted["campaign"]["processing"] == {
        "workflow_status": "COMPLETED",
        "attempt_count": 1,
        "datahub_writeback_state": "VERIFIED",
        "last_error_recorded": False,
    }
    assert persisted["campaign"]["assessments"][0]["state"] == "STALE"
    assert findings["scan_complete"] is True
    assert findings["campaigns_scanned"] == 1
    assert findings["findings_total"] == 1
    assert findings["findings"][0]["campaign_id"] == campaign.campaign_id
    assert findings["findings"][0]["assessment"]["state"] == "STALE"
    assert secret not in repr(persisted)
    assert secret not in repr(findings)


def test_campaign_tools_expose_unavailable_state_without_inventing_history(
    tmp_path: Path,
) -> None:
    receipt = _signed_receipt()
    service, _ = _service(tmp_path, receipt)
    campaign_id = "gbx:invalidation:sha256:" + "b" * 64

    campaign = service.get_invalidation_campaign(campaign_id)
    findings = service.list_decision_findings(receipt["receipt_id"])

    assert campaign["availability"] == "CAMPAIGN_STORE_NOT_CONFIGURED"
    assert findings["availability"] == "CAMPAIGN_STORE_NOT_CONFIGURED"
    assert findings["scan_complete"] is False
    with pytest.raises(ForensicsInputError, match="campaign_id"):
        service.get_invalidation_campaign("not-a-campaign")
