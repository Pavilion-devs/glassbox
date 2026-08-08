"""Offline contract proof for the causal half of the live flagship scenario."""

from __future__ import annotations

import copy
import json

from examples.end_to_end_flagship import _replay_artifacts
from examples.end_to_end_invalidation import FIELD_URN
from examples.end_to_end_receipt import build_signed_receipt, demo_signing_key

from glassbox_dbom import verify_receipt
from glassbox_invalidation import OutboxStatus, OutboxTask
from glassbox_policy import (
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    InvalidationWriteEvidence,
    NormalizedChange,
    ReceiptDependencyProfile,
    create_campaign,
)
from tests.unit.test_replay_isolation import FakeProcessRunner, _response


def test_flagship_replay_uses_same_stale_receipt_and_real_corrected_action_input() -> None:
    signing_key = demo_signing_key()
    source = build_signed_receipt(
        schema_field_urn=FIELD_URN,
        signing_key=signing_key,
        replay_ready=True,
    )
    source_before = copy.deepcopy(source)
    profile = ReceiptDependencyProfile.from_receipt(
        source,
        field_lineage=FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.flagship-offline-test.v1",
            wildcard_query=False,
        ),
    )
    campaign = create_campaign(
        NormalizedChange(
            event_id="flagship-material-change",
            entity_urn="urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)",
            aspect_name="schemaMetadata",
            kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
            occurred_at="2026-08-07T12:00:00Z",
            schema_field_urn=FIELD_URN,
        ),
        (profile,),
    )
    task = OutboxTask(
        campaign=campaign,
        status=OutboxStatus.COMPLETED,
        attempt_count=1,
        lease_owner=None,
        lease_expires_at_ms=None,
        last_error_type=None,
        write_evidence=InvalidationWriteEvidence(
            incident_aspects=("incidentInfo", "incidentKey"),
            target_summary_verified=True,
            quarantined_documents=tuple(
                assessment.document_urn for assessment in campaign.quarantined
            ),
        ),
    )

    (
        authorization,
        authorization_verification,
        bundle,
        plan,
        execution,
        replay_receipt,
        diff,
        supersession,
        closure,
    ) = _replay_artifacts(
        source,
        task,
        signing_key=signing_key,
        sandbox_image_digest="sha256:" + "a" * 64,
        process_runner=FakeProcessRunner(
            _response(),
            capability_source_digest=source["tools"][0]["source_digest"]["value"],
            capability_schema_digest=source["tools"][0]["schema_digest"]["value"],
        ),
        docker_executable="/usr/local/bin/docker",
    )

    assert source == source_before
    assert authorization_verification.valid and authorization.valid
    assert authorization.source_receipt_id == source["receipt_id"]
    assert authorization.campaign_id == campaign.campaign_id
    assert bundle["source"]["receipt_id"] == source["receipt_id"]
    assert plan.execution_permitted and execution.valid
    assert execution.source_receipt_id == source["receipt_id"]
    assert execution.source_history_mutations == 0
    assert verify_receipt(replay_receipt, require_signature=True).valid
    assert replay_receipt["receipt_id"] != source["receipt_id"]
    assert replay_receipt["actions"][0]["input_digest"] != source["actions"][0]["input_digest"]
    assert diff.valid and diff.semantic.result == "CHANGED"
    assert supersession.valid
    assert supersession.source_receipt_id == source["receipt_id"]
    assert supersession.replay_receipt_id == replay_receipt["receipt_id"]
    assert closure.valid
    assert closure.incident_urn == campaign.incident_urn
    assert closure.isolation_attestation_ids == (
        execution.actions[0].isolation_attestation.attestation_id,
    )
    serialized = json.dumps(
        {
            "authorization": authorization_verification.to_dict(),
            "execution": execution.to_dict(),
            "diff": diff.to_dict(),
            "supersession": supersession.to_dict(),
            "closure": closure.to_dict(),
        }
    )
    assert "synthetic-live-customer" not in serialized
    assert '"average_order_value": 62' not in serialized
