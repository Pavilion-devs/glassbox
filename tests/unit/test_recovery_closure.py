"""Verified isolated-recovery closure and DataHub resolution tests."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datahub.metadata.schema_classes import (
    IncidentsSummaryClass,
    IncidentSummaryDetailsClass,
)

from glassbox.redaction import digest_value
from glassbox_datahub import (
    RecoveryClosureEmitter,
    RecoveryClosureError,
    RecoveryClosurePrerequisites,
    RecoveryClosureReadback,
    merge_resolved_incident_summary,
    receipt_document_urn,
    supersession_document_urn,
)
from glassbox_dbom import SigningKey, seal_receipt, signing_key_fingerprint
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
from glassbox_replay import (
    ContainerCapabilityRunner,
    ContextReplacement,
    ReplayContextObservation,
    ReplayExecutionError,
    ReplayMode,
    build_replay_diff,
    build_replay_receipt,
    create_recovery_closure_record,
    create_supersession_record,
    issue_recovery_authorization,
)
from glassbox_replay.execution import _execution_id
from tests.helpers import receipt_payload
from tests.unit.test_replay_execution import _bundle, _execute
from tests.unit.test_replay_isolation import (
    FakeProcessRunner,
    _profile,
    _response,
)

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},average_order_value)"
EVALUATED_AT = "2026-08-08T12:05:00Z"
SUPERSESSION_AT = "2026-08-08T12:06:00Z"
CLOSED_AT = "2026-08-08T12:07:00Z"


def _source() -> tuple[dict[str, Any], object, object]:
    source_input = {"average_order_value": "44"}
    source_output = {"price": 40, "private": "source-only"}
    payload = receipt_payload()
    payload["evidence"][0]["schema_field_urn"] = FIELD
    payload["evidence"][0]["representation_digest"] = {
        "algorithm": "sha256",
        "value": digest_value(source_input),
    }
    payload["actions"][0]["input_digest"] = {
        "algorithm": "sha256",
        "value": digest_value(source_input),
    }
    payload["actions"][0]["output_digest"] = {
        "algorithm": "sha256",
        "value": digest_value(source_output),
    }
    payload["output"]["digest"] = {
        "algorithm": "sha256",
        "value": digest_value(source_output),
    }
    return (
        seal_receipt(
            payload,
            signing_keys=(SigningKey("closure-source", Ed25519PrivateKey.generate()),),
        ),
        source_input,
        source_output,
    )


def _task(source: dict[str, Any]) -> OutboxTask:
    profile = ReceiptDependencyProfile.from_receipt(
        source,
        field_lineage=FieldLineageProof(
            FieldCoverage.COMPLETE,
            "glassbox.closure-test.v1",
            False,
        ),
    )
    campaign = create_campaign(
        NormalizedChange(
            "mcl-closure-001",
            DATASET,
            "schemaMetadata",
            ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
            "2026-08-08T11:55:00Z",
            schema_field_urn=FIELD,
            before_digest=hashlib.sha256(b"varchar").hexdigest(),
            after_digest=hashlib.sha256(b"decimal").hexdigest(),
        ),
        (profile,),
    )
    return OutboxTask(
        campaign,
        OutboxStatus.COMPLETED,
        1,
        None,
        None,
        None,
        InvalidationWriteEvidence(
            ("incidentInfo", "incidentKey"),
            True,
            tuple(item.document_urn for item in campaign.quarantined),
        ),
    )


def _artifacts() -> tuple[Any, ...]:
    source, _source_input, source_output = _source()
    task = _task(source)
    corrected_input = {"average_order_value": 44.0}
    replay_input = {"recovery": "corrected"}
    evidence_id = source["evidence"][0]["evidence_id"]
    authority = "runtime-observation:orders-v2"
    bundle = _bundle(
        source,
        replay_input=replay_input,
        mode=ReplayMode.CORRECTED,
        replacements=(ContextReplacement(evidence_id, digest_value(corrected_input), authority),),
        replacement_action_input=corrected_input,
    )
    operator = SigningKey("closure-operator", Ed25519PrivateKey.generate())
    authorization = issue_recovery_authorization(
        task,
        source,
        bundle,
        issuer="urn:li:corpuser:closure-operator",
        issued_at="2026-08-08T12:00:00Z",
        expires_at="2026-08-08T13:00:00Z",
        signing_keys=(operator,),
    )
    tool = source["tools"][0]
    runner = ContainerCapabilityRunner(
        _profile(tool["source_digest"]["value"], tool["schema_digest"]["value"]),
        docker_executable="/usr/local/bin/docker",
        process_runner=FakeProcessRunner(
            _response(),
            capability_source_digest=tool["source_digest"]["value"],
            capability_schema_digest=tool["schema_digest"]["value"],
        ),
    )
    action_id = source["actions"][0]["action_id"]
    observation = ReplayContextObservation(
        evidence_id,
        digest_value(corrected_input),
        authority,
        "4444444444444444",
        "2026-08-08T12:05:01Z",
        "TOOL_RESULT",
    )
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=corrected_input,
        handler=runner,
        projector=lambda _input, outputs: outputs[action_id],
        observations=(observation,),
    )
    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("closure-replay", Ed25519PrivateKey.generate()),),
    )
    diff = build_replay_diff(
        source,
        replay_receipt,
        source_output=source_output,
        replay_output=execution.output,
    )
    supersession = create_supersession_record(
        source,
        replay_receipt,
        execution=execution,
        plan=plan,
        diff=diff,
        created_at=SUPERSESSION_AT,
    )
    trusted = {operator.key_id: signing_key_fingerprint(operator)}
    closure = create_recovery_closure_record(
        authorization,
        task,
        source,
        replay_receipt,
        bundle,
        execution=execution,
        supersession=supersession,
        evaluated_at=EVALUATED_AT,
        trusted_signer_fingerprints=trusted,
        closed_at=CLOSED_AT,
    )
    return (
        source,
        task,
        bundle,
        authorization,
        trusted,
        execution,
        replay_receipt,
        supersession,
        closure,
    )


class FakeClosureBackend:
    def __init__(
        self,
        record: Any,
        *,
        prerequisite_valid: bool = True,
        changed_receipt: bool = False,
        readback_valid: bool = True,
        wrong_second_urn: bool = False,
        already_closed: bool = False,
    ) -> None:
        self.record = record
        self.prerequisite_valid = prerequisite_valid
        self.changed_receipt = changed_receipt
        self.readback_valid = readback_valid
        self.wrong_second_urn = wrong_second_urn
        self.already_closed = already_closed
        self.calls = 0
        self.digests = (
            (receipt_document_urn(record.source_receipt_id), "a" * 64),
            (receipt_document_urn(record.replay_receipt_id), "b" * 64),
        )

    def verify_closure_prerequisites(self, record: Any, supersession: Any) -> Any:
        del record, supersession
        return RecoveryClosurePrerequisites(
            incident_active=self.prerequisite_valid and not self.already_closed,
            target_summary_active=self.prerequisite_valid and not self.already_closed,
            supersession_verified=self.prerequisite_valid,
            supersession_aspects=("documentInfo",),
            source_receipt_verified=self.prerequisite_valid,
            source_receipt_aspects=("documentInfo",),
            replay_receipt_verified=self.prerequisite_valid,
            replay_receipt_aspects=("documentInfo",),
            receipt_entity_digests=self.digests,
            incident_already_closed_by_record=self.already_closed,
            target_summary_resolved=self.already_closed,
        )

    def upsert_recovery_closure(self, record: Any) -> str:
        self.calls += 1
        if self.wrong_second_urn and self.calls == 2:
            return record.incident_urn + ".wrong"
        return record.incident_urn

    def direct_read_recovery_closure(self, record: Any, supersession: Any) -> Any:
        del supersession
        digests = self.digests
        if self.changed_receipt:
            digests = (digests[0], (digests[1][0], "c" * 64))
        return RecoveryClosureReadback(
            incident_state="RESOLVED" if self.readback_valid else "ACTIVE",
            incident_stage="FIXED" if self.readback_valid else "TRIAGE",
            closure_id_verified=self.readback_valid,
            target_summary_resolved=self.readback_valid,
            supersession_verified=self.readback_valid,
            incident_aspects=("incidentInfo", "incidentKey"),
            receipt_entity_digests=digests,
        )


def test_recovery_closure_rechecks_full_chain_and_emits_idempotently() -> None:
    *_, supersession, closure = _artifacts()
    second = copy.deepcopy(closure)
    assert closure == second and closure.valid
    assert closure.resolution == "RECOVERED_BY_VERIFIED_ISOLATED_REPLAY"
    assert len(closure.isolation_attestation_ids) == 1
    assert json.dumps(closure.to_dict()).find("transient-output") == -1

    backend = FakeClosureBackend(closure)
    report = RecoveryClosureEmitter(backend).close_verified(closure, supersession)
    assert report.valid and backend.calls == 2
    assert report.target_summary_resolved
    assert report.receipt_documents_unchanged
    assert report.supersession_document_urn == supersession_document_urn(
        supersession.supersession_id
    )


def test_recovery_closure_recovers_exact_prior_resolution_without_another_write() -> None:
    *_, supersession, closure = _artifacts()
    backend = FakeClosureBackend(closure, already_closed=True)

    report = RecoveryClosureEmitter(backend).close_verified(closure, supersession)

    assert report.valid and report.reused_completion
    assert report.emission_attempts == 0 and report.aspect_writes == 0
    assert backend.calls == 0


def test_recovery_closure_fails_closed_on_drift_or_unisolated_execution() -> None:
    (
        source,
        task,
        bundle,
        authorization,
        trusted,
        execution,
        replay_receipt,
        supersession,
        closure,
    ) = _artifacts()
    unisolated = replace(
        execution,
        actions=tuple(replace(action, isolation_attestation=None) for action in execution.actions),
    )
    unisolated = replace(unisolated, execution_id=_execution_id(unisolated._material()))
    assert unisolated.valid
    with pytest.raises(ReplayExecutionError, match="isolated"):
        create_recovery_closure_record(
            authorization,
            task,
            source,
            replay_receipt,
            bundle,
            execution=unisolated,
            supersession=supersession,
            evaluated_at=EVALUATED_AT,
            trusted_signer_fingerprints=trusted,
            closed_at=CLOSED_AT,
        )
    with pytest.raises(RecoveryClosureError, match="content address"):
        RecoveryClosureEmitter(FakeClosureBackend(closure)).close_verified(
            replace(closure, closure_id="gbx:recovery-closure:sha256:" + "0" * 64),
            supersession,
        )
    for backend, message in (
        (FakeClosureBackend(closure, prerequisite_valid=False), "prerequisites"),
        (FakeClosureBackend(closure, wrong_second_urn=True), "idempotent"),
        (FakeClosureBackend(closure, readback_valid=False), "readback"),
        (FakeClosureBackend(closure, changed_receipt=True), "receipt Documents"),
    ):
        with pytest.raises(RecoveryClosureError, match=message):
            RecoveryClosureEmitter(backend).close_verified(closure, supersession)


def test_summary_resolution_is_idempotent_and_preserves_unrelated_incidents() -> None:
    target = "urn:li:incident:glassbox-target"
    other_active = "urn:li:incident:other-active"
    other_resolved = "urn:li:incident:other-resolved"
    current = IncidentsSummaryClass(
        activeIncidents=[other_active, target],
        resolvedIncidents=[other_resolved],
        activeIncidentDetails=[
            IncidentSummaryDetailsClass(other_active, "CUSTOM", 1, priority=3),
            IncidentSummaryDetailsClass(target, "CUSTOM", 2, priority=1),
        ],
        resolvedIncidentDetails=[
            IncidentSummaryDetailsClass(other_resolved, "CUSTOM", 3, 4, 2),
        ],
    )
    resolved = merge_resolved_incident_summary(current, incident_urn=target, resolved_at=5)
    assert resolved.activeIncidents == [other_active]
    assert resolved.resolvedIncidents == sorted([other_resolved, target])
    assert [item.urn for item in resolved.activeIncidentDetails] == [other_active]
    assert {item.urn for item in resolved.resolvedIncidentDetails} == {
        other_resolved,
        target,
    }
    target_detail = next(item for item in resolved.resolvedIncidentDetails if item.urn == target)
    assert target_detail.createdAt == 2 and target_detail.resolvedAt == 5
    assert merge_resolved_incident_summary(resolved, incident_urn=target, resolved_at=5) == resolved
    rich_details_only = IncidentsSummaryClass(
        activeIncidents=[other_active],
        resolvedIncidents=[],
        activeIncidentDetails=resolved.activeIncidentDetails,
        resolvedIncidentDetails=resolved.resolvedIncidentDetails,
    )
    restored = merge_resolved_incident_summary(
        rich_details_only,
        incident_urn=target,
        resolved_at=5,
    )
    assert target in restored.resolvedIncidents
    with pytest.raises(RecoveryClosureError, match="different event"):
        merge_resolved_incident_summary(resolved, incident_urn=target, resolved_at=6)
