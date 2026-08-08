"""Offline contracts for the live durable flagship and abrupt-worker harness."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import NoReturn

import pytest
from examples.end_to_end_durable_recovery import (
    ABRUPT_CHECKPOINT_EXIT_CODE,
    ABRUPT_PRECOMMIT_EXIT_CODE,
    FAULT_REPORT_PREFIX,
    REPLAY_SIGNING_KEY_ENV,
    WORKER_REPORT_PREFIX,
    CrashBeforePostgresCompletionStore,
    FlagshipRecoveryExecutor,
    LiveProofTimeline,
    _build_corrected_handoff,
    _parse_fault_report,
    _parse_worker_report,
    _private_key_base64url,
    _worker_environment,
)
from examples.end_to_end_invalidation import FIELD_URN
from examples.end_to_end_receipt import build_signed_receipt, demo_signing_key

from glassbox_dbom import signing_key_fingerprint, signing_key_from_base64url
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
    RecoveryEffectEvidence,
    RecoveryJob,
    RecoveryOperation,
    RecoveryStage,
    recovery_workflow_id,
)
from tests.unit.test_replay_isolation import FakeProcessRunner, _response


def _authorized_job() -> tuple[dict[str, object], OutboxTask, dict[str, str], RecoveryJob]:
    signing_key = demo_signing_key()
    source = build_signed_receipt(
        schema_field_urn=FIELD_URN,
        signing_key=signing_key,
        replay_ready=True,
    )
    profile = ReceiptDependencyProfile.from_receipt(
        source,
        field_lineage=FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.durable-flagship-test.v1",
            wildcard_query=False,
        ),
    )
    campaign = create_campaign(
        NormalizedChange(
            event_id="durable-flagship-material-change",
            entity_urn="urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)",
            aspect_name="schemaMetadata",
            kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
            occurred_at="2026-08-08T01:00:00Z",
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
    authorization, bundle, verification, trusted = _build_corrected_handoff(
        source,
        task,
        timeline=LiveProofTimeline(
            issued_at="2026-08-08T01:10:00Z",
            expires_at="2026-08-08T02:10:00Z",
            evaluated_at="2026-08-08T01:20:00Z",
        ),
    )
    assert verification.valid
    job = RecoveryJob(
        workflow_id=recovery_workflow_id(authorization),
        authorization=authorization,
        bundle=bundle,
        stage=RecoveryStage.AUTHORIZED,
        stage_version=0,
        attempt_count=1,
        lease_operation=None,
        lease_owner=None,
        lease_expires_at_ms=None,
        last_error_type=None,
        artifacts=None,
        replay_publication=None,
        supersession_publication=None,
        incident_closure=None,
    )
    assert job.valid
    return source, task, trusted, job


def test_flagship_executor_consumes_the_persisted_authorization_and_bundle() -> None:
    source, task, trusted, job = _authorized_job()
    signing_key = demo_signing_key()
    tools = source["tools"]
    assert isinstance(tools, list) and isinstance(tools[0], dict)
    artifacts = FlagshipRecoveryExecutor(
        signing_key=signing_key,
        sandbox_image_digest="sha256:" + "a" * 64,
        trusted_signer_fingerprints=trusted,
        process_runner=FakeProcessRunner(
            _response(),
            capability_source_digest=tools[0]["source_digest"]["value"],
            capability_schema_digest=tools[0]["schema_digest"]["value"],
        ),
        docker_executable="/usr/local/bin/docker",
    ).execute(job, task, source)

    assert artifacts.valid
    assert artifacts.closure.authorization_id == job.authorization.authorization_id
    assert artifacts.closure.campaign_id == task.campaign.campaign_id
    assert artifacts.closure.bundle_id == job.bundle_id
    serialized = json.dumps(artifacts.to_dict())
    assert "synthetic-live-customer" not in serialized
    assert '"average_order_value": 62' not in serialized


def test_worker_report_requires_an_abrupt_unique_process_and_exact_stage() -> None:
    payload = {
        "valid": True,
        "pid": 12345,
        "abrupt_exit_injected": True,
        "step": {
            "stage": RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED.value,
            "reused_completion": False,
        },
        "raw_content_returned": False,
    }
    completed = subprocess.CompletedProcess(
        args=("python",),
        returncode=ABRUPT_CHECKPOINT_EXIT_CODE,
        stdout=WORKER_REPORT_PREFIX + json.dumps(payload) + "\n",
        stderr="",
    )
    seen: set[int] = set()
    report = _parse_worker_report(
        completed,
        expected_stage=RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
        seen_pids=seen,
        expect_reused=False,
    )
    assert report == payload
    assert seen == {12345}

    with pytest.raises(RuntimeError, match="stage or identity"):
        _parse_worker_report(
            completed,
            expected_stage=RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
            seen_pids=seen,
            expect_reused=False,
        )


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    (
        (0, ""),
        (ABRUPT_CHECKPOINT_EXIT_CODE, ""),
        (ABRUPT_CHECKPOINT_EXIT_CODE, WORKER_REPORT_PREFIX + "[]\n"),
    ),
)
def test_worker_report_rejects_normal_exit_and_malformed_evidence(
    returncode: int,
    stdout: str,
) -> None:
    completed = subprocess.CompletedProcess(
        args=("python",),
        returncode=returncode,
        stdout=stdout,
        stderr="private transport failure",
    )
    with pytest.raises(RuntimeError):
        _parse_worker_report(
            completed,
            expected_stage=RecoveryStage.INCIDENT_CLOSED,
            seen_pids=set(),
            expect_reused=True,
        )


def test_precommit_fault_store_reports_success_without_completing_postgres(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _source, task, _trusted, authorized = _authorized_job()
    claimed = replace(
        authorized,
        lease_operation=RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
        lease_owner="fault-worker",
        lease_expires_at_ms=123456,
    )

    class FakeState:
        def get(self, campaign_id: str) -> RecoveryJob:
            assert campaign_id == task.campaign.campaign_id
            return claimed

        def read_events(self, campaign_id: str) -> tuple[str]:
            assert campaign_id == task.campaign.campaign_id
            return ("authorized",)

    class InjectedExitError(RuntimeError):
        def __init__(self, code: int) -> None:
            self.code = code

    def exit_process(code: int) -> NoReturn:
        raise InjectedExitError(code)

    evidence = RecoveryEffectEvidence.create(
        operation=RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
        campaign_id=task.campaign.campaign_id,
        artifact_id="gbx:receipt:sha256:" + "a" * 64,
        target_id="urn:li:document:replay",
        aspect_names=("documentInfo",),
        emission_count=2,
        write_performed=True,
        readback_verified=True,
        recorded_at="2026-08-08T01:30:00Z",
    )
    state = CrashBeforePostgresCompletionStore(  # type: ignore[arg-type]
        FakeState(),
        exit_process=exit_process,
    )
    with pytest.raises(InjectedExitError) as raised:
        state.complete_effect(
            task.campaign.campaign_id,
            evidence,
            worker_id="fault-worker",
        )

    assert raised.value.code == ABRUPT_PRECOMMIT_EXIT_CODE
    line = capsys.readouterr().out.strip()
    assert line.startswith(FAULT_REPORT_PREFIX)
    report = json.loads(line.removeprefix(FAULT_REPORT_PREFIX))
    assert report["operation"] == RecoveryOperation.PUBLISH_REPLAY_RECEIPT.value
    assert report["postgres_completion_called"] is False
    assert report["durable_event_count_before"] == 1
    assert report["write_performed"] is True
    assert report["readback_verified"] is True
    assert report["raw_content_returned"] is False


def test_precommit_fault_report_requires_exact_stage_operation_and_unique_pid() -> None:
    payload = {
        "contract": "glassbox.recovery-precommit-fault.v1",
        "valid": True,
        "pid": 54321,
        "fault_point": "AFTER_SUCCESS_BEFORE_POSTGRES_COMPLETION",
        "operation": RecoveryOperation.PUBLISH_SUPERSESSION.value,
        "durable_stage_before": RecoveryStage.REPLAY_RECEIPT_PUBLISHED.value,
        "lease_operation": RecoveryOperation.PUBLISH_SUPERSESSION.value,
        "readback_verified": True,
        "postgres_completion_called": False,
        "raw_content_returned": False,
    }
    completed = subprocess.CompletedProcess(
        args=("python",),
        returncode=ABRUPT_PRECOMMIT_EXIT_CODE,
        stdout=FAULT_REPORT_PREFIX + json.dumps(payload) + "\n",
        stderr="",
    )
    seen: set[int] = set()
    report = _parse_fault_report(
        completed,
        expected_stage=RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
        expected_operation=RecoveryOperation.PUBLISH_SUPERSESSION,
        seen_pids=seen,
    )
    assert report == payload
    assert seen == {54321}

    with pytest.raises(RuntimeError, match="boundary verification"):
        _parse_fault_report(
            completed,
            expected_stage=RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
            expected_operation=RecoveryOperation.PUBLISH_SUPERSESSION,
            seen_pids=seen,
        )


def test_worker_environment_is_minimal_and_signing_key_round_trips(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signing_key = demo_signing_key()
    monkeypatch.setenv("GLASSBOX_UNRELATED_SECRET", "must-not-cross-worker-boundary")
    environment = _worker_environment(
        dsn_environment="GLASSBOX_TEST_DSN",
        dsn="postgresql://bounded-placeholder",
        token_environment="GLASSBOX_TEST_TOKEN",
        token="bounded-token",
        signing_key=signing_key,
    )

    assert "GLASSBOX_UNRELATED_SECRET" not in environment
    assert environment["GLASSBOX_TEST_DSN"] == "postgresql://bounded-placeholder"
    assert environment["GLASSBOX_TEST_TOKEN"] == "bounded-token"
    encoded = environment[REPLAY_SIGNING_KEY_ENV]
    assert encoded == _private_key_base64url(signing_key)
    restored = signing_key_from_base64url(signing_key.key_id, encoded)
    assert signing_key_fingerprint(restored) == signing_key_fingerprint(signing_key)


def test_committed_live_report_preserves_the_measured_crash_boundary() -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "compatibility"
        / "datahub-1.6.0-durable-recovery-crash.live.json"
    )
    encoded = path.read_text(encoding="utf-8")
    report = json.loads(encoded)

    assert report["contract"] == "glassbox.durable-causal-recovery-crash.v1"
    assert report["valid"] is True
    assert report["raw_content_returned"] is False
    assert report["runtime"]["worker_processes"] == 5
    assert report["runtime"]["distinct_worker_pids"] == 5
    assert report["integrity"] == {
        "active_workflows": 0,
        "closed_workflows": 1,
        "events": 5,
        "workflows": 1,
    }
    workers = report["recovery"]["workers"]
    assert len({item["pid"] for item in workers}) == 5
    assert all(item["abrupt_exit_injected"] for item in workers)
    assert [item["step"]["stage"] for item in workers] == [
        "ISOLATED_EXECUTION_SUCCEEDED",
        "REPLAY_RECEIPT_PUBLISHED",
        "SUPERSESSION_VERIFIED",
        "INCIDENT_CLOSED",
        "INCIDENT_CLOSED",
    ]
    assert workers[-1]["step"]["reused_completion"] is True
    assert report["history_preservation"]["postgres_source_receipt_unchanged"] is True
    assert report["history_preservation"]["datahub_receipt_documents_unchanged"] is True
    assert report["scope"]["fresh_process_after_each_checkpoint"] == "PROVEN"
    assert report["scope"]["crash_before_checkpoint_commit"] == "NOT_EXERCISED"
    assert "postgresql://" not in encoded
    assert "synthetic-live-customer" not in encoded
    assert '"average_order_value": 62' not in encoded


def test_uncertain_completion_live_report_preserves_the_measured_crash_boundary() -> None:
    path = (
        Path(__file__).resolve().parents[2]
        / "docs"
        / "compatibility"
        / "datahub-1.6.0-durable-recovery-uncertain-crash.live.json"
    )
    encoded = path.read_text(encoding="utf-8")
    report = json.loads(encoded)

    assert report["contract"] == "glassbox.durable-uncertain-completion-crash.v1"
    assert report["valid"] is True
    assert report["runtime"]["worker_processes"] == 9
    assert report["runtime"]["distinct_worker_pids"] == 9
    assert report["recovery"]["attempt_count"] == 8
    assert report["integrity"]["events"] == 5

    faults = report["recovery"]["precommit_faults"]
    assert [item["operation"] for item in faults] == [
        "EXECUTE_ISOLATED_REPLAY",
        "PUBLISH_REPLAY_RECEIPT",
        "PUBLISH_SUPERSESSION",
        "CLOSE_INCIDENT",
    ]
    assert [item["attempt_count"] for item in faults] == [1, 3, 5, 7]
    assert [item["write_performed"] for item in faults] == [None, True, True, True]
    assert all(item["postgres_completion_called"] is False for item in faults)

    retries = report["recovery"]["retry_effect_evidence"]
    assert retries["replay_receipt"]["write_performed"] is False
    assert retries["supersession"]["write_performed"] is True
    assert retries["incident_closure"]["write_performed"] is False
    assert report["recovery"]["closed_redelivery_reused_completion"] is True
    assert report["scope"]["crash_after_oci_before_artifact_commit"] == "PROVEN"
    assert report["scope"]["crash_after_datahub_before_stage_commit"] == "PROVEN"
    assert report["scope"]["physical_multi_host_failover"] == "NOT_EXERCISED"
    assert "postgresql://" not in encoded
    assert "synthetic-live-customer" not in encoded
    assert '"average_order_value": 62' not in encoded
