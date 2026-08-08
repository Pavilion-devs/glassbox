"""Durable recovery orchestration, restart, and uncertain-effect tests."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from typing import Any

import pytest

from glassbox_replay import (
    RecoveryArtifacts,
    RecoveryEffectEvidence,
    RecoveryJob,
    RecoveryOperation,
    RecoveryOrchestrationError,
    RecoveryOrchestrator,
    RecoveryStage,
    ReplayExecutionError,
    authorization_from_dict,
    build_replay_diff,
    recovery_workflow_id,
)
from tests.unit.test_recovery_closure import _artifacts, _source

EVALUATED_AT = "2026-08-08T12:05:00Z"


def _sealed_artifacts() -> tuple[Any, ...]:
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
    source_output = _source()[2]
    diff = build_replay_diff(
        source,
        replay_receipt,
        source_output=source_output,
        replay_output=execution.output,
    )
    sealed = RecoveryArtifacts.from_domain(
        execution,
        replay_receipt,
        diff,
        supersession,
        closure,
    )
    return source, task, bundle, authorization, trusted, sealed


def _job() -> tuple[Any, ...]:
    source, task, bundle, authorization, trusted, artifacts = _sealed_artifacts()
    job = RecoveryJob(
        workflow_id=recovery_workflow_id(authorization),
        authorization=authorization,
        bundle=bundle,
        stage=RecoveryStage.AUTHORIZED,
        stage_version=0,
        attempt_count=0,
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
    return source, task, trusted, artifacts, job


class FakeAuthority:
    def __init__(self, source: Any, task: Any) -> None:
        self.source = source
        self.task = task

    def get_task(self, campaign_id: str) -> Any:
        return self.task if campaign_id == self.task.campaign.campaign_id else None

    def get_receipt(self, receipt_id: str) -> Any:
        return self.source if receipt_id == self.source["receipt_id"] else None


class FakeStore:
    def __init__(self, job: RecoveryJob) -> None:
        self.job = job
        self.fail_completion_once = False

    def get(self, campaign_id: str) -> RecoveryJob | None:
        return self.job if campaign_id == self.job.campaign_id else None

    def claim(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> RecoveryJob | None:
        if campaign_id != self.job.campaign_id or self.job.next_operation is None:
            return None
        if (
            self.job.lease_owner is not None
            and self.job.lease_expires_at_ms is not None
            and self.job.lease_expires_at_ms > now_ms
        ):
            return None
        self.job = replace(
            self.job,
            attempt_count=self.job.attempt_count + 1,
            lease_operation=self.job.next_operation,
            lease_owner=worker_id,
            lease_expires_at_ms=now_ms + lease_duration_ms,
            last_error_type=None,
        )
        assert self.job.valid
        return self.job

    def release(self, campaign_id: str, *, worker_id: str, error_type: str) -> None:
        assert campaign_id == self.job.campaign_id and worker_id == self.job.lease_owner
        self.job = replace(
            self.job,
            lease_operation=None,
            lease_owner=None,
            lease_expires_at_ms=None,
            last_error_type=error_type,
        )

    def complete_execution(
        self,
        campaign_id: str,
        artifacts: RecoveryArtifacts,
        *,
        worker_id: str,
    ) -> bool:
        assert campaign_id == self.job.campaign_id and worker_id == self.job.lease_owner
        self.job = replace(
            self.job,
            stage=RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
            stage_version=1,
            lease_operation=None,
            lease_owner=None,
            lease_expires_at_ms=None,
            artifacts=artifacts,
        )
        assert self.job.valid
        return True

    def complete_effect(
        self,
        campaign_id: str,
        evidence: RecoveryEffectEvidence,
        *,
        worker_id: str,
    ) -> bool:
        assert campaign_id == self.job.campaign_id and worker_id == self.job.lease_owner
        if self.fail_completion_once:
            self.fail_completion_once = False
            raise OSError("synthetic uncertain commit")
        if evidence.operation is RecoveryOperation.PUBLISH_REPLAY_RECEIPT:
            changes = {
                "stage": RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
                "stage_version": 2,
                "replay_publication": evidence,
            }
        elif evidence.operation is RecoveryOperation.PUBLISH_SUPERSESSION:
            changes = {
                "stage": RecoveryStage.SUPERSESSION_VERIFIED,
                "stage_version": 3,
                "supersession_publication": evidence,
            }
        else:
            changes = {
                "stage": RecoveryStage.INCIDENT_CLOSED,
                "stage_version": 4,
                "incident_closure": evidence,
            }
        self.job = replace(
            self.job,
            **changes,
            lease_operation=None,
            lease_owner=None,
            lease_expires_at_ms=None,
        )
        assert self.job.valid
        return True


class FakeExecutor:
    def __init__(self, artifacts: RecoveryArtifacts) -> None:
        self.artifacts = artifacts
        self.calls = 0

    def execute(self, job: Any, task: Any, source_receipt: Any) -> RecoveryArtifacts:
        del job, task, source_receipt
        self.calls += 1
        return self.artifacts


class FakeEffects:
    def __init__(self) -> None:
        self.calls = {
            operation: 0
            for operation in RecoveryOperation
            if operation.name != "EXECUTE_ISOLATED_REPLAY"
        }

    def publish_replay_receipt(self, job: RecoveryJob) -> RecoveryEffectEvidence:
        assert job.artifacts is not None
        return self._evidence(
            job,
            RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
            str(job.artifacts.replay_receipt["receipt_id"]),
        )

    def publish_supersession(self, job: RecoveryJob) -> RecoveryEffectEvidence:
        assert job.artifacts is not None
        return self._evidence(
            job,
            RecoveryOperation.PUBLISH_SUPERSESSION,
            job.artifacts.supersession.supersession_id,
        )

    def close_incident(self, job: RecoveryJob) -> RecoveryEffectEvidence:
        assert job.artifacts is not None
        return self._evidence(
            job,
            RecoveryOperation.CLOSE_INCIDENT,
            job.artifacts.closure.closure_id,
        )

    def _evidence(
        self,
        job: RecoveryJob,
        operation: RecoveryOperation,
        artifact_id: str,
    ) -> RecoveryEffectEvidence:
        self.calls[operation] += 1
        return RecoveryEffectEvidence.create(
            operation=operation,
            campaign_id=job.campaign_id,
            artifact_id=artifact_id,
            target_id=f"urn:li:document:{operation.value.lower()}",
            aspect_names=("documentInfo",),
            emission_count=2,
            write_performed=True,
            readback_verified=True,
            recorded_at="2026-08-08T12:06:00Z",
        )


def _orchestrator(
    store: FakeStore,
    authority: FakeAuthority,
    executor: FakeExecutor,
    effects: FakeEffects,
    trusted: dict[str, str],
    *,
    now_ms: int,
    worker_id: str,
) -> RecoveryOrchestrator:
    return RecoveryOrchestrator(
        store,
        authority,
        executor,
        effects,
        trusted_signer_fingerprints=trusted,
        worker_id=worker_id,
        clock_ms=lambda: now_ms,
        clock_iso=lambda: EVALUATED_AT,
    )


def test_artifact_set_and_authorization_round_trip_without_transient_values() -> None:
    _source_receipt, _task, _trusted, artifacts, job = _job()

    restored = RecoveryArtifacts.from_dict(artifacts.to_dict())
    restored_authorization = authorization_from_dict(job.authorization.to_dict())

    assert restored == artifacts and restored.valid
    assert restored.to_dict()["contract"] == "glassbox.recovery-artifacts.v2"
    assert restored_authorization == job.authorization and restored_authorization.valid
    encoded = json.dumps(restored.to_dict())
    assert "transient-output" not in encoded
    assert "source-only" not in encoded

    legacy = artifacts.to_dict()
    legacy["contract"] = "glassbox.recovery-artifacts.v1"
    with pytest.raises(ReplayExecutionError, match="invalid"):
        RecoveryArtifacts.from_dict(legacy)

    (
        raw_source,
        _raw_task,
        _raw_bundle,
        _raw_authorization,
        _raw_trusted,
        raw_execution,
        raw_replay,
        raw_supersession,
        raw_closure,
    ) = _artifacts()
    raw_diff = build_replay_diff(
        raw_source,
        raw_replay,
        source_output=_source()[2],
        replay_output=raw_execution.output,
    )
    with pytest.raises(ReplayExecutionError, match="successful execution"):
        RecoveryArtifacts.from_domain(
            replace(raw_execution, status="FAILED"),
            raw_replay,
            raw_diff,
            raw_supersession,
            raw_closure,
        )
    with pytest.raises(ReplayExecutionError, match="bindings"):
        RecoveryArtifacts.from_domain(
            raw_execution,
            raw_replay,
            raw_diff,
            raw_supersession,
            replace(raw_closure, authorization_id="different-authorization"),
        )


def test_orchestrator_closes_in_four_durable_steps_and_restart_skips_execution() -> None:
    source, task, trusted, artifacts, job = _job()
    store = FakeStore(job)
    authority = FakeAuthority(source, task)
    executor = FakeExecutor(artifacts)
    effects = FakeEffects()
    first_worker = _orchestrator(
        store,
        authority,
        executor,
        effects,
        trusted,
        now_ms=1_000,
        worker_id="worker-a",
    )

    first = first_worker.process_next(job.campaign_id)
    assert first.stage is RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED
    assert first.to_dict()["raw_content_returned"] is False
    assert store.job.to_dict()["workflow_state"] == "ISOLATED_EXECUTION_SUCCEEDED"
    assert executor.calls == 1

    restarted = _orchestrator(
        store,
        authority,
        executor,
        effects,
        trusted,
        now_ms=2_000,
        worker_id="worker-b",
    )
    remaining = restarted.run_to_completion(job.campaign_id)

    assert [item.stage for item in remaining] == [
        RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
        RecoveryStage.SUPERSESSION_VERIFIED,
        RecoveryStage.INCIDENT_CLOSED,
    ]
    assert executor.calls == 1
    assert store.job.valid and store.job.stage is RecoveryStage.INCIDENT_CLOSED
    reused = restarted.process_next(job.campaign_id)
    assert reused.reused_completion and reused.operation is None


def test_uncertain_remote_completion_waits_for_lease_then_retries_idempotently() -> None:
    source, task, trusted, artifacts, job = _job()
    store = FakeStore(job)
    authority = FakeAuthority(source, task)
    executor = FakeExecutor(artifacts)
    effects = FakeEffects()
    worker = _orchestrator(
        store,
        authority,
        executor,
        effects,
        trusted,
        now_ms=1_000,
        worker_id="worker-a",
    )
    worker.process_next(job.campaign_id)
    store.fail_completion_once = True

    with pytest.raises(RecoveryOrchestrationError, match="OSError"):
        worker.process_next(job.campaign_id)
    assert store.job.lease_operation is RecoveryOperation.PUBLISH_REPLAY_RECEIPT
    assert store.job.workflow_state.value == "REPLAY_PUBLICATION_CLAIMED"
    assert effects.calls[RecoveryOperation.PUBLISH_REPLAY_RECEIPT] == 1

    immediate = _orchestrator(
        store,
        authority,
        executor,
        effects,
        trusted,
        now_ms=2_000,
        worker_id="worker-b",
    )
    with pytest.raises(RecoveryOrchestrationError, match="RecoveryLeaseUnavailable"):
        immediate.process_next(job.campaign_id)

    recovered = _orchestrator(
        store,
        authority,
        executor,
        effects,
        trusted,
        now_ms=62_000,
        worker_id="worker-b",
    ).process_next(job.campaign_id)
    assert recovered.stage is RecoveryStage.REPLAY_RECEIPT_PUBLISHED
    assert effects.calls[RecoveryOperation.PUBLISH_REPLAY_RECEIPT] == 2
    assert executor.calls == 1


def test_domain_decoders_reject_tampered_and_malformed_recovery_material() -> None:
    _source_value, _task_value, _trusted, artifacts, job = _job()
    valid = artifacts.to_dict()

    mutations = []
    tampered_id = copy.deepcopy(valid)
    tampered_id["artifact_set_id"] = "gbx:recovery-artifacts:sha256:" + "0" * 64
    mutations.append(tampered_id)
    malformed_changes = copy.deepcopy(valid)
    malformed_changes["diff"]["structural_changes"] = None
    mutations.append(malformed_changes)
    bad_diff = copy.deepcopy(valid)
    bad_diff["diff"]["diff_id"] = "gbx:replay-diff:sha256:" + "0" * 64
    mutations.append(bad_diff)
    bad_supersession = copy.deepcopy(valid)
    bad_supersession["supersession"]["supersession_id"] = (
        "gbx:replay-supersession:sha256:" + "0" * 64
    )
    mutations.append(bad_supersession)
    bad_closure = copy.deepcopy(valid)
    bad_closure["closure"]["closure_id"] = "gbx:recovery-closure:sha256:" + "0" * 64
    mutations.append(bad_closure)
    bad_score = copy.deepcopy(valid)
    bad_score["diff"]["semantic"]["score"] = True
    mutations.append(bad_score)
    bad_tuple = copy.deepcopy(valid)
    bad_tuple["closure"]["isolation_attestation_ids"] = "not-an-array"
    mutations.append(bad_tuple)
    bad_digest = copy.deepcopy(valid)
    bad_digest["diff"]["source_output_digest"]["algorithm"] = "md5"
    mutations.append(bad_digest)

    for value in mutations:
        with pytest.raises(ReplayExecutionError):
            RecoveryArtifacts.from_dict(value)

    authorization = job.authorization.to_dict()
    without_signatures = copy.deepcopy(authorization)
    without_signatures["signatures"] = None
    with pytest.raises(ReplayExecutionError, match="signatures"):
        authorization_from_dict(without_signatures)
    wrong_id = copy.deepcopy(authorization)
    wrong_id["authorization_id"] = "gbx:recovery-authorization:sha256:" + "0" * 64
    with pytest.raises(ReplayExecutionError, match="authorization is invalid"):
        authorization_from_dict(wrong_id)

    evidence = RecoveryEffectEvidence.create(
        operation=RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
        campaign_id=job.campaign_id,
        artifact_id=str(artifacts.replay_receipt["receipt_id"]),
        target_id="urn:li:document:replay",
        aspect_names=("documentInfo",),
        emission_count=2,
        write_performed=True,
        readback_verified=True,
        recorded_at="2026-08-08T12:06:00Z",
    )
    assert RecoveryEffectEvidence.from_dict(evidence.to_dict()) == evidence
    invalid_operation = evidence.to_dict()
    invalid_operation["operation"] = "DELETE_HISTORY"
    with pytest.raises(ReplayExecutionError, match="operation"):
        RecoveryEffectEvidence.from_dict(invalid_operation)
    invalid_evidence = evidence.to_dict()
    invalid_evidence["evidence_id"] = "gbx:recovery-effect:sha256:" + "0" * 64
    with pytest.raises(ReplayExecutionError, match="effect evidence"):
        RecoveryEffectEvidence.from_dict(invalid_evidence)
    invalid_write_flag = evidence.to_dict()
    invalid_write_flag["write_performed"] = "yes"
    with pytest.raises(ReplayExecutionError, match="write_performed"):
        RecoveryEffectEvidence.from_dict(invalid_write_flag)
    assert not replace(evidence, recorded_at="not-a-time").valid
    with pytest.raises(ReplayExecutionError, match="ISO 8601"):
        RecoveryEffectEvidence.create(
            operation=RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
            campaign_id=job.campaign_id,
            artifact_id="artifact",
            target_id="target",
            aspect_names=("documentInfo",),
            emission_count=1,
            write_performed=True,
            readback_verified=True,
            recorded_at="not-a-time",
        )
    with pytest.raises(ReplayExecutionError, match="timezone"):
        RecoveryEffectEvidence.create(
            operation=RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
            campaign_id=job.campaign_id,
            artifact_id="artifact",
            target_id="target",
            aspect_names=("documentInfo",),
            emission_count=1,
            write_performed=True,
            readback_verified=True,
            recorded_at="2026-08-08T12:00:00",
        )


def test_orchestrator_reports_bounded_preflight_and_state_failures() -> None:
    source, task, trusted, artifacts, job = _job()
    authority = FakeAuthority(source, task)
    effects = FakeEffects()

    with pytest.raises(ReplayExecutionError, match="lease duration"):
        RecoveryOrchestrator(
            FakeStore(job),
            authority,
            FakeExecutor(artifacts),
            effects,
            trusted_signer_fingerprints=trusted,
            lease_duration_ms=0,
        )
    with pytest.raises(ReplayExecutionError, match="trusted signer"):
        RecoveryOrchestrator(
            FakeStore(job),
            authority,
            FakeExecutor(artifacts),
            effects,
            trusted_signer_fingerprints={},
        )
    missing = FakeStore(job)
    missing.get = lambda _campaign_id: None  # type: ignore[method-assign]
    with pytest.raises(RecoveryOrchestrationError, match="RecoveryWorkflowMissing"):
        _orchestrator(
            missing,
            authority,
            FakeExecutor(artifacts),
            effects,
            trusted,
            now_ms=1,
            worker_id="worker",
        ).process_next(job.campaign_id)

    invalid_authority = FakeAuthority(source, task)
    invalid_authority.source = None
    invalid_store = FakeStore(job)
    with pytest.raises(RecoveryOrchestrationError, match="TypeError"):
        _orchestrator(
            invalid_store,
            invalid_authority,
            FakeExecutor(artifacts),
            effects,
            trusted,
            now_ms=1,
            worker_id="worker",
        ).process_next(job.campaign_id)
    assert invalid_store.job.last_error_type == "TypeError"

    expired_store = FakeStore(job)
    expired = RecoveryOrchestrator(
        expired_store,
        authority,
        FakeExecutor(artifacts),
        effects,
        trusted_signer_fingerprints=trusted,
        worker_id="worker",
        clock_ms=lambda: 1,
        clock_iso=lambda: "2026-08-08T13:00:00Z",
    )
    with pytest.raises(RecoveryOrchestrationError, match="ReplayExecutionError"):
        expired.process_next(job.campaign_id)
    assert expired_store.job.last_error_type == "ReplayExecutionError"

    class MissingAuthority:
        def get_task(self, campaign_id: str) -> None:
            del campaign_id

        def get_receipt(self, receipt_id: str) -> None:
            del receipt_id

    missing_authority_store = FakeStore(job)
    with pytest.raises(RecoveryOrchestrationError, match="ReplayExecutionError"):
        _orchestrator(
            missing_authority_store,
            MissingAuthority(),  # type: ignore[arg-type]
            FakeExecutor(artifacts),
            effects,
            trusted,
            now_ms=1,
            worker_id="worker",
        ).process_next(job.campaign_id)

    invalid_artifacts = replace(artifacts, artifact_set_id="invalid")
    invalid_artifact_store = FakeStore(job)
    with pytest.raises(RecoveryOrchestrationError, match="ReplayExecutionError"):
        _orchestrator(
            invalid_artifact_store,
            authority,
            FakeExecutor(invalid_artifacts),
            effects,
            trusted,
            now_ms=1,
            worker_id="worker",
        ).process_next(job.campaign_id)

    with pytest.raises(ReplayExecutionError, match="max_steps"):
        _orchestrator(
            FakeStore(job),
            authority,
            FakeExecutor(artifacts),
            effects,
            trusted,
            now_ms=1,
            worker_id="worker",
        ).run_to_completion(job.campaign_id, max_steps=0)

    private_orchestrator = _orchestrator(
        FakeStore(job),
        authority,
        FakeExecutor(artifacts),
        effects,
        trusted,
        now_ms=1,
        worker_id="worker",
    )
    with pytest.raises(ReplayExecutionError, match="persisted execution artifacts"):
        private_orchestrator._apply_effect(
            RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
            job,
        )

    class InvalidEffects(FakeEffects):
        def publish_replay_receipt(self, effect_job: RecoveryJob) -> RecoveryEffectEvidence:
            return replace(super().publish_replay_receipt(effect_job), readback_verified=False)

    job_with_artifacts = replace(
        job,
        stage=RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
        stage_version=1,
        artifacts=artifacts,
    )
    invalid_effect_orchestrator = _orchestrator(
        FakeStore(job_with_artifacts),
        authority,
        FakeExecutor(artifacts),
        InvalidEffects(),
        trusted,
        now_ms=1,
        worker_id="worker",
    )
    with pytest.raises(ReplayExecutionError, match="direct-readback evidence"):
        invalid_effect_orchestrator._apply_effect(
            RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
            job_with_artifacts,
        )


def test_orchestrator_preserves_execution_lease_on_uncertain_state_commit() -> None:
    source, task, trusted, artifacts, job = _job()

    class ExecutionCommitFailureStore(FakeStore):
        def complete_execution(self, *args: Any, **kwargs: Any) -> bool:
            del args, kwargs
            raise OSError("uncertain execution commit")

    store = ExecutionCommitFailureStore(job)
    orchestrator = _orchestrator(
        store,
        FakeAuthority(source, task),
        FakeExecutor(artifacts),
        FakeEffects(),
        trusted,
        now_ms=1,
        worker_id="worker",
    )
    with pytest.raises(RecoveryOrchestrationError, match="OSError"):
        orchestrator.process_next(job.campaign_id)
    assert store.job.lease_operation is RecoveryOperation.EXECUTE_ISOLATED_REPLAY

    class ClaimFailureStore(FakeStore):
        def claim(self, *args: Any, **kwargs: Any) -> None:
            del args, kwargs
            raise OSError("state unavailable")

    with pytest.raises(RecoveryOrchestrationError, match="OSError"):
        _orchestrator(
            ClaimFailureStore(job),
            FakeAuthority(source, task),
            FakeExecutor(artifacts),
            FakeEffects(),
            trusted,
            now_ms=1,
            worker_id="worker",
        ).process_next(job.campaign_id)
