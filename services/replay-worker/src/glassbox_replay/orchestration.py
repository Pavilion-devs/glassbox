"""Durable, restart-safe orchestration for authorized recovery workflows."""

from __future__ import annotations

import copy
import hashlib
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from glassbox_dbom import verify_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_invalidation import OutboxTask
from glassbox_policy import SemanticAssessment, SemanticRuleEvaluation
from glassbox_replay.closure import RecoveryClosureRecord
from glassbox_replay.diff import ReplayDiff, StructuralChange
from glassbox_replay.execution import ReadOnlyReplayExecution, ReplayExecutionError
from glassbox_replay.recovery import (
    RecoveryAuthorization,
    RecoverySignature,
    verify_recovery_authorization,
)
from glassbox_replay.supersession import SupersessionRecord

RECOVERY_ORCHESTRATION_POLICY_VERSION = "glassbox.recovery-orchestration.v1"
RECOVERY_ARTIFACT_SET_CONTRACT = "glassbox.recovery-artifacts.v2"
_WORKFLOW_DOMAIN = b"glassbox.recovery.workflow.v1\0"
_ARTIFACT_SET_DOMAIN = b"glassbox.recovery.artifact-set.v2\0"
_EFFECT_EVIDENCE_DOMAIN = b"glassbox.recovery.effect-evidence.v1\0"


class RecoveryOrchestrationError(RuntimeError):
    """A bounded recovery-stage failure that does not expose transport details."""

    def __init__(self, operation: RecoveryOperation | None, failure_type: str) -> None:
        self.operation = operation
        self.failure_type = failure_type
        label = operation.value if operation is not None else "STATE"
        super().__init__(f"recovery orchestration failed at {label} ({failure_type})")


class RecoveryStage(StrEnum):
    """Durable checkpoints; claimed work is represented by a separate lease."""

    AUTHORIZED = "AUTHORIZED"
    ISOLATED_EXECUTION_SUCCEEDED = "ISOLATED_EXECUTION_SUCCEEDED"
    REPLAY_RECEIPT_PUBLISHED = "REPLAY_RECEIPT_PUBLISHED"
    SUPERSESSION_VERIFIED = "SUPERSESSION_VERIFIED"
    INCIDENT_CLOSED = "INCIDENT_CLOSED"


class RecoveryOperation(StrEnum):
    """The one operation permitted after each durable checkpoint."""

    EXECUTE_ISOLATED_REPLAY = "EXECUTE_ISOLATED_REPLAY"
    PUBLISH_REPLAY_RECEIPT = "PUBLISH_REPLAY_RECEIPT"
    PUBLISH_SUPERSESSION = "PUBLISH_SUPERSESSION"
    CLOSE_INCIDENT = "CLOSE_INCIDENT"


class RecoveryWorkflowState(StrEnum):
    """Operator-facing state including active lease claims."""

    AUTHORIZED = "AUTHORIZED"
    EXECUTION_CLAIMED = "EXECUTION_CLAIMED"
    ISOLATED_EXECUTION_SUCCEEDED = "ISOLATED_EXECUTION_SUCCEEDED"
    REPLAY_PUBLICATION_CLAIMED = "REPLAY_PUBLICATION_CLAIMED"
    REPLAY_RECEIPT_PUBLISHED = "REPLAY_RECEIPT_PUBLISHED"
    SUPERSESSION_PUBLICATION_CLAIMED = "SUPERSESSION_PUBLICATION_CLAIMED"
    SUPERSESSION_VERIFIED = "SUPERSESSION_VERIFIED"
    INCIDENT_CLOSURE_CLAIMED = "INCIDENT_CLOSURE_CLAIMED"
    INCIDENT_CLOSED = "INCIDENT_CLOSED"


_NEXT_OPERATION = {
    RecoveryStage.AUTHORIZED: RecoveryOperation.EXECUTE_ISOLATED_REPLAY,
    RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED: RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
    RecoveryStage.REPLAY_RECEIPT_PUBLISHED: RecoveryOperation.PUBLISH_SUPERSESSION,
    RecoveryStage.SUPERSESSION_VERIFIED: RecoveryOperation.CLOSE_INCIDENT,
}
_RESULT_STAGE = {
    RecoveryOperation.EXECUTE_ISOLATED_REPLAY: RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
    RecoveryOperation.PUBLISH_REPLAY_RECEIPT: RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
    RecoveryOperation.PUBLISH_SUPERSESSION: RecoveryStage.SUPERSESSION_VERIFIED,
    RecoveryOperation.CLOSE_INCIDENT: RecoveryStage.INCIDENT_CLOSED,
}
_CLAIMED_STATE = {
    RecoveryOperation.EXECUTE_ISOLATED_REPLAY: RecoveryWorkflowState.EXECUTION_CLAIMED,
    RecoveryOperation.PUBLISH_REPLAY_RECEIPT: RecoveryWorkflowState.REPLAY_PUBLICATION_CLAIMED,
    RecoveryOperation.PUBLISH_SUPERSESSION: RecoveryWorkflowState.SUPERSESSION_PUBLICATION_CLAIMED,
    RecoveryOperation.CLOSE_INCIDENT: RecoveryWorkflowState.INCIDENT_CLOSURE_CLAIMED,
}
_STAGE_STATE = {item: RecoveryWorkflowState(item.value) for item in RecoveryStage}
_STAGE_RANK = {stage: index for index, stage in enumerate(RecoveryStage)}


@dataclass(frozen=True)
class RecoveryArtifacts:
    """Raw-free artifacts sealed atomically after one isolated execution result."""

    artifact_set_id: str
    execution: Mapping[str, Any] = field(repr=False)
    replay_receipt: Mapping[str, Any] = field(repr=False)
    diff: ReplayDiff
    supersession: SupersessionRecord
    closure: RecoveryClosureRecord
    contract: str = RECOVERY_ARTIFACT_SET_CONTRACT

    @classmethod
    def from_domain(
        cls,
        execution: ReadOnlyReplayExecution,
        replay_receipt: Mapping[str, Any],
        diff: ReplayDiff,
        supersession: SupersessionRecord,
        closure: RecoveryClosureRecord,
    ) -> RecoveryArtifacts:
        """Remove transient outputs and seal the complete downstream artifact set."""

        if not execution.valid or execution.status != "SUCCEEDED":
            raise ReplayExecutionError("recovery artifacts require a successful execution")
        material: dict[str, Any] = {
            "contract": RECOVERY_ARTIFACT_SET_CONTRACT,
            "execution": execution.to_dict(),
            "replay_receipt": copy.deepcopy(dict(replay_receipt)),
            "diff": diff.to_dict(),
            "supersession": supersession.to_dict(),
            "closure": closure.to_dict(),
        }
        result = cls(
            artifact_set_id=_content_id(
                "gbx:recovery-artifacts:sha256:", _ARTIFACT_SET_DOMAIN, material
            ),
            execution=material["execution"],
            replay_receipt=material["replay_receipt"],
            diff=diff,
            supersession=supersession,
            closure=closure,
        )
        if not result.valid:
            raise ReplayExecutionError("recovery artifact bindings are invalid")
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RecoveryArtifacts:
        """Reconstruct and recheck a persisted raw-free artifact set."""

        result = cls(
            artifact_set_id=_text(value, "artifact_set_id"),
            execution=copy.deepcopy(dict(_mapping(value, "execution"))),
            replay_receipt=copy.deepcopy(dict(_mapping(value, "replay_receipt"))),
            diff=_diff_from_dict(_mapping(value, "diff")),
            supersession=_supersession_from_dict(_mapping(value, "supersession")),
            closure=_closure_from_dict(_mapping(value, "closure")),
            contract=_text(value, "contract"),
        )
        if not result.valid:
            raise ReplayExecutionError("persisted recovery artifact set is invalid")
        return result

    @property
    def valid(self) -> bool:
        receipt_report = verify_receipt(self.replay_receipt, require_signature=True)
        execution_id = self.execution.get("execution_id")
        source_receipt_id = self.execution.get("source_receipt_id")
        bundle_id = self.execution.get("bundle_id")
        replay_receipt_id = self.replay_receipt.get("receipt_id")
        extensions = self.replay_receipt.get("extensions")
        material = self._material()
        return (
            self.contract == RECOVERY_ARTIFACT_SET_CONTRACT
            and self.artifact_set_id
            == _content_id("gbx:recovery-artifacts:sha256:", _ARTIFACT_SET_DOMAIN, material)
            and receipt_report.valid
            and self.diff.valid
            and self.supersession.valid
            and self.closure.valid
            and isinstance(extensions, Mapping)
            and execution_id == self.supersession.execution_id == self.closure.execution_id
            and source_receipt_id
            == self.diff.source_receipt_id
            == self.supersession.source_receipt_id
            == self.closure.source_receipt_id
            and replay_receipt_id
            == self.diff.replay_receipt_id
            == self.supersession.replay_receipt_id
            == self.closure.replay_receipt_id
            and bundle_id == self.supersession.bundle_id == self.closure.bundle_id
            and self.diff.diff_id == self.supersession.diff_id == self.closure.diff_id
            and self.diff.semantic.method == self.supersession.semantic_method
            and self.diff.semantic.policy_id == self.supersession.semantic_policy_id
            and self.diff.semantic.rule_id == self.supersession.semantic_rule_id
            and self.diff.semantic.rule_version == self.supersession.semantic_rule_version
            and self.diff.semantic.result == self.supersession.semantic_result
            and self.diff.semantic.exact_match == self.supersession.semantic_exact_match
            and self.supersession.supersession_id == self.closure.supersession_id
            and extensions.get("glassbox.replay.execution_id") == execution_id
            and extensions.get("glassbox.replay.source_receipt_id") == source_receipt_id
            and extensions.get("glassbox.replay.bundle_id") == bundle_id
        )

    def to_dict(self) -> dict[str, Any]:
        return {"artifact_set_id": self.artifact_set_id, **self._material()}

    def _material(self) -> dict[str, Any]:
        return {
            "contract": self.contract,
            "execution": copy.deepcopy(dict(self.execution)),
            "replay_receipt": copy.deepcopy(dict(self.replay_receipt)),
            "diff": self.diff.to_dict(),
            "supersession": self.supersession.to_dict(),
            "closure": self.closure.to_dict(),
        }


@dataclass(frozen=True)
class RecoveryEffectEvidence:
    """Content-addressed proof that one remote stage passed direct readback."""

    evidence_id: str
    operation: RecoveryOperation
    campaign_id: str
    artifact_id: str
    target_id: str
    aspect_names: tuple[str, ...]
    emission_count: int
    write_performed: bool
    readback_verified: bool
    recorded_at: str
    policy_version: str = RECOVERY_ORCHESTRATION_POLICY_VERSION

    @classmethod
    def create(
        cls,
        *,
        operation: RecoveryOperation,
        campaign_id: str,
        artifact_id: str,
        target_id: str,
        aspect_names: tuple[str, ...],
        emission_count: int,
        write_performed: bool,
        readback_verified: bool,
        recorded_at: str,
    ) -> RecoveryEffectEvidence:
        _timestamp(recorded_at, "recorded_at")
        material: dict[str, Any] = {
            "operation": operation.value,
            "campaign_id": campaign_id,
            "artifact_id": artifact_id,
            "target_id": target_id,
            "aspect_names": sorted(aspect_names),
            "emission_count": emission_count,
            "write_performed": write_performed,
            "readback_verified": readback_verified,
            "recorded_at": recorded_at,
            "policy_version": RECOVERY_ORCHESTRATION_POLICY_VERSION,
        }
        return cls(
            evidence_id=_content_id(
                "gbx:recovery-effect:sha256:", _EFFECT_EVIDENCE_DOMAIN, material
            ),
            operation=operation,
            campaign_id=campaign_id,
            artifact_id=artifact_id,
            target_id=target_id,
            aspect_names=tuple(sorted(aspect_names)),
            emission_count=emission_count,
            write_performed=write_performed,
            readback_verified=readback_verified,
            recorded_at=recorded_at,
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RecoveryEffectEvidence:
        try:
            operation = RecoveryOperation(_text(value, "operation"))
        except ValueError as exc:
            raise ReplayExecutionError("recovery effect operation is invalid") from exc
        aspects = _string_tuple(value, "aspect_names")
        result = cls(
            evidence_id=_text(value, "evidence_id"),
            operation=operation,
            campaign_id=_text(value, "campaign_id"),
            artifact_id=_text(value, "artifact_id"),
            target_id=_text(value, "target_id"),
            aspect_names=aspects,
            emission_count=_integer(value, "emission_count"),
            write_performed=_boolean(value, "write_performed"),
            readback_verified=_boolean(value, "readback_verified"),
            recorded_at=_text(value, "recorded_at"),
            policy_version=_text(value, "policy_version"),
        )
        if not result.valid:
            raise ReplayExecutionError("persisted recovery effect evidence is invalid")
        return result

    @property
    def valid(self) -> bool:
        try:
            _timestamp(self.recorded_at, "recorded_at")
        except ReplayExecutionError:
            return False
        return (
            self.policy_version == RECOVERY_ORCHESTRATION_POLICY_VERSION
            and self.readback_verified
            and bool(self.campaign_id)
            and bool(self.artifact_id)
            and bool(self.target_id)
            and bool(self.aspect_names)
            and tuple(sorted(set(self.aspect_names))) == self.aspect_names
            and self.emission_count >= 0
            and self.evidence_id
            == _content_id(
                "gbx:recovery-effect:sha256:",
                _EFFECT_EVIDENCE_DOMAIN,
                self._material(),
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {"evidence_id": self.evidence_id, **self._material(), "raw_content_returned": False}

    def _material(self) -> dict[str, Any]:
        return {
            "operation": self.operation.value,
            "campaign_id": self.campaign_id,
            "artifact_id": self.artifact_id,
            "target_id": self.target_id,
            "aspect_names": list(self.aspect_names),
            "emission_count": self.emission_count,
            "write_performed": self.write_performed,
            "readback_verified": self.readback_verified,
            "recorded_at": self.recorded_at,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class RecoveryJob:
    """Verified snapshot of one durable recovery workflow."""

    workflow_id: str
    authorization: RecoveryAuthorization = field(repr=False)
    bundle: Mapping[str, Any] = field(repr=False)
    stage: RecoveryStage
    stage_version: int
    attempt_count: int
    lease_operation: RecoveryOperation | None
    lease_owner: str | None
    lease_expires_at_ms: int | None
    last_error_type: str | None
    artifacts: RecoveryArtifacts | None
    replay_publication: RecoveryEffectEvidence | None
    supersession_publication: RecoveryEffectEvidence | None
    incident_closure: RecoveryEffectEvidence | None

    @property
    def campaign_id(self) -> str:
        return self.authorization.campaign_id

    @property
    def source_receipt_id(self) -> str:
        return self.authorization.source_receipt_id

    @property
    def bundle_id(self) -> str:
        return self.authorization.bundle_id

    @property
    def workflow_state(self) -> RecoveryWorkflowState:
        if self.lease_operation is not None:
            return _CLAIMED_STATE[self.lease_operation]
        return _STAGE_STATE[self.stage]

    @property
    def next_operation(self) -> RecoveryOperation | None:
        return _NEXT_OPERATION.get(self.stage)

    @property
    def valid(self) -> bool:
        expected_id = recovery_workflow_id(self.authorization)
        lease_valid = (
            self.lease_operation is not None
            and self.lease_owner is not None
            and self.lease_expires_at_ms is not None
            and self.lease_operation == self.next_operation
        ) or (
            self.lease_operation is None
            and self.lease_owner is None
            and self.lease_expires_at_ms is None
        )
        expected = _STAGE_RANK[self.stage]
        artifact_valid = (expected == 0 and self.artifacts is None) or (
            expected >= 1 and self.artifacts is not None and self.artifacts.valid
        )
        evidence = (
            self.replay_publication,
            self.supersession_publication,
            self.incident_closure,
        )
        evidence_valid = all(
            (index < expected and item is not None and item.valid)
            or (index >= expected and item is None)
            for index, item in enumerate(evidence, start=1)
        )
        if self.artifacts is not None:
            expected_artifacts = (
                self.artifacts.replay_receipt.get("receipt_id"),
                self.artifacts.supersession.supersession_id,
                self.artifacts.closure.closure_id,
            )
            evidence_valid = evidence_valid and all(
                item is None
                or (item.campaign_id == self.campaign_id and item.artifact_id == artifact_id)
                for item, artifact_id in zip(evidence, expected_artifacts, strict=True)
            )
        return (
            self.workflow_id == expected_id
            and self.authorization.valid
            and self.bundle.get("bundle_id") == self.bundle_id
            and self.stage_version == expected
            and self.attempt_count >= 0
            and lease_valid
            and artifact_valid
            and evidence_valid
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "workflow_id": self.workflow_id,
            "authorization_id": self.authorization.authorization_id,
            "campaign_id": self.campaign_id,
            "source_receipt_id": self.source_receipt_id,
            "bundle_id": self.bundle_id,
            "stage": self.stage.value,
            "workflow_state": self.workflow_state.value,
            "stage_version": self.stage_version,
            "attempt_count": self.attempt_count,
            "lease_operation": self.lease_operation.value if self.lease_operation else None,
            "lease_owner": self.lease_owner,
            "lease_expires_at_ms": self.lease_expires_at_ms,
            "last_error_type": self.last_error_type,
            "artifact_set_id": self.artifacts.artifact_set_id if self.artifacts else None,
            "replay_receipt_id": (
                self.artifacts.replay_receipt.get("receipt_id") if self.artifacts else None
            ),
            "supersession_id": (
                self.artifacts.supersession.supersession_id if self.artifacts else None
            ),
            "closure_id": self.artifacts.closure.closure_id if self.artifacts else None,
            "effect_evidence_ids": [
                item.evidence_id
                for item in (
                    self.replay_publication,
                    self.supersession_publication,
                    self.incident_closure,
                )
                if item is not None
            ],
            "raw_content_returned": False,
        }


@dataclass(frozen=True)
class RecoveryStepReport:
    """Bounded result for one completed or reused orchestration step."""

    workflow_id: str
    operation: RecoveryOperation | None
    stage: RecoveryStage
    workflow_state: RecoveryWorkflowState
    attempt_count: int
    reused_completion: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": True,
            "workflow_id": self.workflow_id,
            "operation": self.operation.value if self.operation else None,
            "stage": self.stage.value,
            "workflow_state": self.workflow_state.value,
            "attempt_count": self.attempt_count,
            "reused_completion": self.reused_completion,
            "raw_content_returned": False,
        }


class RecoveryAuthority(Protocol):
    """Authoritative invalidation state used for fresh authorization verification."""

    def get_task(self, campaign_id: str) -> OutboxTask | None: ...

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None: ...


class RecoveryStateStore(Protocol):
    """Persistence contract for the restart-safe orchestration worker."""

    def get(self, campaign_id: str) -> RecoveryJob | None: ...

    def claim(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> RecoveryJob | None: ...

    def release(self, campaign_id: str, *, worker_id: str, error_type: str) -> None: ...

    def complete_execution(
        self,
        campaign_id: str,
        artifacts: RecoveryArtifacts,
        *,
        worker_id: str,
    ) -> bool: ...

    def complete_effect(
        self,
        campaign_id: str,
        evidence: RecoveryEffectEvidence,
        *,
        worker_id: str,
    ) -> bool: ...


class AuthorizedRecoveryExecutor(Protocol):
    """Build the full raw-free artifact set from one exact authorized job."""

    def execute(
        self,
        job: RecoveryJob,
        task: OutboxTask,
        source_receipt: Mapping[str, Any],
    ) -> RecoveryArtifacts: ...


class RecoveryEffects(Protocol):
    """Idempotent DataHub effects, each ending in authoritative direct readback."""

    def publish_replay_receipt(self, job: RecoveryJob) -> RecoveryEffectEvidence: ...

    def publish_supersession(self, job: RecoveryJob) -> RecoveryEffectEvidence: ...

    def close_incident(self, job: RecoveryJob) -> RecoveryEffectEvidence: ...


class RecoveryOrchestrator:
    """Lease and advance one recovery without keeping correctness in process memory."""

    def __init__(
        self,
        store: RecoveryStateStore,
        authority: RecoveryAuthority,
        executor: AuthorizedRecoveryExecutor,
        effects: RecoveryEffects,
        *,
        trusted_signer_fingerprints: Mapping[str, str],
        worker_id: str | None = None,
        lease_duration_ms: int = 60_000,
        clock_ms: Callable[[], int] | None = None,
        clock_iso: Callable[[], str] | None = None,
    ) -> None:
        if lease_duration_ms <= 0:
            raise ReplayExecutionError("recovery lease duration must be positive")
        if not trusted_signer_fingerprints:
            raise ReplayExecutionError(
                "recovery orchestration requires trusted signer fingerprints"
            )
        self._store = store
        self._authority = authority
        self._executor = executor
        self._effects = effects
        self._trusted = dict(trusted_signer_fingerprints)
        self.worker_id = worker_id or f"recovery-worker-{uuid.uuid4().hex}"
        self.lease_duration_ms = lease_duration_ms
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)
        self._clock_iso = clock_iso or (
            lambda: datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        )

    def process_next(self, campaign_id: str) -> RecoveryStepReport:
        """Advance exactly one durable checkpoint, or reuse a closed workflow."""

        current = self._store.get(campaign_id)
        if current is None:
            raise RecoveryOrchestrationError(None, "RecoveryWorkflowMissing")
        if current.stage is RecoveryStage.INCIDENT_CLOSED:
            return _step_report(current, None, reused=True)
        try:
            claimed = self._store.claim(
                campaign_id,
                worker_id=self.worker_id,
                now_ms=self._clock_ms(),
                lease_duration_ms=self.lease_duration_ms,
            )
        except Exception as exc:
            raise RecoveryOrchestrationError(None, type(exc).__name__) from exc
        if claimed is None or claimed.lease_operation is None:
            raise RecoveryOrchestrationError(None, "RecoveryLeaseUnavailable")
        operation = claimed.lease_operation

        try:
            if operation is RecoveryOperation.EXECUTE_ISOLATED_REPLAY:
                artifacts = self._execute(claimed)
                try:
                    self._store.complete_execution(
                        campaign_id,
                        artifacts,
                        worker_id=self.worker_id,
                    )
                except Exception as exc:
                    # The completion outcome is uncertain. Keep the lease until expiry.
                    raise RecoveryOrchestrationError(operation, type(exc).__name__) from exc
            else:
                evidence = self._apply_effect(operation, claimed)
                try:
                    self._store.complete_effect(
                        campaign_id,
                        evidence,
                        worker_id=self.worker_id,
                    )
                except Exception as exc:
                    # The remote effect may have succeeded. Retry only after lease expiry.
                    raise RecoveryOrchestrationError(operation, type(exc).__name__) from exc
        except RecoveryOrchestrationError:
            raise
        except Exception as exc:
            try:
                self._store.release(
                    campaign_id,
                    worker_id=self.worker_id,
                    error_type=type(exc).__name__,
                )
            except Exception as release_exc:
                raise RecoveryOrchestrationError(
                    operation, type(release_exc).__name__
                ) from release_exc
            raise RecoveryOrchestrationError(operation, type(exc).__name__) from exc

        completed = self._store.get(campaign_id)
        if completed is None or completed.stage is not _RESULT_STAGE[operation]:
            raise RecoveryOrchestrationError(operation, "RecoveryCompletionReadbackMismatch")
        return _step_report(completed, operation, reused=False)

    def run_to_completion(
        self,
        campaign_id: str,
        *,
        max_steps: int = 4,
    ) -> tuple[RecoveryStepReport, ...]:
        """Run a bounded number of checkpoints; safe to call again after restart."""

        if max_steps <= 0:
            raise ReplayExecutionError("max_steps must be positive")
        reports: list[RecoveryStepReport] = []
        for _ in range(max_steps):
            report = self.process_next(campaign_id)
            reports.append(report)
            if report.stage is RecoveryStage.INCIDENT_CLOSED:
                break
        return tuple(reports)

    def _execute(self, job: RecoveryJob) -> RecoveryArtifacts:
        task = self._authority.get_task(job.campaign_id)
        source = self._authority.get_receipt(job.source_receipt_id)
        if task is None or source is None:
            raise ReplayExecutionError(
                "recovery authority no longer contains the bound source state"
            )
        verification = verify_recovery_authorization(
            job.authorization,
            task,
            source,
            job.bundle,
            evaluated_at=self._clock_iso(),
            trusted_signer_fingerprints=self._trusted,
        )
        if not verification.valid:
            raise ReplayExecutionError("recovery authorization failed fresh execution verification")
        artifacts = self._executor.execute(job, task, source)
        if not artifacts.valid:
            raise ReplayExecutionError("recovery executor returned invalid artifacts")
        if (
            artifacts.closure.authorization_id != job.authorization.authorization_id
            or artifacts.closure.campaign_id != job.campaign_id
            or artifacts.closure.source_receipt_id != job.source_receipt_id
            or artifacts.closure.bundle_id != job.bundle_id
        ):
            raise ReplayExecutionError("recovery artifacts do not bind the claimed authorization")
        return artifacts

    def _apply_effect(
        self,
        operation: RecoveryOperation,
        job: RecoveryJob,
    ) -> RecoveryEffectEvidence:
        if job.artifacts is None:
            raise ReplayExecutionError("recovery effect requires persisted execution artifacts")
        if operation is RecoveryOperation.PUBLISH_REPLAY_RECEIPT:
            evidence = self._effects.publish_replay_receipt(job)
        elif operation is RecoveryOperation.PUBLISH_SUPERSESSION:
            evidence = self._effects.publish_supersession(job)
        elif operation is RecoveryOperation.CLOSE_INCIDENT:
            evidence = self._effects.close_incident(job)
        else:  # pragma: no cover - enum and claim decoder close this branch
            raise ReplayExecutionError("unsupported recovery operation")
        if not evidence.valid or evidence.operation is not operation:
            raise ReplayExecutionError("recovery effect returned invalid direct-readback evidence")
        return evidence


def recovery_workflow_id(authorization: RecoveryAuthorization) -> str:
    """Return the stable logical-execution/idempotency identity for one authorization."""

    material = {
        "authorization_id": authorization.authorization_id,
        "campaign_id": authorization.campaign_id,
        "source_receipt_id": authorization.source_receipt_id,
        "bundle_id": authorization.bundle_id,
        "policy_version": RECOVERY_ORCHESTRATION_POLICY_VERSION,
    }
    return _content_id("gbx:recovery-workflow:sha256:", _WORKFLOW_DOMAIN, material)


def authorization_from_dict(value: Mapping[str, Any]) -> RecoveryAuthorization:
    """Strictly reconstruct a persisted recovery authorization."""

    signatures_value = value.get("signatures")
    if not isinstance(signatures_value, list) or not all(
        isinstance(item, Mapping) for item in signatures_value
    ):
        raise ReplayExecutionError("authorization signatures must be an array of objects")
    signatures = tuple(
        RecoverySignature(
            algorithm=_text(item, "algorithm"),
            key_id=_text(item, "key_id"),
            public_key=_text(item, "public_key"),
            value=_text(item, "value"),
        )
        for item in signatures_value
    )
    result = RecoveryAuthorization(
        authorization_id=_text(value, "authorization_id"),
        campaign_id=_text(value, "campaign_id"),
        incident_urn=_text(value, "incident_urn"),
        change_event_id=_text(value, "change_event_id"),
        source_receipt_id=_text(value, "source_receipt_id"),
        source_payload_digest=_digest_value(value, "source_payload_digest"),
        bundle_id=_text(value, "bundle_id"),
        mode=_text(value, "mode"),
        finding_state=_text(value, "finding_state"),
        finding_reason_code=_text(value, "finding_reason_code"),
        matched_evidence_ids=_string_tuple(value, "matched_evidence_ids"),
        campaign_policy_version=_text(value, "campaign_policy_version"),
        campaign_attempt_count=_integer(value, "campaign_attempt_count"),
        writeback_evidence_digest=_digest_value(value, "writeback_evidence_digest"),
        issuer=_text(value, "issuer"),
        issued_at=_text(value, "issued_at"),
        expires_at=_text(value, "expires_at"),
        revoked=_boolean(value, "revoked"),
        signatures=signatures,
        policy_version=_text(value, "policy_version"),
        scope=_text(value, "scope"),
    )
    if not result.valid:
        raise ReplayExecutionError("persisted recovery authorization is invalid")
    return result


def _step_report(
    job: RecoveryJob,
    operation: RecoveryOperation | None,
    *,
    reused: bool,
) -> RecoveryStepReport:
    return RecoveryStepReport(
        workflow_id=job.workflow_id,
        operation=operation,
        stage=job.stage,
        workflow_state=job.workflow_state,
        attempt_count=job.attempt_count,
        reused_completion=reused,
    )


def _diff_from_dict(value: Mapping[str, Any]) -> ReplayDiff:
    changes_value = value.get("structural_changes")
    if not isinstance(changes_value, list) or not all(
        isinstance(item, Mapping) for item in changes_value
    ):
        raise ReplayExecutionError("persisted replay diff structural changes are invalid")
    semantic_value = _mapping(value, "semantic")
    evaluations_value = semantic_value.get("evaluations")
    if not isinstance(evaluations_value, list) or not all(
        isinstance(item, Mapping) for item in evaluations_value
    ):
        raise ReplayExecutionError("persisted semantic rule evaluations are invalid")
    semantic = SemanticAssessment(
        method=_text(semantic_value, "method"),
        policy_id=_text(semantic_value, "policy_id"),
        rule_id=_text(semantic_value, "rule_id"),
        rule_version=_text(semantic_value, "rule_version"),
        result=_text(semantic_value, "result"),
        score=_number(semantic_value, "score"),
        exact_match=_boolean(semantic_value, "exact_match"),
        structural_change_count=_integer(semantic_value, "structural_change_count"),
        matched_change_count=_integer(semantic_value, "matched_change_count"),
        reason_codes=_string_tuple(semantic_value, "reason_codes"),
        evaluations=tuple(
            SemanticRuleEvaluation(
                rule_id=_text(item, "rule_id"),
                kind=_text(item, "kind"),
                path=_required_string(item, "path"),
                passed=_boolean(item, "passed"),
                reason_code=_text(item, "reason_code"),
                covered_change_paths=_string_tuple(item, "covered_change_paths"),
            )
            for item in evaluations_value
        ),
    )
    result = ReplayDiff(
        diff_id=_text(value, "diff_id"),
        source_receipt_id=_text(value, "source_receipt_id"),
        replay_receipt_id=_text(value, "replay_receipt_id"),
        source_output_digest=_digest_value(value, "source_output_digest"),
        replay_output_digest=_digest_value(value, "replay_output_digest"),
        structural_changes=tuple(
            StructuralChange(
                path=_text(item, "path"),
                kind=_text(item, "kind"),
                before_type=_optional_text(item, "before_type"),
                after_type=_optional_text(item, "after_type"),
                before_digest=_optional_digest_value(item, "before_digest"),
                after_digest=_optional_digest_value(item, "after_digest"),
            )
            for item in changes_value
        ),
        semantic=semantic,
    )
    if not result.valid:
        raise ReplayExecutionError("persisted replay diff is invalid")
    return result


def _supersession_from_dict(value: Mapping[str, Any]) -> SupersessionRecord:
    result = SupersessionRecord(
        supersession_id=_text(value, "supersession_id"),
        source_receipt_id=_text(value, "source_receipt_id"),
        replay_receipt_id=_text(value, "replay_receipt_id"),
        bundle_id=_text(value, "bundle_id"),
        plan_id=_text(value, "plan_id"),
        execution_id=_text(value, "execution_id"),
        diff_id=_text(value, "diff_id"),
        semantic_method=_text(value, "semantic_method"),
        semantic_policy_id=_text(value, "semantic_policy_id"),
        semantic_rule_id=_text(value, "semantic_rule_id"),
        semantic_rule_version=_text(value, "semantic_rule_version"),
        semantic_result=_text(value, "semantic_result"),
        semantic_exact_match=_boolean(value, "semantic_exact_match"),
        structural_change_count=_integer(value, "structural_change_count"),
        created_at=_text(value, "created_at"),
        policy_version=_text(value, "policy_version"),
        relation=_text(value, "relation"),
    )
    if not result.valid:
        raise ReplayExecutionError("persisted supersession is invalid")
    return result


def _closure_from_dict(value: Mapping[str, Any]) -> RecoveryClosureRecord:
    result = RecoveryClosureRecord(
        closure_id=_text(value, "closure_id"),
        campaign_id=_text(value, "campaign_id"),
        incident_urn=_text(value, "incident_urn"),
        authorization_id=_text(value, "authorization_id"),
        source_receipt_id=_text(value, "source_receipt_id"),
        replay_receipt_id=_text(value, "replay_receipt_id"),
        bundle_id=_text(value, "bundle_id"),
        execution_id=_text(value, "execution_id"),
        supersession_id=_text(value, "supersession_id"),
        diff_id=_text(value, "diff_id"),
        isolation_attestation_ids=_string_tuple(value, "isolation_attestation_ids"),
        closed_at=_text(value, "closed_at"),
        policy_version=_text(value, "policy_version"),
        resolution=_text(value, "resolution"),
    )
    if not result.valid:
        raise ReplayExecutionError("persisted recovery closure is invalid")
    return result


def _content_id(prefix: str, domain: bytes, material: Mapping[str, Any]) -> str:
    return prefix + hashlib.sha256(domain + canonicalize(material)).hexdigest()


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplayExecutionError(f"{name} must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplayExecutionError(f"{name} must include a timezone")
    return parsed


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayExecutionError(f"{key} must be an object")
    return selected


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayExecutionError(f"{key} must be a non-empty string")
    return selected


def _required_string(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str):
        raise ReplayExecutionError(f"{key} must be a string")
    return selected


def _optional_text(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is None:
        return None
    if not isinstance(selected, str):
        raise ReplayExecutionError(f"{key} must be a string or null")
    return selected


def _integer(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise ReplayExecutionError(f"{key} must be an integer")
    return selected


def _number(value: Mapping[str, Any], key: str) -> float:
    selected = value.get(key)
    if not isinstance(selected, int | float) or isinstance(selected, bool):
        raise ReplayExecutionError(f"{key} must be a number")
    return float(selected)


def _boolean(value: Mapping[str, Any], key: str) -> bool:
    selected = value.get(key)
    if not isinstance(selected, bool):
        raise ReplayExecutionError(f"{key} must be a boolean")
    return selected


def _string_tuple(value: Mapping[str, Any], key: str) -> tuple[str, ...]:
    selected = value.get(key)
    if not isinstance(selected, list | tuple) or not all(
        isinstance(item, str) for item in selected
    ):
        raise ReplayExecutionError(f"{key} must be an array of strings")
    return tuple(selected)


def _digest_value(value: Mapping[str, Any], key: str) -> str:
    selected = _mapping(value, key)
    if selected.get("algorithm") != "sha256":
        raise ReplayExecutionError(f"{key} must use sha256")
    return _text(selected, "value")


def _optional_digest_value(value: Mapping[str, Any], key: str) -> str | None:
    if value.get(key) is None:
        return None
    return _digest_value(value, key)


__all__ = [
    "RECOVERY_ARTIFACT_SET_CONTRACT",
    "RECOVERY_ORCHESTRATION_POLICY_VERSION",
    "AuthorizedRecoveryExecutor",
    "RecoveryArtifacts",
    "RecoveryAuthority",
    "RecoveryEffectEvidence",
    "RecoveryEffects",
    "RecoveryJob",
    "RecoveryOperation",
    "RecoveryOrchestrationError",
    "RecoveryOrchestrator",
    "RecoveryStage",
    "RecoveryStateStore",
    "RecoveryStepReport",
    "RecoveryWorkflowState",
    "authorization_from_dict",
    "recovery_workflow_id",
]
