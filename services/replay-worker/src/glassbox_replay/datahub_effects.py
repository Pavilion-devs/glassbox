"""Concrete idempotent DataHub effects for the durable recovery orchestrator."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime

from glassbox_compiler.publication import LiveReceiptPipeline
from glassbox_datahub.closure import RecoveryClosureEmitter
from glassbox_datahub.supersession import SupersessionEmitter
from glassbox_policy import FieldLineageProof
from glassbox_replay.execution import ReplayExecutionError
from glassbox_replay.orchestration import (
    RecoveryArtifacts,
    RecoveryEffectEvidence,
    RecoveryJob,
    RecoveryOperation,
)


class DataHubRecoveryEffects:
    """Translate persisted artifacts into directly verified DataHub operations."""

    def __init__(
        self,
        receipt_pipeline: LiveReceiptPipeline,
        supersession_emitter: SupersessionEmitter,
        closure_emitter: RecoveryClosureEmitter,
        *,
        clock_iso: Callable[[], str] | None = None,
    ) -> None:
        self._receipt_pipeline = receipt_pipeline
        self._supersession_emitter = supersession_emitter
        self._closure_emitter = closure_emitter
        self._clock_iso = clock_iso or (
            lambda: datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        )

    def publish_replay_receipt(self, job: RecoveryJob) -> RecoveryEffectEvidence:
        """Register, publish, and directly verify the persisted replay DBOM."""

        artifacts = _artifacts(job)
        receipt = artifacts.replay_receipt
        report = self._receipt_pipeline.publish_compiled(
            receipt,
            field_lineage=FieldLineageProof(),
        )
        if not report.valid:
            raise ReplayExecutionError("replay receipt publication did not verify")
        return RecoveryEffectEvidence.create(
            operation=RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
            campaign_id=job.campaign_id,
            artifact_id=str(receipt["receipt_id"]),
            target_id=report.datahub.document_urn,
            aspect_names=report.datahub.aspect_names,
            emission_count=report.datahub.emissions,
            write_performed=report.datahub_write_performed,
            readback_verified=report.state_readback_verified and report.datahub.valid,
            recorded_at=self._clock_iso(),
        )

    def publish_supersession(self, job: RecoveryJob) -> RecoveryEffectEvidence:
        """Double-write and directly verify the immutable supersession Document."""

        artifacts = _artifacts(job)
        report = self._supersession_emitter.emit_verified(artifacts.supersession)
        if not report.valid:
            raise ReplayExecutionError("supersession publication did not verify")
        return RecoveryEffectEvidence.create(
            operation=RecoveryOperation.PUBLISH_SUPERSESSION,
            campaign_id=job.campaign_id,
            artifact_id=artifacts.supersession.supersession_id,
            target_id=report.document_urn,
            aspect_names=report.aspect_names,
            emission_count=report.emissions,
            write_performed=report.emissions > 0,
            readback_verified=report.valid,
            recorded_at=self._clock_iso(),
        )

    def close_incident(self, job: RecoveryJob) -> RecoveryEffectEvidence:
        """Resolve only the exact incident after fresh prerequisite readback."""

        artifacts = _artifacts(job)
        report = self._closure_emitter.close_verified(
            artifacts.closure,
            artifacts.supersession,
        )
        if not report.valid:
            raise ReplayExecutionError("incident closure did not verify")
        return RecoveryEffectEvidence.create(
            operation=RecoveryOperation.CLOSE_INCIDENT,
            campaign_id=job.campaign_id,
            artifact_id=artifacts.closure.closure_id,
            target_id=report.incident_urn,
            aspect_names=report.incident_aspects,
            emission_count=report.emission_attempts,
            write_performed=report.emission_attempts > 0,
            readback_verified=report.valid,
            recorded_at=self._clock_iso(),
        )


def _artifacts(job: RecoveryJob) -> RecoveryArtifacts:
    if job.artifacts is None:
        raise ReplayExecutionError("DataHub recovery effect requires persisted artifacts")
    return job.artifacts


__all__ = ["DataHubRecoveryEffects"]
