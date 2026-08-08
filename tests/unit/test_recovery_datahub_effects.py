"""Concrete DataHub effect adapter tests for durable recovery."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

from glassbox_replay import RecoveryOperation, RecoveryStage, ReplayExecutionError
from glassbox_replay.datahub_effects import DataHubRecoveryEffects
from tests.unit.test_recovery_orchestration import _job


class FakeReceiptPipeline:
    def __init__(self) -> None:
        self.receipts: list[Any] = []

    def publish_compiled(self, receipt: Any, *, field_lineage: Any) -> Any:
        self.receipts.append((receipt, field_lineage))
        return SimpleNamespace(
            valid=True,
            state_readback_verified=True,
            datahub_write_performed=False,
            datahub=SimpleNamespace(
                valid=True,
                document_urn="urn:li:document:replay",
                aspect_names=("documentInfo",),
                emissions=2,
            ),
        )


class FakeSupersessionEmitter:
    def __init__(self) -> None:
        self.records: list[Any] = []

    def emit_verified(self, record: Any) -> Any:
        self.records.append(record)
        return SimpleNamespace(
            valid=True,
            document_urn="urn:li:document:supersession",
            aspect_names=("documentInfo",),
            emissions=2,
        )


class FakeClosureEmitter:
    def __init__(self) -> None:
        self.records: list[Any] = []

    def close_verified(self, closure: Any, supersession: Any) -> Any:
        self.records.append((closure, supersession))
        return SimpleNamespace(
            valid=True,
            incident_urn=closure.incident_urn,
            incident_aspects=("incidentInfo", "incidentKey"),
            emission_attempts=0,
        )


def test_datahub_recovery_effects_emit_only_persisted_artifacts() -> None:
    _source, _task, _trusted, artifacts, authorized = _job()
    job = replace(
        authorized,
        stage=RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
        stage_version=1,
        artifacts=artifacts,
    )
    receipt_pipeline = FakeReceiptPipeline()
    supersession_emitter = FakeSupersessionEmitter()
    closure_emitter = FakeClosureEmitter()
    effects = DataHubRecoveryEffects(
        receipt_pipeline,  # type: ignore[arg-type]
        supersession_emitter,  # type: ignore[arg-type]
        closure_emitter,  # type: ignore[arg-type]
        clock_iso=lambda: "2026-08-08T12:08:00Z",
    )

    replay = effects.publish_replay_receipt(job)
    supersession = effects.publish_supersession(job)
    closure = effects.close_incident(job)

    assert replay.valid and replay.operation is RecoveryOperation.PUBLISH_REPLAY_RECEIPT
    assert supersession.valid and supersession.operation is RecoveryOperation.PUBLISH_SUPERSESSION
    assert closure.valid and closure.operation is RecoveryOperation.CLOSE_INCIDENT
    assert replay.artifact_id == artifacts.replay_receipt["receipt_id"]
    assert supersession.artifact_id == artifacts.supersession.supersession_id
    assert closure.artifact_id == artifacts.closure.closure_id
    assert closure.emission_count == 0
    assert not replay.write_performed
    assert supersession.write_performed
    assert not closure.write_performed
    assert receipt_pipeline.receipts[0][0] == artifacts.replay_receipt
    assert supersession_emitter.records == [artifacts.supersession]
    assert closure_emitter.records == [(artifacts.closure, artifacts.supersession)]


def test_datahub_recovery_effects_fail_closed_on_missing_or_unverified_results() -> None:
    _source, _task, _trusted, artifacts, authorized = _job()
    pipeline = FakeReceiptPipeline()
    supersession = FakeSupersessionEmitter()
    closure = FakeClosureEmitter()
    effects = DataHubRecoveryEffects(
        pipeline,  # type: ignore[arg-type]
        supersession,  # type: ignore[arg-type]
        closure,  # type: ignore[arg-type]
    )
    with pytest.raises(ReplayExecutionError, match="persisted artifacts"):
        effects.publish_replay_receipt(authorized)

    job = replace(
        authorized,
        stage=RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
        stage_version=1,
        artifacts=artifacts,
    )
    pipeline.publish_compiled = lambda *args, **kwargs: SimpleNamespace(  # type: ignore[method-assign]
        valid=False
    )
    with pytest.raises(ReplayExecutionError, match="receipt publication"):
        effects.publish_replay_receipt(job)
    supersession.emit_verified = lambda _record: SimpleNamespace(  # type: ignore[method-assign]
        valid=False
    )
    with pytest.raises(ReplayExecutionError, match="supersession publication"):
        effects.publish_supersession(job)
    closure.close_verified = lambda *_args: SimpleNamespace(valid=False)  # type: ignore[method-assign]
    with pytest.raises(ReplayExecutionError, match="incident closure"):
        effects.close_incident(job)
