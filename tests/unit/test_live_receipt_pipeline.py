"""Live compiler-to-state-to-DataHub receipt publication tests."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from examples.deterministic_pricing_agent import ORDERS_URN, build_pricing_agent

from glassbox import GlassBox, InMemorySink, RuntimeEvent
from glassbox_compiler import (
    CompilationProfile,
    ComponentDeclaration,
    Environment,
    LiveReceiptConfigurationError,
    LiveReceiptPipeline,
    LiveReceiptPipelineError,
    PostgresReceiptStateConfig,
    PublicationStage,
    RegistrationDisposition,
)
from glassbox_datahub import ReceiptEmitter, receipt_document_urn
from glassbox_dbom import SigningKey
from glassbox_invalidation import OutboxStatus, SQLiteInvalidationStore, TransactionalStoreError
from glassbox_policy import FieldCoverage, FieldLineageProof


class FakeReceiptBackend:
    """Deterministic DataHub boundary with configurable direct readback."""

    def __init__(self, *, aspects: tuple[str, ...] = ("documentInfo",)) -> None:
        self.aspects = aspects
        self.receipts: list[Mapping[str, Any]] = []

    def upsert_receipt(self, receipt: Mapping[str, Any]) -> str:
        self.receipts.append(receipt)
        return receipt_document_urn(str(receipt["receipt_id"]))

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        del urn
        return self.aspects


class FailingRegistry:
    """State boundary proving that sensitive driver text is not surfaced."""

    def register(
        self,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
        superseded_by: str | None = None,
    ) -> bool:
        del receipt, field_lineage, superseded_by
        raise TransactionalStoreError("postgresql://operator:secret@private-host/database")

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None:
        del receipt_id
        raise AssertionError("readback must not run after registration failure")


def _events() -> tuple[RuntimeEvent, ...]:
    sink = InMemorySink()
    agent = build_pricing_agent(GlassBox(sink))
    agent("synthetic-private-customer")
    return sink.events


def _profile(*, signed: bool = True) -> CompilationProfile:
    keys = (SigningKey("live-receipt-test", Ed25519PrivateKey.generate()),) if signed else ()
    return CompilationProfile(
        environment=Environment.DEV,
        output_kind="pricing-recommendation",
        output_mime_type="application/json",
        agent=ComponentDeclaration(
            id="glassbox.demo.pricing-agent",
            version="0.1.0",
        ),
        signing_keys=keys,
    )


def _store(tmp_path: Path) -> SQLiteInvalidationStore:
    return SQLiteInvalidationStore(tmp_path / "live-receipts.sqlite3")


def test_live_pipeline_compiles_registers_rereads_and_publishes(tmp_path: Path) -> None:
    state = _store(tmp_path)
    backend = FakeReceiptBackend()
    lineage = FieldLineageProof(
        coverage=FieldCoverage.COMPLETE,
        rule_id="glassbox.runtime-field-observation.v1",
        wildcard_query=False,
    )

    receipt, report = LiveReceiptPipeline(
        state,
        ReceiptEmitter(backend),
    ).compile_and_publish(
        _events(),
        profile=_profile(),
        field_lineage=lineage,
    )

    assert report.valid
    assert report.registration is RegistrationDisposition.INSERTED
    assert report.datahub_write_performed
    assert report.publication_attempt_count == 1
    assert report.state_readback_verified
    assert report.field_lineage == lineage
    assert state.get_receipt(receipt["receipt_id"]) == receipt
    assert state.all_profiles()[0].field_lineage == lineage
    assert state.all_profiles()[0].dependencies[0].datahub_urn == ORDERS_URN
    assert len(backend.receipts) == 2
    projection = report.to_dict()
    assert projection["raw_content_returned"] is False
    assert "synthetic-private-customer" not in repr(projection)


def test_default_lineage_is_conservative_and_retry_reuses_registration(
    tmp_path: Path,
) -> None:
    state = _store(tmp_path)
    first_backend = FakeReceiptBackend(aspects=())
    pipeline = LiveReceiptPipeline(state, ReceiptEmitter(first_backend))

    with pytest.raises(LiveReceiptPipelineError) as failure:
        receipt, _ = pipeline.compile_and_publish(_events(), profile=_profile())

    assert failure.value.stage is PublicationStage.DATAHUB_PUBLICATION
    stored = state.all_profiles()
    assert len(stored) == 1
    assert stored[0].field_lineage.coverage is FieldCoverage.NONE
    task = state.get_receipt_publication_task(stored[0].receipt_id)
    assert task is not None
    assert task.status is OutboxStatus.READY
    assert task.attempt_count == 1
    assert task.last_error_type == "ReceiptEmissionError"

    receipt = state.get_receipt(stored[0].receipt_id)
    assert receipt is not None
    retry_backend = FakeReceiptBackend()
    report = LiveReceiptPipeline(state, ReceiptEmitter(retry_backend)).publish_compiled(receipt)

    assert report.valid
    assert report.registration is RegistrationDisposition.REUSED
    assert report.datahub_write_performed
    assert report.publication_attempt_count == 2
    assert len(retry_backend.receipts) == 2

    completed_retry = LiveReceiptPipeline(state, ReceiptEmitter(retry_backend)).publish_compiled(
        receipt
    )
    assert completed_retry.valid
    assert completed_retry.registration is RegistrationDisposition.REUSED
    assert not completed_retry.datahub_write_performed
    assert completed_retry.publication_attempt_count == 2
    assert len(retry_backend.receipts) == 2


def test_state_conflict_and_unsigned_receipt_block_datahub_mutation(tmp_path: Path) -> None:
    state = _store(tmp_path)
    first_backend = FakeReceiptBackend()
    unsigned_pipeline = LiveReceiptPipeline(state, ReceiptEmitter(first_backend))

    with pytest.raises(LiveReceiptPipelineError) as unsigned:
        unsigned_pipeline.compile_and_publish(_events(), profile=_profile(signed=False))
    assert unsigned.value.stage is PublicationStage.STATE_REGISTRATION
    assert first_backend.receipts == []

    signed_receipt, _ = LiveReceiptPipeline(
        state,
        ReceiptEmitter(FakeReceiptBackend()),
    ).compile_and_publish(_events(), profile=_profile())
    conflict_backend = FakeReceiptBackend()
    with pytest.raises(LiveReceiptPipelineError) as conflict:
        LiveReceiptPipeline(state, ReceiptEmitter(conflict_backend)).publish_compiled(
            signed_receipt,
            field_lineage=FieldLineageProof(
                coverage=FieldCoverage.COMPLETE,
                rule_id="glassbox.conflicting-lineage.v1",
                wildcard_query=False,
            ),
        )

    assert conflict.value.stage is PublicationStage.STATE_REGISTRATION
    assert conflict_backend.receipts == []


def test_registration_failure_reports_only_bounded_type() -> None:
    backend = FakeReceiptBackend()
    pipeline = LiveReceiptPipeline(FailingRegistry(), ReceiptEmitter(backend))

    with pytest.raises(LiveReceiptPipelineError) as failure:
        pipeline.compile_and_publish(_events(), profile=_profile())

    assert failure.value.stage is PublicationStage.STATE_REGISTRATION
    assert failure.value.failure_type == "TransactionalStoreError"
    assert "secret" not in str(failure.value)
    assert "private-host" not in str(failure.value)
    assert backend.receipts == []


@pytest.mark.parametrize(
    "configuration",
    [
        {"dsn_environment_variable": "INVALID-NAME"},
        {"schema": "Invalid-Schema"},
        {"connect_timeout_seconds": 0},
    ],
)
def test_postgres_registration_configuration_fails_closed(
    configuration: dict[str, object],
) -> None:
    with pytest.raises(LiveReceiptConfigurationError):
        PostgresReceiptStateConfig(**configuration)  # type: ignore[arg-type]


def test_postgres_registration_loads_only_a_named_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GLASSBOX_LIVE_RECEIPT_TEST_DSN", raising=False)
    configuration = PostgresReceiptStateConfig(
        dsn_environment_variable="GLASSBOX_LIVE_RECEIPT_TEST_DSN",
    )

    with pytest.raises(LiveReceiptConfigurationError, match="environment variable is unset"):
        configuration.connect()

    assert "postgresql://" not in repr(configuration)
