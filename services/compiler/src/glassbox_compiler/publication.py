"""Fail-closed publication of compiled receipts into shared state and DataHub."""

from __future__ import annotations

import copy
import os
import re
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Protocol

from glassbox.models import RuntimeEvent
from glassbox_compiler.compiler import CompilationProfile, compile_events
from glassbox_compiler.otlp import compile_otlp_json
from glassbox_datahub import (
    ReceiptEmissionError,
    ReceiptEmissionReport,
    ReceiptReadbackReport,
)
from glassbox_dbom.canonical import canonicalize
from glassbox_dbom.errors import CanonicalizationError
from glassbox_dbom.trust import SignerTrustMode, SignerTrustPolicy
from glassbox_invalidation import (
    OutboxStatus,
    ReceiptPublicationEvidence,
    ReceiptPublicationTask,
    TransactionalStoreError,
)
from glassbox_policy import FieldLineageProof, PolicyInputError

_ENVIRONMENT_VARIABLE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_POSTGRES_SCHEMA = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


class ReceiptStateRegistry(Protocol):
    """Minimum shared-state contract required by live receipt publication."""

    def register(
        self,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
        superseded_by: str | None = None,
    ) -> bool: ...

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None: ...

    def get_receipt_publication_task(self, receipt_id: str) -> ReceiptPublicationTask | None: ...

    def list_receipt_publication_tasks(self) -> tuple[ReceiptPublicationTask, ...]: ...

    def claim_receipt_publication(
        self,
        receipt_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> ReceiptPublicationTask | None: ...

    def release_receipt_publication(
        self, receipt_id: str, *, worker_id: str, error_type: str
    ) -> None: ...

    def complete_receipt_publication(
        self,
        receipt_id: str,
        evidence: ReceiptPublicationEvidence,
        *,
        worker_id: str,
    ) -> bool: ...


class VerifiedReceiptPublisher(Protocol):
    """Transport that verifies and directly reads back a governed receipt."""

    def emit_verified(
        self,
        receipt: Mapping[str, Any],
        *,
        trust_mode: SignerTrustMode = SignerTrustMode.ADMISSION,
    ) -> ReceiptEmissionReport: ...

    def verify_published(
        self,
        receipt: Mapping[str, Any],
        *,
        document_urn: str,
        aspect_names: tuple[str, ...],
    ) -> ReceiptReadbackReport: ...


class PublicationStage(StrEnum):
    """Closed failure stages safe to expose without transport details."""

    STATE_REGISTRATION = "STATE_REGISTRATION"
    STATE_READBACK = "STATE_READBACK"
    DATAHUB_PUBLICATION = "DATAHUB_PUBLICATION"
    DATAHUB_READBACK = "DATAHUB_READBACK"
    PUBLICATION_LEASE = "PUBLICATION_LEASE"


class RegistrationDisposition(StrEnum):
    """Whether this run inserted or idempotently reused the receipt record."""

    INSERTED = "INSERTED"
    REUSED = "REUSED"


class LiveReceiptPipelineError(RuntimeError):
    """Bounded stage failure that keeps driver and server details out of reports."""

    def __init__(self, stage: PublicationStage, failure_type: str) -> None:
        self.stage = stage
        self.failure_type = failure_type
        super().__init__(f"live receipt pipeline failed at {stage.value} ({failure_type})")


class LiveReceiptConfigurationError(ValueError):
    """Raised for bounded shared-state configuration failures."""


@dataclass(frozen=True)
class PostgresReceiptStateConfig:
    """Secret-indirect connection settings for the existing Action state schema."""

    dsn_environment_variable: str = "GLASSBOX_STATE_POSTGRES_DSN"
    schema: str = "glassbox"
    connect_timeout_seconds: float = 10.0
    signer_trust_policy: SignerTrustPolicy | None = None

    def __post_init__(self) -> None:
        if not _ENVIRONMENT_VARIABLE.fullmatch(self.dsn_environment_variable):
            raise LiveReceiptConfigurationError(
                "PostgreSQL DSN environment-variable name is invalid"
            )
        if not _POSTGRES_SCHEMA.fullmatch(self.schema):
            raise LiveReceiptConfigurationError("PostgreSQL state schema name is invalid")
        if self.connect_timeout_seconds <= 0:
            raise LiveReceiptConfigurationError("PostgreSQL connect timeout must be positive")

    def connect(self) -> ReceiptStateRegistry:
        """Open the initialized schema in runtime mode without issuing DDL."""

        dsn = os.getenv(self.dsn_environment_variable)
        if dsn is None or not dsn:
            raise LiveReceiptConfigurationError(
                "configured PostgreSQL DSN environment variable is unset"
            )
        try:
            from glassbox_invalidation.postgres_store import PostgresInvalidationStore
        except ImportError as exc:  # pragma: no cover - exercised without postgres extra
            raise LiveReceiptConfigurationError(
                "PostgreSQL live state requires the 'postgres' optional dependency"
            ) from exc
        return PostgresInvalidationStore(
            dsn,
            schema=self.schema,
            require_signature=True,
            signer_trust_policy=self.signer_trust_policy,
            connect_timeout_seconds=self.connect_timeout_seconds,
            initialize_schema=False,
        )


@dataclass(frozen=True)
class LiveReceiptPublicationReport:
    """Raw-free proof of shared-state registration and DataHub readback."""

    receipt_id: str
    registration: RegistrationDisposition
    state_readback_verified: bool
    field_lineage: FieldLineageProof
    datahub: ReceiptEmissionReport
    publication_attempt_count: int
    datahub_write_performed: bool

    @property
    def valid(self) -> bool:
        return self.state_readback_verified and self.datahub.valid

    def to_dict(self) -> dict[str, object]:
        return {
            "valid": self.valid,
            "receipt_id": self.receipt_id,
            "state": {
                "registration": self.registration.value,
                "readback_verified": self.state_readback_verified,
                "field_lineage": {
                    "coverage": self.field_lineage.coverage.value,
                    "rule_id": self.field_lineage.rule_id,
                    "wildcard_query": self.field_lineage.wildcard_query,
                },
            },
            "datahub": self.datahub.to_dict(),
            "publication": {
                "attempt_count": self.publication_attempt_count,
                "datahub_write_performed": self.datahub_write_performed,
            },
            "raw_content_returned": False,
        }


class ReceiptPublicationWorker:
    """Lease, publish, and seal one durable receipt-publication obligation."""

    def __init__(
        self,
        registry: ReceiptStateRegistry,
        publisher: VerifiedReceiptPublisher,
        *,
        worker_id: str | None = None,
        lease_duration_ms: int = 60_000,
        clock_ms: Callable[[], int] | None = None,
    ) -> None:
        if lease_duration_ms <= 0:
            raise LiveReceiptConfigurationError("publication lease duration must be positive")
        self._registry = registry
        self._publisher = publisher
        self.worker_id = worker_id or f"receipt-publisher-{uuid.uuid4().hex}"
        if not self.worker_id:
            raise LiveReceiptConfigurationError("publication worker ID must be non-empty")
        self.lease_duration_ms = lease_duration_ms
        self._clock_ms = clock_ms or (lambda: time.time_ns() // 1_000_000)

    def process(self, receipt_id: str) -> tuple[ReceiptEmissionReport, int, bool]:
        """Publish pending work or verify completed work with zero writes."""

        try:
            task = self._registry.get_receipt_publication_task(receipt_id)
            receipt = self._registry.get_receipt(receipt_id)
        except TransactionalStoreError as exc:
            raise LiveReceiptPipelineError(
                PublicationStage.STATE_READBACK, type(exc).__name__
            ) from exc
        if task is None or receipt is None:
            raise LiveReceiptPipelineError(
                PublicationStage.STATE_READBACK, "PublicationObligationMissing"
            )
        if task.status is OutboxStatus.COMPLETED:
            evidence = task.publication_evidence
            if evidence is None:  # pragma: no cover - store decoder guarantees this
                raise LiveReceiptPipelineError(
                    PublicationStage.STATE_READBACK, "PublicationEvidenceMissing"
                )
            try:
                readback = self._publisher.verify_published(
                    receipt,
                    document_urn=evidence.document_urn,
                    aspect_names=evidence.aspect_names,
                )
            except ReceiptEmissionError as exc:
                raise LiveReceiptPipelineError(
                    PublicationStage.DATAHUB_READBACK, type(exc).__name__
                ) from exc
            if not readback.valid or readback.receipt_id != receipt_id:
                raise LiveReceiptPipelineError(
                    PublicationStage.DATAHUB_READBACK, "ReceiptReadbackMismatch"
                )
            return (
                ReceiptEmissionReport(
                    receipt_id=receipt_id,
                    document_urn=evidence.document_urn,
                    aspect_names=evidence.aspect_names,
                    emissions=evidence.emission_count,
                ),
                task.attempt_count,
                False,
            )

        try:
            claimed = self._registry.claim_receipt_publication(
                receipt_id,
                worker_id=self.worker_id,
                now_ms=self._clock_ms(),
                lease_duration_ms=self.lease_duration_ms,
            )
        except TransactionalStoreError as exc:
            raise LiveReceiptPipelineError(
                PublicationStage.PUBLICATION_LEASE, type(exc).__name__
            ) from exc
        if claimed is None:
            raise LiveReceiptPipelineError(
                PublicationStage.PUBLICATION_LEASE, "PublicationLeaseUnavailable"
            )
        try:
            emission = self._publisher.emit_verified(
                receipt,
                trust_mode=SignerTrustMode.HISTORICAL,
            )
            if not emission.valid or emission.receipt_id != receipt_id:
                raise ReceiptEmissionError("receipt emission evidence is invalid")
            evidence = ReceiptPublicationEvidence(
                document_urn=emission.document_urn,
                aspect_names=emission.aspect_names,
                emission_count=emission.emissions,
            )
            self._registry.complete_receipt_publication(
                receipt_id, evidence, worker_id=self.worker_id
            )
        except ReceiptEmissionError as exc:
            try:
                self._registry.release_receipt_publication(
                    receipt_id,
                    worker_id=self.worker_id,
                    error_type=type(exc).__name__,
                )
            except TransactionalStoreError as release_exc:
                raise LiveReceiptPipelineError(
                    PublicationStage.PUBLICATION_LEASE, type(release_exc).__name__
                ) from release_exc
            raise LiveReceiptPipelineError(
                PublicationStage.DATAHUB_PUBLICATION, type(exc).__name__
            ) from exc
        except TransactionalStoreError as exc:
            raise LiveReceiptPipelineError(
                PublicationStage.PUBLICATION_LEASE, type(exc).__name__
            ) from exc
        return emission, claimed.attempt_count, True

    def drain(self, *, limit: int = 100) -> tuple[LiveReceiptPipelineError | None, ...]:
        """Attempt bounded recovery work and return one raw-free outcome per candidate."""

        if limit <= 0:
            raise LiveReceiptConfigurationError("publication drain limit must be positive")
        outcomes: list[LiveReceiptPipelineError | None] = []
        for task in self._registry.list_receipt_publication_tasks():
            if len(outcomes) >= limit:
                break
            if task.status is OutboxStatus.COMPLETED:
                continue
            try:
                self.process(task.receipt_id)
            except LiveReceiptPipelineError as exc:
                outcomes.append(exc)
            else:
                outcomes.append(None)
        return tuple(outcomes)


class LiveReceiptPipeline:
    """Register a signed receipt before publishing its governed DataHub projection."""

    def __init__(
        self,
        registry: ReceiptStateRegistry,
        publisher: VerifiedReceiptPublisher,
        *,
        worker_id: str | None = None,
        lease_duration_ms: int = 60_000,
    ) -> None:
        self._registry = registry
        self._worker = ReceiptPublicationWorker(
            registry,
            publisher,
            worker_id=worker_id,
            lease_duration_ms=lease_duration_ms,
        )

    def compile_and_publish(
        self,
        events: Sequence[RuntimeEvent],
        *,
        profile: CompilationProfile,
        field_lineage: FieldLineageProof | None = None,
    ) -> tuple[dict[str, Any], LiveReceiptPublicationReport]:
        """Compile one run, then synchronously register and publish its receipt."""

        receipt = compile_events(events, profile=profile)
        return receipt, self.publish_compiled(receipt, field_lineage=field_lineage)

    def compile_otlp_and_publish(
        self,
        payload: Mapping[str, Any],
        *,
        profile: CompilationProfile,
        run_span_id: str | None = None,
        max_spans: int = 10_000,
        field_lineage: FieldLineageProof | None = None,
    ) -> tuple[dict[str, Any], LiveReceiptPublicationReport]:
        """Strictly compile one OTLP run, then register and publish it synchronously."""

        receipt = compile_otlp_json(
            payload,
            profile=profile,
            run_span_id=run_span_id,
            max_spans=max_spans,
        )
        return receipt, self.publish_compiled(receipt, field_lineage=field_lineage)

    def publish_compiled(
        self,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
    ) -> LiveReceiptPublicationReport:
        """Register, reread, emit, and directly verify one already compiled receipt."""

        material = copy.deepcopy(dict(receipt))
        receipt_id = _receipt_id(material)
        proof = field_lineage or FieldLineageProof()
        try:
            inserted = self._registry.register(material, field_lineage=proof)
        except (PolicyInputError, TransactionalStoreError) as exc:
            raise LiveReceiptPipelineError(
                PublicationStage.STATE_REGISTRATION,
                type(exc).__name__,
            ) from exc

        try:
            stored = self._registry.get_receipt(receipt_id)
        except TransactionalStoreError as exc:
            raise LiveReceiptPipelineError(
                PublicationStage.STATE_READBACK,
                type(exc).__name__,
            ) from exc
        try:
            readback_matches = stored is not None and canonicalize(stored) == canonicalize(material)
        except CanonicalizationError as exc:
            raise LiveReceiptPipelineError(
                PublicationStage.STATE_READBACK,
                type(exc).__name__,
            ) from exc
        if not readback_matches:
            raise LiveReceiptPipelineError(
                PublicationStage.STATE_READBACK,
                "ReceiptReadbackMismatch",
            )

        emission, attempt_count, write_performed = self._worker.process(receipt_id)

        return LiveReceiptPublicationReport(
            receipt_id=receipt_id,
            registration=(
                RegistrationDisposition.INSERTED if inserted else RegistrationDisposition.REUSED
            ),
            state_readback_verified=True,
            field_lineage=proof,
            datahub=emission,
            publication_attempt_count=attempt_count,
            datahub_write_performed=write_performed,
        )


def _receipt_id(receipt: Mapping[str, Any]) -> str:
    value = receipt.get("receipt_id")
    if not isinstance(value, str) or not value:
        raise LiveReceiptPipelineError(
            PublicationStage.STATE_REGISTRATION,
            "InvalidReceiptIdentity",
        )
    return value


__all__ = [
    "LiveReceiptConfigurationError",
    "LiveReceiptPipeline",
    "LiveReceiptPipelineError",
    "LiveReceiptPublicationReport",
    "PostgresReceiptStateConfig",
    "PublicationStage",
    "ReceiptStateRegistry",
    "RegistrationDisposition",
    "VerifiedReceiptPublisher",
]
