"""Normalized runtime records shared by every instrumentation adapter."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import TypeAlias

JSONScalar: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONScalar | list["JSONValue"] | dict[str, "JSONValue"]
RUNTIME_EVENT_SPEC_VERSION = "0.1.0"


class ActionEffect(StrEnum):
    """Material side-effect classification used by DBOM 0.1."""

    READ_ONLY = "READ_ONLY"
    REVERSIBLE = "REVERSIBLE"
    IRREVERSIBLE = "IRREVERSIBLE"
    UNKNOWN_EFFECT = "UNKNOWN_EFFECT"


class ActionStatus(StrEnum):
    """Action lifecycle status used by DBOM 0.1."""

    ATTEMPTED = "ATTEMPTED"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class EvidenceRole(StrEnum):
    """How an evidence item influenced an agent decision."""

    INPUT = "INPUT"
    REFERENCE = "REFERENCE"
    CONSTRAINT = "CONSTRAINT"
    POLICY = "POLICY"
    MEMORY = "MEMORY"
    OUTPUT_TARGET = "OUTPUT_TARGET"


class EvidenceState(StrEnum):
    """Strength and origin of an evidence claim."""

    OBSERVED = "OBSERVED"
    DECLARED = "DECLARED"
    INFERRED = "INFERRED"
    UNKNOWN = "UNKNOWN"


class EventKind(StrEnum):
    """Stable event names emitted by the runtime SDK."""

    RUN_STARTED = "glassbox.run.started"
    RUN_FINISHED = "glassbox.run.finished"
    EVIDENCE_OBSERVED = "glassbox.evidence.observed"
    ACTION_ATTEMPTED = "glassbox.action.attempted"
    ACTION_FINISHED = "glassbox.action.finished"


class RunStatus(StrEnum):
    """Terminal run status used by DBOM 0.1."""

    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    ABSTAINED = "ABSTAINED"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True)
class RunContext:
    """Correlation identifiers for one agent or workflow invocation."""

    run_id: str
    trace_id: str
    span_id: str
    parent_run_id: str | None
    parent_span_id: str | None
    agent_id: str
    agent_version: str | None
    workflow_id: str
    workflow_version: str | None


@dataclass(frozen=True)
class ActionObservation:
    """Framework-neutral, privacy-safe tool execution evidence."""

    tool_id: str
    effect: ActionEffect
    status: ActionStatus
    input_digest: str
    output_digest: str | None
    idempotency_key: str | None
    approval_id: str | None
    error_type: str | None = None
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def attributes(self) -> dict[str, JSONValue]:
        """Return the canonical event attributes for this observation."""

        return {
            "tool.id": self.tool_id,
            "action.effect": self.effect.value,
            "action.status": self.status.value,
            "action.input_digest": self.input_digest,
            "action.output_digest": self.output_digest,
            "action.idempotency_key": self.idempotency_key,
            "action.approval_id": self.approval_id,
            "error.type": self.error_type,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class ActionToken:
    """Privacy-safe handle joining a tool start callback to its terminal callback."""

    run: RunContext
    span_id: str
    tool_id: str
    effect: ActionEffect
    input_digest: str
    idempotency_key: str | None
    approval_id: str | None
    metadata: dict[str, JSONValue] = field(default_factory=dict)


@dataclass(frozen=True)
class EvidenceObservation:
    """Framework-neutral evidence claim with explicit epistemic state."""

    entity_type: str
    datahub_urn: str | None
    schema_field_urn: str | None
    state: EvidenceState
    role: EvidenceRole
    representation_digest: str | None
    capture_method: str
    rule_id: str | None
    confidence: float | None
    metadata: dict[str, JSONValue] = field(default_factory=dict)

    def attributes(self) -> dict[str, JSONValue]:
        """Return the canonical event attributes for this observation."""

        return {
            "evidence.entity_type": self.entity_type,
            "datahub.urn": self.datahub_urn,
            "datahub.schema_field_urn": self.schema_field_urn,
            "evidence.state": self.state.value,
            "evidence.role": self.role.value,
            "evidence.representation_digest": self.representation_digest,
            "evidence.capture_method": self.capture_method,
            "evidence.rule_id": self.rule_id,
            "evidence.confidence": self.confidence,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class RuntimeEvent:
    """An immutable normalized event suitable for OTLP or local collection."""

    sequence: int
    occurred_at: str
    kind: EventKind
    run: RunContext
    span_id: str
    parent_span_id: str | None
    attributes: dict[str, JSONValue]

    def to_dict(self) -> dict[str, JSONValue]:
        """Serialize without exposing implementation objects."""

        return {
            "spec_version": RUNTIME_EVENT_SPEC_VERSION,
            "sequence": self.sequence,
            "occurred_at": self.occurred_at,
            "kind": self.kind.value,
            "trace_id": self.run.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id,
            "run_id": self.run.run_id,
            "parent_run_id": self.run.parent_run_id,
            "agent.id": self.run.agent_id,
            "agent.version": self.run.agent_version,
            "workflow.id": self.run.workflow_id,
            "workflow.version": self.run.workflow_version,
            "attributes": self.attributes,
        }
