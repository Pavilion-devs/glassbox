"""Typed inputs and closed policy vocabulary for replay planning."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ReplayInputError(ValueError):
    """Raised when replay preparation input violates the closed contract."""


class ReplayMode(StrEnum):
    """The requested relationship between original and replay context."""

    PINNED = "PINNED"
    CORRECTED = "CORRECTED"
    COUNTERFACTUAL = "COUNTERFACTUAL"
    DRY = "DRY"


class ReplayDecision(StrEnum):
    """Deterministic policy outcome for one immutable replay bundle."""

    ALLOW = "ALLOW"
    ALLOW_WITH_RECEIPT = "ALLOW_WITH_RECEIPT"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"
    DRY_RUN_ONLY = "DRY_RUN_ONLY"
    BLOCK = "BLOCK"


class ReplayReason(StrEnum):
    """Stable reason codes emitted by replay policy version 1."""

    SOURCE_UNREPLAYABLE = "SOURCE_UNREPLAYABLE"
    SOURCE_NOT_EVALUATED = "SOURCE_NOT_EVALUATED"
    ACTION_OUTCOME_UNCERTAIN = "ACTION_OUTCOME_UNCERTAIN"
    ACTION_FAILED_OR_BLOCKED = "ACTION_FAILED_OR_BLOCKED"
    IRREVERSIBLE_ACTION = "IRREVERSIBLE_ACTION"
    UNKNOWN_ACTION_EFFECT = "UNKNOWN_ACTION_EFFECT"
    REVERSIBLE_ACTION = "REVERSIBLE_ACTION"
    IDEMPOTENCY_KEY_MISSING = "IDEMPOTENCY_KEY_MISSING"
    ROLLBACK_CONTRACT_MISSING = "ROLLBACK_CONTRACT_MISSING"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_INVALID = "APPROVAL_INVALID"
    RESOURCE_UNPINNED = "RESOURCE_UNPINNED"
    RESOURCE_UNAVAILABLE = "RESOURCE_UNAVAILABLE"
    CONTEXT_INCOMPLETE = "CONTEXT_INCOMPLETE"
    CONTEXT_REPLACEMENT_UNVERIFIED = "CONTEXT_REPLACEMENT_UNVERIFIED"
    ACTION_INPUT_REPLACEMENT_UNVERIFIED = "ACTION_INPUT_REPLACEMENT_UNVERIFIED"
    EXECUTION_INPUT_UNAVAILABLE = "EXECUTION_INPUT_UNAVAILABLE"
    FEATURE_FLAGS_UNPINNED = "FEATURE_FLAGS_UNPINNED"
    MODEL_CONFIG_UNPINNED = "MODEL_CONFIG_UNPINNED"
    MODEL_NONDETERMINISM_DISCLOSED = "MODEL_NONDETERMINISM_DISCLOSED"
    MODEL_DETERMINISM_UNKNOWN = "MODEL_DETERMINISM_UNKNOWN"
    DRY_MODE_REQUESTED = "DRY_MODE_REQUESTED"
    SAFE_READ_ONLY_REPLAY = "SAFE_READ_ONLY_REPLAY"


class ResourceKind(StrEnum):
    """Kinds of exact execution resources checked by the planner."""

    AGENT = "AGENT"
    WORKFLOW = "WORKFLOW"
    MODEL = "MODEL"
    SKILL = "SKILL"
    TOOL = "TOOL"


class ModelDeterminism(StrEnum):
    """Disclosure state for a pinned model invocation profile."""

    DETERMINISTIC = "DETERMINISTIC"
    NONDETERMINISTIC = "NONDETERMINISTIC"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class ContextReplacement:
    """Digest-only replacement for one original evidence item."""

    evidence_id: str
    representation_digest: str
    verification_authority: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.evidence_id, "evidence_id")
        _digest(self.representation_digest, "representation_digest")
        if self.verification_authority is not None:
            _nonempty(self.verification_authority, "verification_authority")


@dataclass(frozen=True)
class ActionInputReplacement:
    """Digest-only replacement for an action input derived from corrected evidence."""

    action_id: str
    input_digest: str
    evidence_ids: tuple[str, ...]
    verification_authority: str

    def __post_init__(self) -> None:
        _nonempty(self.action_id, "action_id")
        _digest(self.input_digest, "input_digest")
        if not self.evidence_ids:
            raise ReplayInputError("action input replacement requires evidence IDs")
        if len(self.evidence_ids) != len(set(self.evidence_ids)):
            raise ReplayInputError("action input replacement evidence IDs must be unique")
        for evidence_id in self.evidence_ids:
            _nonempty(evidence_id, "evidence_id")
        _nonempty(self.verification_authority, "verification_authority")


@dataclass(frozen=True)
class ModelReplayConfig:
    """Digest commitment for provider parameters needed by one model pin."""

    model_id: str
    provider_id: str
    parameters_digest: str
    determinism: ModelDeterminism
    verification_authority: str

    def __post_init__(self) -> None:
        _nonempty(self.model_id, "model_id")
        _nonempty(self.provider_id, "provider_id")
        _digest(self.parameters_digest, "parameters_digest")
        _nonempty(self.verification_authority, "verification_authority")

    def to_dict(self) -> dict[str, object]:
        return {
            "model_id": self.model_id,
            "provider_id": self.provider_id,
            "parameters_digest": _digest_object(self.parameters_digest),
            "determinism": self.determinism.value,
            "verification_authority": self.verification_authority,
        }


@dataclass(frozen=True)
class ReplaySupplement:
    """Authorized digest-only execution material absent from DBOM 0.1."""

    input_digest: str | None = None
    input_reference: str | None = None
    feature_flags_digest: str | None = None
    model_configs: tuple[ModelReplayConfig, ...] = ()

    def __post_init__(self) -> None:
        if self.input_digest is not None:
            _digest(self.input_digest, "input_digest")
        if self.input_reference is not None:
            _nonempty(self.input_reference, "input_reference")
        if (self.input_digest is None) != (self.input_reference is None):
            raise ReplayInputError("input_digest and input_reference must be configured together")
        if self.feature_flags_digest is not None:
            _digest(self.feature_flags_digest, "feature_flags_digest")
        ids = [item.model_id for item in self.model_configs]
        if len(ids) != len(set(ids)):
            raise ReplayInputError("model replay configs must have unique model IDs")

    def to_dict(self) -> dict[str, object]:
        return {
            "input_digest": _optional_digest_object(self.input_digest),
            "input_reference": self.input_reference,
            "feature_flags_digest": _optional_digest_object(self.feature_flags_digest),
            "model_configs": [
                item.to_dict()
                for item in sorted(self.model_configs, key=lambda item: item.model_id)
            ],
        }


@dataclass(frozen=True)
class ResourceAvailability:
    """Exact version and digest exposed by an isolated replay environment."""

    kind: ResourceKind
    resource_id: str
    version: str
    source_digest: str | None = None
    schema_digest: str | None = None
    rollback_contract_digest: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.resource_id, "resource_id")
        _nonempty(self.version, "version")
        for value, name in (
            (self.source_digest, "source_digest"),
            (self.schema_digest, "schema_digest"),
            (self.rollback_contract_digest, "rollback_contract_digest"),
        ):
            if value is not None:
                _digest(value, name)
        if self.kind is not ResourceKind.TOOL and (
            self.schema_digest is not None or self.rollback_contract_digest is not None
        ):
            raise ReplayInputError(
                "schema and rollback contract digests are valid only for TOOL resources"
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind.value,
            "resource_id": self.resource_id,
            "version": self.version,
            "source_digest": _optional_digest_object(self.source_digest),
            "schema_digest": _optional_digest_object(self.schema_digest),
            "rollback_contract_digest": _optional_digest_object(self.rollback_contract_digest),
        }


@dataclass(frozen=True)
class ResourceInventory:
    """Closed snapshot of resources available to an isolated replay worker."""

    resources: tuple[ResourceAvailability, ...]

    def __post_init__(self) -> None:
        identities = [(item.kind, item.resource_id) for item in self.resources]
        if len(identities) != len(set(identities)):
            raise ReplayInputError("resource inventory identities must be unique")

    def find(self, kind: ResourceKind, resource_id: str) -> ResourceAvailability | None:
        return next(
            (
                item
                for item in self.resources
                if item.kind is kind and item.resource_id == resource_id
            ),
            None,
        )


def _digest_object(value: str) -> dict[str, str]:
    return {"algorithm": "sha256", "value": value}


def _optional_digest_object(value: str | None) -> dict[str, str] | None:
    return None if value is None else _digest_object(value)


def _nonempty(value: str, name: str) -> None:
    if not value:
        raise ReplayInputError(f"{name} must be non-empty")


def _digest(value: str, name: str) -> None:
    if not _SHA256.fullmatch(value):
        raise ReplayInputError(f"{name} must be a lowercase SHA-256 digest")


__all__ = [
    "ActionInputReplacement",
    "ContextReplacement",
    "ModelDeterminism",
    "ModelReplayConfig",
    "ReplayDecision",
    "ReplayInputError",
    "ReplayMode",
    "ReplayReason",
    "ReplaySupplement",
    "ResourceAvailability",
    "ResourceInventory",
    "ResourceKind",
]
