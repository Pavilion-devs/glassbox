"""Content-addressed authorization to resolve one recovered DataHub incident."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from glassbox_dbom import verify_receipt
from glassbox_dbom.canonical import canonicalize
from glassbox_invalidation import OutboxTask
from glassbox_replay.execution import ReadOnlyReplayExecution, ReplayExecutionError
from glassbox_replay.recovery import (
    RecoveryAuthorization,
    verify_recovery_authorization,
)
from glassbox_replay.supersession import SupersessionRecord

RECOVERY_CLOSURE_POLICY_VERSION = "glassbox.recovery-closure.v1"
_CLOSURE_DOMAIN = b"glassbox.recovery.closure.v1\0"


@dataclass(frozen=True)
class RecoveryClosureRecord:
    """Immutable authority to resolve one incident after an isolated supersession."""

    closure_id: str
    campaign_id: str
    incident_urn: str
    authorization_id: str
    source_receipt_id: str
    replay_receipt_id: str
    bundle_id: str
    execution_id: str
    supersession_id: str
    diff_id: str
    isolation_attestation_ids: tuple[str, ...]
    closed_at: str
    policy_version: str = RECOVERY_CLOSURE_POLICY_VERSION
    resolution: str = "RECOVERED_BY_VERIFIED_ISOLATED_REPLAY"

    @property
    def valid(self) -> bool:
        return self.closure_id == _closure_id(self._material())

    def to_dict(self) -> dict[str, Any]:
        return {
            "closure_id": self.closure_id,
            **self._material(),
            "raw_values_retained": False,
        }

    def _material(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id,
            "incident_urn": self.incident_urn,
            "authorization_id": self.authorization_id,
            "source_receipt_id": self.source_receipt_id,
            "replay_receipt_id": self.replay_receipt_id,
            "bundle_id": self.bundle_id,
            "execution_id": self.execution_id,
            "supersession_id": self.supersession_id,
            "diff_id": self.diff_id,
            "isolation_attestation_ids": list(self.isolation_attestation_ids),
            "closed_at": self.closed_at,
            "policy_version": self.policy_version,
            "resolution": self.resolution,
        }


def create_recovery_closure_record(
    authorization: RecoveryAuthorization,
    task: OutboxTask,
    source_receipt: Mapping[str, Any],
    replay_receipt: Mapping[str, Any],
    bundle: Mapping[str, Any],
    *,
    execution: ReadOnlyReplayExecution,
    supersession: SupersessionRecord,
    evaluated_at: str,
    trusted_signer_fingerprints: Mapping[str, str],
    closed_at: str,
) -> RecoveryClosureRecord:
    """Recheck the full chain and authorize closure only after isolated recovery."""

    closed = _timestamp(closed_at, "closed_at")
    authorization_report = verify_recovery_authorization(
        authorization,
        task,
        source_receipt,
        bundle,
        evaluated_at=evaluated_at,
        trusted_signer_fingerprints=trusted_signer_fingerprints,
    )
    if not authorization_report.valid:
        raise ReplayExecutionError("recovery authorization does not permit incident closure")
    replay_report = verify_receipt(replay_receipt, require_signature=True)
    if not replay_report.valid:
        raise ReplayExecutionError("replay receipt verification failed before incident closure")
    if not execution.valid or execution.status != "SUCCEEDED":
        raise ReplayExecutionError("incident closure requires a valid successful execution")
    attestations = tuple(
        action.isolation_attestation for action in execution.actions if action.status == "SUCCEEDED"
    )
    if (
        not attestations
        or len(attestations) != len(execution.actions)
        or any(item is None or not item.valid for item in attestations)
    ):
        raise ReplayExecutionError("incident closure requires isolated execution attestations")
    if not supersession.valid:
        raise ReplayExecutionError("incident closure requires a valid supersession")
    if closed < _timestamp(supersession.created_at, "supersession created_at"):
        raise ReplayExecutionError("incident closure cannot precede supersession")

    source_id = _text(source_receipt, "receipt_id")
    replay_id = _text(replay_receipt, "receipt_id")
    bundle_id = _text(bundle, "bundle_id")
    if (
        authorization.campaign_id != task.campaign.campaign_id
        or authorization.incident_urn != task.campaign.incident_urn
        or authorization.source_receipt_id != source_id
        or authorization.bundle_id != bundle_id
    ):
        raise ReplayExecutionError("closure authorization binding is invalid")
    if (
        execution.source_receipt_id != source_id
        or execution.bundle_id != bundle_id
        or supersession.source_receipt_id != source_id
        or supersession.replay_receipt_id != replay_id
        or supersession.bundle_id != bundle_id
        or supersession.execution_id != execution.execution_id
    ):
        raise ReplayExecutionError("closure replay and supersession binding is invalid")
    extensions = _mapping(replay_receipt, "extensions")
    expected_attestations = tuple(item.attestation_id for item in attestations if item is not None)
    if (
        extensions.get("glassbox.replay.source_receipt_id") != source_id
        or extensions.get("glassbox.replay.bundle_id") != bundle_id
        or extensions.get("glassbox.replay.execution_id") != execution.execution_id
        or tuple(extensions.get("glassbox.replay.isolation_attestation_ids", ()))
        != expected_attestations
    ):
        raise ReplayExecutionError("replay receipt isolation or execution binding is invalid")

    material: dict[str, Any] = {
        "campaign_id": authorization.campaign_id,
        "incident_urn": authorization.incident_urn,
        "authorization_id": authorization.authorization_id,
        "source_receipt_id": source_id,
        "replay_receipt_id": replay_id,
        "bundle_id": bundle_id,
        "execution_id": execution.execution_id,
        "supersession_id": supersession.supersession_id,
        "diff_id": supersession.diff_id,
        "isolation_attestation_ids": list(expected_attestations),
        "closed_at": closed_at,
        "policy_version": RECOVERY_CLOSURE_POLICY_VERSION,
        "resolution": "RECOVERED_BY_VERIFIED_ISOLATED_REPLAY",
    }
    return RecoveryClosureRecord(
        closure_id=_closure_id(material),
        campaign_id=authorization.campaign_id,
        incident_urn=authorization.incident_urn,
        authorization_id=authorization.authorization_id,
        source_receipt_id=source_id,
        replay_receipt_id=replay_id,
        bundle_id=bundle_id,
        execution_id=execution.execution_id,
        supersession_id=supersession.supersession_id,
        diff_id=supersession.diff_id,
        isolation_attestation_ids=expected_attestations,
        closed_at=closed_at,
    )


def _closure_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_CLOSURE_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:recovery-closure:sha256:{digest}"


def _timestamp(value: str, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReplayExecutionError(f"{name} must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ReplayExecutionError(f"{name} must include a timezone offset")
    return parsed


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayExecutionError(f"{key} must be a non-empty string")
    return selected


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise ReplayExecutionError(f"{key} must be an object")
    return selected


__all__ = [
    "RECOVERY_CLOSURE_POLICY_VERSION",
    "RecoveryClosureRecord",
    "create_recovery_closure_record",
]
