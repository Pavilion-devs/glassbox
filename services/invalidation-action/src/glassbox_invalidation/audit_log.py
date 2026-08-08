"""Checksummed, append-only audit records for invalidation campaigns."""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from threading import Lock
from typing import Any, Protocol

from glassbox_dbom.canonical import canonicalize
from glassbox_policy import InvalidationCampaign

_AUDIT_DOMAIN = b"glassbox.invalidation-audit.v1\0"


class AuditLogError(RuntimeError):
    """Raised when the append-only campaign audit cannot be trusted."""


class AuditPhase(StrEnum):
    """Stable campaign lifecycle checkpoints."""

    CLASSIFIED = "CLASSIFIED"
    DATAHUB_FAILED = "DATAHUB_FAILED"
    DATAHUB_VERIFIED = "DATAHUB_VERIFIED"
    OWNER_ROUTING_FAILED = "OWNER_ROUTING_FAILED"
    OWNER_ROUTING_ACCEPTED = "OWNER_ROUTING_ACCEPTED"


@dataclass(frozen=True)
class CampaignAuditRecord:
    """Digest-only audit event with a deterministic retry identity."""

    record_id: str
    campaign_id: str
    change_event_id: str
    incident_urn: str
    policy_version: str
    phase: AuditPhase
    impact_counts: tuple[tuple[str, int], ...]
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_id": self.record_id,
            "campaign_id": self.campaign_id,
            "change_event_id": self.change_event_id,
            "incident_urn": self.incident_urn,
            "policy_version": self.policy_version,
            "phase": self.phase.value,
            "impact_counts": dict(self.impact_counts),
            "detail": self.detail,
        }


class CampaignAuditSink(Protocol):
    """Idempotent audit boundary used by the invalidation action."""

    def record(self, item: CampaignAuditRecord) -> bool: ...


def campaign_audit_record(
    campaign: InvalidationCampaign,
    phase: AuditPhase,
    *,
    detail: str,
) -> CampaignAuditRecord:
    """Build a stable record ID from campaign, phase, and bounded detail."""

    counts: dict[str, int] = {}
    for assessment in campaign.assessments:
        counts[assessment.state.value] = counts.get(assessment.state.value, 0) + 1
    impact_counts = tuple(sorted(counts.items()))
    record_material = {
        "campaign_id": campaign.campaign_id,
        "phase": phase.value,
        "detail": detail,
    }
    digest = hashlib.sha256(canonicalize(record_material)).hexdigest()
    return CampaignAuditRecord(
        record_id=f"gbx:invalidation-audit:sha256:{digest}",
        campaign_id=campaign.campaign_id,
        change_event_id=campaign.change.event_id,
        incident_urn=campaign.incident_urn,
        policy_version=campaign.policy_version,
        phase=phase,
        impact_counts=impact_counts,
        detail=detail,
    )


class AppendOnlyCampaignAuditLog:
    """Single-process JSONL audit with checksums and retry deduplication."""

    def __init__(self, path: Path, *, sync: bool = True) -> None:
        if not path.parent.is_dir():
            raise AuditLogError(f"audit-log parent directory does not exist: {path.parent}")
        if path.exists() and not path.is_file():
            raise AuditLogError(f"audit-log path is not a regular file: {path}")
        self.path = path
        self.sync = sync
        self._lock = Lock()
        self._record_ids = {item.record_id for item in self.read_records()}

    def record(self, item: CampaignAuditRecord) -> bool:
        """Append a new record, or return false for an already recorded retry."""

        with self._lock:
            if item.record_id in self._record_ids:
                return False
            material = item.to_dict()
            envelope = {
                "audit": material,
                "sha256": hashlib.sha256(_AUDIT_DOMAIN + canonicalize(material)).hexdigest(),
            }
            record = canonicalize(envelope) + b"\n"
            descriptor = os.open(self.path, os.O_APPEND | os.O_CREAT | os.O_WRONLY, 0o600)
            try:
                _write_all(descriptor, record)
                if self.sync:
                    os.fsync(descriptor)
            finally:
                os.close(descriptor)
            self._record_ids.add(item.record_id)
            return True

    def read_records(self) -> tuple[CampaignAuditRecord, ...]:
        """Verify and decode every complete record; corruption fails visibly."""

        if not self.path.exists():
            return ()
        data = self.path.read_bytes()
        if data and not data.endswith(b"\n"):
            raise AuditLogError("audit log has a truncated trailing record")
        records: list[CampaignAuditRecord] = []
        seen: set[str] = set()
        for line_number, line in enumerate(data.splitlines(), start=1):
            record = _decode_line(line, line_number=line_number)
            if record.record_id in seen:
                raise AuditLogError(f"audit log line {line_number} duplicates a record ID")
            seen.add(record.record_id)
            records.append(record)
        return tuple(records)


def _decode_line(line: bytes, *, line_number: int) -> CampaignAuditRecord:
    try:
        value = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuditLogError(f"audit log line {line_number} is not valid JSON") from exc
    if not isinstance(value, Mapping):
        raise AuditLogError(f"audit log line {line_number} must be an object")
    raw_audit = value.get("audit")
    digest = value.get("sha256")
    if not isinstance(raw_audit, Mapping) or not isinstance(digest, str):
        raise AuditLogError(f"audit log line {line_number} has an invalid envelope")
    expected = hashlib.sha256(_AUDIT_DOMAIN + canonicalize(raw_audit)).hexdigest()
    if digest != expected:
        raise AuditLogError(f"audit log line {line_number} failed its checksum")
    counts = raw_audit.get("impact_counts")
    if not isinstance(counts, Mapping):
        raise AuditLogError(f"audit log line {line_number} impact_counts must be an object")
    parsed_counts: list[tuple[str, int]] = []
    for key, count in counts.items():
        if not isinstance(key, str) or isinstance(count, bool) or not isinstance(count, int):
            raise AuditLogError(f"audit log line {line_number} has invalid impact counts")
        parsed_counts.append((key, count))
    try:
        return CampaignAuditRecord(
            record_id=_text(raw_audit, "record_id", line_number),
            campaign_id=_text(raw_audit, "campaign_id", line_number),
            change_event_id=_text(raw_audit, "change_event_id", line_number),
            incident_urn=_text(raw_audit, "incident_urn", line_number),
            policy_version=_text(raw_audit, "policy_version", line_number),
            phase=AuditPhase(_text(raw_audit, "phase", line_number)),
            impact_counts=tuple(sorted(parsed_counts)),
            detail=_text(raw_audit, "detail", line_number),
        )
    except ValueError as exc:
        raise AuditLogError(f"audit log line {line_number} has an invalid phase") from exc


def _text(value: Mapping[str, Any], key: str, line_number: int) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise AuditLogError(f"audit log line {line_number} field {key!r} must be non-empty")
    return selected


def _write_all(descriptor: int, value: bytes) -> None:
    remaining = memoryview(value)
    while remaining:
        written = os.write(descriptor, remaining)
        if written <= 0:  # pragma: no cover - defensive operating-system contract check
            raise AuditLogError("audit log append made no forward progress")
        remaining = remaining[written:]
