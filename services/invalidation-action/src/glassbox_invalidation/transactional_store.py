"""Transactional single-host receipt index, audit ledger, and campaign outbox."""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal

from glassbox_dbom.canonical import canonicalize
from glassbox_dbom.trust import (
    SignerAdmissionEvidence,
    SignerTrustError,
    SignerTrustMode,
    SignerTrustPolicy,
)
from glassbox_invalidation.audit_log import (
    AuditPhase,
    CampaignAuditRecord,
    campaign_audit_record,
)
from glassbox_policy import (
    POLICY_VERSION,
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    ImpactAssessment,
    ImpactState,
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    PolicyInputError,
    ReceiptDependencyProfile,
    campaign_identity,
)

_RECEIPT_DOMAIN = b"glassbox.sqlite-receipt.v1\0"
_CAMPAIGN_DOMAIN = b"glassbox.sqlite-campaign.v1\0"
_AUDIT_DOMAIN = b"glassbox.sqlite-audit.v1\0"
_EVIDENCE_DOMAIN = b"glassbox.sqlite-write-evidence.v1\0"
_ROUTING_EVIDENCE_DOMAIN = b"glassbox.sqlite-routing-evidence.v1\0"
_PUBLICATION_EVIDENCE_DOMAIN = b"glassbox.sqlite-publication-evidence.v1\0"
_DESTINATION_DOMAIN = b"glassbox.owner-destination.v1\0"
SQLITE_STATE_SCHEMA_VERSION = "4"
_SCHEMA_VERSION = SQLITE_STATE_SCHEMA_VERSION

_METADATA_SCHEMA = """
CREATE TABLE IF NOT EXISTS state_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_SCHEMA = """
CREATE TABLE IF NOT EXISTS receipt_records (
    receipt_id TEXT PRIMARY KEY,
    material BLOB NOT NULL,
    material_sha256 TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipt_dependencies (
    receipt_id TEXT NOT NULL REFERENCES receipt_records(receipt_id) ON DELETE RESTRICT,
    evidence_id TEXT NOT NULL,
    datahub_urn TEXT,
    schema_field_urn TEXT,
    evidence_state TEXT NOT NULL,
    evidence_role TEXT NOT NULL,
    observed_at TEXT,
    representation_digest TEXT,
    PRIMARY KEY (receipt_id, evidence_id)
);
CREATE INDEX IF NOT EXISTS receipt_dependencies_datahub_urn
    ON receipt_dependencies(datahub_urn);
CREATE INDEX IF NOT EXISTS receipt_dependencies_schema_field_urn
    ON receipt_dependencies(schema_field_urn);
CREATE TABLE IF NOT EXISTS receipt_publication_outbox (
    receipt_id TEXT PRIMARY KEY
        REFERENCES receipt_records(receipt_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('READY', 'LEASED', 'COMPLETED')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner TEXT,
    lease_expires_at_ms INTEGER,
    last_error_type TEXT,
    publication_evidence BLOB,
    publication_evidence_sha256 TEXT,
    CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
        OR
        (status != 'LEASED' AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
    ),
    CHECK (
        (publication_evidence IS NULL AND publication_evidence_sha256 IS NULL)
        OR
        (publication_evidence IS NOT NULL AND publication_evidence_sha256 IS NOT NULL)
    )
);
CREATE TABLE IF NOT EXISTS campaign_audit (
    record_id TEXT PRIMARY KEY,
    campaign_id TEXT NOT NULL,
    phase TEXT NOT NULL,
    material BLOB NOT NULL,
    material_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS campaign_audit_campaign_id
    ON campaign_audit(campaign_id);
CREATE TABLE IF NOT EXISTS campaign_outbox (
    campaign_id TEXT PRIMARY KEY,
    material BLOB NOT NULL,
    material_sha256 TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('READY', 'LEASED', 'COMPLETED')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner TEXT,
    lease_expires_at_ms INTEGER,
    last_error_type TEXT,
    write_evidence BLOB,
    write_evidence_sha256 TEXT,
    CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
        OR
        (status != 'LEASED' AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
    ),
    CHECK (
        (write_evidence IS NULL AND write_evidence_sha256 IS NULL)
        OR
        (write_evidence IS NOT NULL AND write_evidence_sha256 IS NOT NULL)
    )
);
CREATE TABLE IF NOT EXISTS owner_routing_outbox (
    campaign_id TEXT PRIMARY KEY
        REFERENCES campaign_outbox(campaign_id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('READY', 'LEASED', 'COMPLETED')),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    lease_owner TEXT,
    lease_expires_at_ms INTEGER,
    last_error_type TEXT,
    delivery_evidence BLOB,
    delivery_evidence_sha256 TEXT,
    CHECK (
        (status = 'LEASED' AND lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL)
        OR
        (status != 'LEASED' AND lease_owner IS NULL AND lease_expires_at_ms IS NULL)
    ),
    CHECK (
        (delivery_evidence IS NULL AND delivery_evidence_sha256 IS NULL)
        OR
        (delivery_evidence IS NOT NULL AND delivery_evidence_sha256 IS NOT NULL)
    )
);
"""


class TransactionalStoreError(RuntimeError):
    """Raised when transactional state is invalid, corrupt, or conflicts."""


class OutboxStatus(StrEnum):
    """Closed lifecycle for one deterministic campaign task."""

    READY = "READY"
    LEASED = "LEASED"
    COMPLETED = "COMPLETED"


@dataclass(frozen=True)
class OutboxTask:
    """Verified snapshot of one campaign outbox row."""

    campaign: InvalidationCampaign
    status: OutboxStatus
    attempt_count: int
    lease_owner: str | None
    lease_expires_at_ms: int | None
    last_error_type: str | None
    write_evidence: InvalidationWriteEvidence | None


@dataclass(frozen=True)
class ReceiptPublicationEvidence:
    """Sealed proof of two writes followed by direct DataHub readback."""

    document_urn: str
    aspect_names: tuple[str, ...]
    emission_count: int = 2


@dataclass(frozen=True)
class ReceiptPublicationTask:
    """Verified snapshot of one durable receipt-publication obligation."""

    receipt_id: str
    status: OutboxStatus
    attempt_count: int
    lease_owner: str | None
    lease_expires_at_ms: int | None
    last_error_type: str | None
    publication_evidence: ReceiptPublicationEvidence | None


@dataclass(frozen=True)
class OwnerRoutingEvidence:
    """Privacy-minimized proof that a router accepted bounded destinations."""

    destination_count: int
    destination_digests: tuple[str, ...]


@dataclass(frozen=True)
class OwnerRoutingTask:
    """Verified snapshot of one durable owner-routing obligation."""

    campaign_id: str
    status: OutboxStatus
    attempt_count: int
    lease_owner: str | None
    lease_expires_at_ms: int | None
    last_error_type: str | None
    delivery_evidence: OwnerRoutingEvidence | None


@dataclass(frozen=True)
class TransactionalIntegrityReport:
    """Counts returned only after database and record-level verification succeeds."""

    receipts: int
    dependencies: int
    campaigns: int
    audit_records: int
    owner_routing_tasks: int
    receipt_publication_tasks: int


class SQLiteInvalidationStore:
    """SQLite WAL profile safe for multiple processes on one local host."""

    def __init__(
        self,
        path: Path,
        *,
        require_signature: bool = True,
        signer_trust_policy: SignerTrustPolicy | None = None,
        busy_timeout_seconds: float = 10.0,
    ) -> None:
        if busy_timeout_seconds <= 0:
            raise TransactionalStoreError("busy_timeout_seconds must be positive")
        if not path.parent.is_dir():
            raise TransactionalStoreError(
                f"database parent directory does not exist: {path.parent}"
            )
        if path.is_symlink():
            raise TransactionalStoreError("database path must not be a symbolic link")
        if path.exists() and not path.is_file():
            raise TransactionalStoreError(f"database path is not a regular file: {path}")
        self.path = path
        self.require_signature = require_signature
        self.signer_trust_policy = signer_trust_policy
        self.busy_timeout_seconds = busy_timeout_seconds
        try:
            with closing(self._connect()) as connection:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
                connection.executescript(_METADATA_SCHEMA)
                version = connection.execute(
                    "SELECT value FROM state_metadata WHERE key = 'schema_version'"
                ).fetchone()
                if version is None:
                    application_tables = connection.execute(
                        """
                        SELECT name FROM sqlite_master
                        WHERE type = 'table' AND name != 'state_metadata'
                        LIMIT 1
                        """
                    ).fetchone()
                    if application_tables is not None:
                        raise TransactionalStoreError(
                            "transactional database has application tables but no schema version"
                        )
                    connection.execute(
                        "INSERT INTO state_metadata(key, value) VALUES ('schema_version', ?)",
                        (_SCHEMA_VERSION,),
                    )
                elif version[0] != _SCHEMA_VERSION:
                    raise TransactionalStoreError(
                        "transactional database schema version is unsupported"
                    )
                connection.executescript(_SCHEMA)
                self._verify_schema_version(connection)
        except sqlite3.Error as exc:
            raise TransactionalStoreError("failed to initialize transactional store") from exc
        self.path.chmod(0o600)
        self.verify_integrity()

    def register(
        self,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
        superseded_by: str | None = None,
    ) -> bool:
        """Atomically append a signed receipt and every reverse-index row."""

        return self.register_many(((receipt, field_lineage, superseded_by),))[0]

    def register_many(
        self,
        registrations: Sequence[tuple[Mapping[str, Any], FieldLineageProof | None, str | None]],
    ) -> tuple[bool, ...]:
        """Register a complete receipt batch in one SQLite transaction."""

        if not registrations:
            return ()
        with self._write_transaction() as connection:
            return tuple(
                self._register_receipt(
                    connection,
                    receipt,
                    field_lineage=field_lineage,
                    superseded_by=superseded_by,
                )
                for receipt, field_lineage, superseded_by in registrations
            )

    def _register_receipt(
        self,
        connection: sqlite3.Connection,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None,
        superseded_by: str | None,
    ) -> bool:
        """Register one receipt inside an existing write transaction."""

        proof = field_lineage or FieldLineageProof()
        core_material = {
            "receipt": copy.deepcopy(dict(receipt)),
            "field_lineage": _lineage_to_dict(proof),
            "superseded_by": superseded_by,
        }
        encoded_core = canonicalize(core_material)
        receipt_id = _receipt_id(receipt)
        existing = connection.execute(
            "SELECT material, material_sha256 FROM receipt_records WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if existing is not None:
            existing_material = _receipt_material_from_row(existing)
            if canonicalize(_receipt_core_material(existing_material)) == encoded_core:
                self._decode_receipt(existing)
                publication = connection.execute(
                    "SELECT receipt_id FROM receipt_publication_outbox WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
                if publication is None:
                    raise TransactionalStoreError(
                        "registered receipt has no publication obligation"
                    )
                return False
            raise TransactionalStoreError(
                f"receipt {receipt_id} already has conflicting dependency metadata"
            )
        profile = ReceiptDependencyProfile.from_receipt(
            receipt,
            field_lineage=proof,
            superseded_by=superseded_by,
            require_signature=self.require_signature,
            signer_trust_policy=self.signer_trust_policy,
            signer_trust_mode=SignerTrustMode.ADMISSION,
        )
        admission = _signer_admission_evidence(self.signer_trust_policy, receipt)
        material = {
            **core_material,
            "signer_admission": admission.to_dict() if admission is not None else None,
        }
        encoded = canonicalize(material)
        digest = _digest(_RECEIPT_DOMAIN, encoded)
        connection.execute(
            """
            INSERT INTO receipt_records(receipt_id, material, material_sha256)
            VALUES (?, ?, ?)
            """,
            (profile.receipt_id, encoded, digest),
        )
        connection.executemany(
            """
            INSERT INTO receipt_dependencies(
                receipt_id, evidence_id, datahub_urn, schema_field_urn,
                evidence_state, evidence_role, observed_at, representation_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            _dependency_rows(profile),
        )
        connection.execute(
            """
            INSERT INTO receipt_publication_outbox(receipt_id, status)
            VALUES (?, 'READY')
            """,
            (profile.receipt_id,),
        )
        return True

    def get_receipt_publication_task(self, receipt_id: str) -> ReceiptPublicationTask | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        return self._decode_receipt_publication_task(row) if row is not None else None

    def list_receipt_publication_tasks(self) -> tuple[ReceiptPublicationTask, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM receipt_publication_outbox ORDER BY receipt_id"
            ).fetchall()
        return tuple(self._decode_receipt_publication_task(row) for row in rows)

    def claim_receipt_publication(
        self,
        receipt_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> ReceiptPublicationTask | None:
        """Claim ready or expired publication work; completed work is never reclaimed."""

        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        _nonempty(worker_id, "worker_id")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"receipt publication {receipt_id} is not staged")
            task = self._decode_receipt_publication_task(row)
            if task.status is OutboxStatus.COMPLETED:
                return None
            if (
                task.status is OutboxStatus.LEASED
                and task.lease_expires_at_ms is not None
                and task.lease_expires_at_ms > now_ms
            ):
                return None
            connection.execute(
                """
                UPDATE receipt_publication_outbox
                SET status = 'LEASED', attempt_count = attempt_count + 1,
                    lease_owner = ?, lease_expires_at_ms = ?, last_error_type = NULL
                WHERE receipt_id = ?
                """,
                (worker_id, now_ms + lease_duration_ms, receipt_id),
            )
            claimed = connection.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if claimed is None:  # pragma: no cover - protected by primary key
                raise TransactionalStoreError("claimed receipt publication disappeared")
            return self._decode_receipt_publication_task(claimed)

    def renew_receipt_publication(
        self,
        receipt_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> ReceiptPublicationTask:
        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"receipt publication {receipt_id} is not staged")
            task = self._decode_receipt_publication_task(row)
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "receipt-publication lease is not owned by this worker"
                )
            connection.execute(
                """
                UPDATE receipt_publication_outbox SET lease_expires_at_ms = ?
                WHERE receipt_id = ?
                """,
                (now_ms + lease_duration_ms, receipt_id),
            )
            renewed = connection.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if renewed is None:  # pragma: no cover
                raise TransactionalStoreError("renewed receipt publication disappeared")
            return self._decode_receipt_publication_task(renewed)

    def release_receipt_publication(
        self, receipt_id: str, *, worker_id: str, error_type: str
    ) -> None:
        _nonempty(error_type, "error_type")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"receipt publication {receipt_id} is not staged")
            task = self._decode_receipt_publication_task(row)
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "cannot release a receipt-publication lease owned elsewhere"
                )
            connection.execute(
                """
                UPDATE receipt_publication_outbox
                SET status = 'READY', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = ?
                WHERE receipt_id = ?
                """,
                (error_type, receipt_id),
            )

    def complete_receipt_publication(
        self,
        receipt_id: str,
        evidence: ReceiptPublicationEvidence,
        *,
        worker_id: str,
    ) -> bool:
        _validate_publication_evidence(receipt_id, evidence)
        encoded = canonicalize(_publication_evidence_to_dict(evidence))
        digest = _digest(_PUBLICATION_EVIDENCE_DOMAIN, encoded)
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"receipt publication {receipt_id} is not staged")
            task = self._decode_receipt_publication_task(row)
            if task.status is OutboxStatus.COMPLETED:
                if task.publication_evidence == evidence:
                    return False
                raise TransactionalStoreError(
                    "completed receipt publication has conflicting evidence"
                )
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "cannot complete a receipt-publication lease owned elsewhere"
                )
            connection.execute(
                """
                UPDATE receipt_publication_outbox
                SET status = 'COMPLETED', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = NULL, publication_evidence = ?,
                    publication_evidence_sha256 = ?
                WHERE receipt_id = ?
                """,
                (encoded, digest, receipt_id),
            )
        return True

    def all_profiles(self) -> tuple[ReceiptDependencyProfile, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT material, material_sha256 FROM receipt_records ORDER BY receipt_id"
            ).fetchall()
        return tuple(self._decode_receipt(row) for row in rows)

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None:
        """Return a defensive copy after checksum and receipt verification."""

        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                SELECT material, material_sha256 FROM receipt_records
                WHERE receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
        if row is None:
            return None
        profile = self._decode_receipt(row)
        encoded = _checked_blob(row, "material", "material_sha256", _RECEIPT_DOMAIN)
        material = _mapping(json.loads(encoded), "receipt material")
        receipt = _mapping(material.get("receipt"), "stored receipt")
        if receipt.get("receipt_id") != profile.receipt_id:
            raise TransactionalStoreError("stored receipt identity changed after verification")
        return copy.deepcopy(dict(receipt))

    def candidates(self, change: NormalizedChange) -> tuple[ReceiptDependencyProfile, ...]:
        """Query exact-asset and unresolved candidates from the transactional index."""

        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                SELECT r.material, r.material_sha256
                FROM receipt_records AS r
                WHERE EXISTS (
                    SELECT 1
                    FROM receipt_dependencies AS d
                    WHERE d.receipt_id = r.receipt_id
                      AND (
                          d.datahub_urn = ?
                          OR d.datahub_urn IS NULL
                          OR d.evidence_state = 'UNKNOWN'
                      )
                )
                ORDER BY r.receipt_id
                """,
                (change.entity_urn,),
            ).fetchall()
        return tuple(self._decode_receipt(row) for row in rows)

    def stage_campaign(self, campaign: InvalidationCampaign) -> bool:
        """Atomically persist a campaign and its CLASSIFIED audit checkpoint."""

        encoded = canonicalize(_campaign_to_dict(campaign))
        digest = _digest(_CAMPAIGN_DOMAIN, encoded)
        classified = campaign_audit_record(
            campaign,
            AuditPhase.CLASSIFIED,
            detail="policy-complete",
        )
        initial_status = OutboxStatus.READY if campaign.quarantined else OutboxStatus.COMPLETED
        with self._write_transaction() as connection:
            existing = connection.execute(
                "SELECT material, material_sha256 FROM campaign_outbox WHERE campaign_id = ?",
                (campaign.campaign_id,),
            ).fetchone()
            if existing is not None:
                if _blob(existing["material"]) != encoded or existing["material_sha256"] != digest:
                    raise TransactionalStoreError(
                        f"campaign {campaign.campaign_id} has conflicting outbox material"
                    )
                self._insert_audit(connection, classified)
                return False
            connection.execute(
                """
                INSERT INTO campaign_outbox(
                    campaign_id, material, material_sha256, status
                ) VALUES (?, ?, ?, ?)
                """,
                (campaign.campaign_id, encoded, digest, initial_status.value),
            )
            self._insert_audit(connection, classified)
        return True

    def get_task(self, campaign_id: str) -> OutboxTask | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM campaign_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
        return self._decode_task(row) if row is not None else None

    def list_tasks(self) -> tuple[OutboxTask, ...]:
        """Return every verified outbox task in deterministic campaign order."""

        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM campaign_outbox ORDER BY campaign_id"
            ).fetchall()
        return tuple(self._decode_task(row) for row in rows)

    def claim(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OutboxTask | None:
        """Claim READY/expired work once, or return none while another lease is live."""

        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        _nonempty(worker_id, "worker_id")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM campaign_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"campaign {campaign_id} is not staged")
            task = self._decode_task(row)
            if task.status is OutboxStatus.COMPLETED:
                return None
            if (
                task.status is OutboxStatus.LEASED
                and task.lease_expires_at_ms is not None
                and task.lease_expires_at_ms > now_ms
            ):
                return None
            connection.execute(
                """
                UPDATE campaign_outbox
                SET status = 'LEASED', attempt_count = attempt_count + 1,
                    lease_owner = ?, lease_expires_at_ms = ?, last_error_type = NULL
                WHERE campaign_id = ?
                """,
                (worker_id, now_ms + lease_duration_ms, campaign_id),
            )
            claimed = connection.execute(
                "SELECT * FROM campaign_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if claimed is None:  # pragma: no cover - protected by transaction and primary key
                raise TransactionalStoreError("claimed campaign disappeared")
            return self._decode_task(claimed)

    def renew(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OutboxTask:
        """Extend a lease only while it remains owned by this worker."""

        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM campaign_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"campaign {campaign_id} is not staged")
            task = self._decode_task(row)
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("campaign lease is not owned by this worker")
            connection.execute(
                "UPDATE campaign_outbox SET lease_expires_at_ms = ? WHERE campaign_id = ?",
                (now_ms + lease_duration_ms, campaign_id),
            )
            renewed = connection.execute(
                "SELECT * FROM campaign_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if renewed is None:  # pragma: no cover - protected by transaction and primary key
                raise TransactionalStoreError("renewed campaign disappeared")
            return self._decode_task(renewed)

    def release(
        self,
        campaign: InvalidationCampaign,
        *,
        worker_id: str,
        error_type: str,
    ) -> None:
        """Return owned work to READY and atomically record a bounded failure audit."""

        _nonempty(error_type, "error_type")
        failure = campaign_audit_record(
            campaign,
            AuditPhase.DATAHUB_FAILED,
            detail=f"failure:{error_type}",
        )
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM campaign_outbox WHERE campaign_id = ?",
                (campaign.campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"campaign {campaign.campaign_id} is not staged")
            task = self._decode_task(row)
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("cannot release a campaign lease owned elsewhere")
            connection.execute(
                """
                UPDATE campaign_outbox
                SET status = 'READY', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = ?
                WHERE campaign_id = ?
                """,
                (error_type, campaign.campaign_id),
            )
            self._insert_audit(connection, failure)

    def complete(
        self,
        campaign: InvalidationCampaign,
        evidence: InvalidationWriteEvidence,
        *,
        worker_id: str,
    ) -> bool:
        """Atomically seal verified evidence and its DATAHUB_VERIFIED audit record."""

        _validate_evidence(campaign, evidence)
        encoded = canonicalize(_evidence_to_dict(evidence))
        digest = _digest(_EVIDENCE_DOMAIN, encoded)
        verified = campaign_audit_record(
            campaign,
            AuditPhase.DATAHUB_VERIFIED,
            detail="direct-readback",
        )
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM campaign_outbox WHERE campaign_id = ?",
                (campaign.campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(f"campaign {campaign.campaign_id} is not staged")
            task = self._decode_task(row)
            if task.status is OutboxStatus.COMPLETED:
                if task.write_evidence == evidence:
                    routing = connection.execute(
                        "SELECT campaign_id FROM owner_routing_outbox WHERE campaign_id = ?",
                        (campaign.campaign_id,),
                    ).fetchone()
                    if routing is None:
                        raise TransactionalStoreError(
                            "completed material campaign has no owner-routing obligation"
                        )
                    self._insert_audit(connection, verified)
                    return False
                raise TransactionalStoreError("completed campaign has conflicting write evidence")
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("cannot complete a campaign lease owned elsewhere")
            connection.execute(
                """
                UPDATE campaign_outbox
                SET status = 'COMPLETED', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = NULL, write_evidence = ?, write_evidence_sha256 = ?
                WHERE campaign_id = ?
                """,
                (encoded, digest, campaign.campaign_id),
            )
            connection.execute(
                """
                INSERT INTO owner_routing_outbox(campaign_id, status)
                VALUES (?, 'READY')
                """,
                (campaign.campaign_id,),
            )
            self._insert_audit(connection, verified)
        return True

    def get_owner_routing_task(self, campaign_id: str) -> OwnerRoutingTask | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
        return self._decode_owner_routing_task(row) if row is not None else None

    def list_owner_routing_tasks(self) -> tuple[OwnerRoutingTask, ...]:
        """Return every verified routing task without exposing destination identifiers."""

        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT * FROM owner_routing_outbox ORDER BY campaign_id"
            ).fetchall()
        return tuple(self._decode_owner_routing_task(row) for row in rows)

    def claim_owner_routing(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OwnerRoutingTask | None:
        """Claim a ready or expired owner-routing obligation."""

        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        _nonempty(worker_id, "worker_id")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(
                    f"owner routing for campaign {campaign_id} is not staged"
                )
            task = self._decode_owner_routing_task(row)
            if task.status is OutboxStatus.COMPLETED:
                return None
            if (
                task.status is OutboxStatus.LEASED
                and task.lease_expires_at_ms is not None
                and task.lease_expires_at_ms > now_ms
            ):
                return None
            connection.execute(
                """
                UPDATE owner_routing_outbox
                SET status = 'LEASED', attempt_count = attempt_count + 1,
                    lease_owner = ?, lease_expires_at_ms = ?, last_error_type = NULL
                WHERE campaign_id = ?
                """,
                (worker_id, now_ms + lease_duration_ms, campaign_id),
            )
            claimed = connection.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if claimed is None:  # pragma: no cover - protected by primary key
                raise TransactionalStoreError("claimed owner-routing task disappeared")
            return self._decode_owner_routing_task(claimed)

    def renew_owner_routing(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OwnerRoutingTask:
        """Extend an owned routing lease."""

        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(
                    f"owner routing for campaign {campaign_id} is not staged"
                )
            task = self._decode_owner_routing_task(row)
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("owner-routing lease is not owned by this worker")
            connection.execute(
                """
                UPDATE owner_routing_outbox SET lease_expires_at_ms = ?
                WHERE campaign_id = ?
                """,
                (now_ms + lease_duration_ms, campaign_id),
            )
            renewed = connection.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = ?",
                (campaign_id,),
            ).fetchone()
            if renewed is None:  # pragma: no cover - protected by primary key
                raise TransactionalStoreError("renewed owner-routing task disappeared")
            return self._decode_owner_routing_task(renewed)

    def release_owner_routing(
        self,
        campaign: InvalidationCampaign,
        *,
        worker_id: str,
        error_type: str,
    ) -> None:
        """Return routing to READY and atomically record a bounded failure."""

        _nonempty(error_type, "error_type")
        failure = campaign_audit_record(
            campaign,
            AuditPhase.OWNER_ROUTING_FAILED,
            detail=f"failure:{error_type}",
        )
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = ?",
                (campaign.campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(
                    f"owner routing for campaign {campaign.campaign_id} is not staged"
                )
            task = self._decode_owner_routing_task(row)
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "cannot release an owner-routing lease owned elsewhere"
                )
            connection.execute(
                """
                UPDATE owner_routing_outbox
                SET status = 'READY', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = ?
                WHERE campaign_id = ?
                """,
                (error_type, campaign.campaign_id),
            )
            self._insert_audit(connection, failure)

    def complete_owner_routing(
        self,
        campaign: InvalidationCampaign,
        destinations: tuple[str, ...],
        *,
        worker_id: str,
    ) -> OwnerRoutingEvidence:
        """Seal privacy-minimized adapter acceptance evidence and its audit."""

        evidence = _owner_routing_evidence(destinations)
        encoded = canonicalize(_routing_evidence_to_dict(evidence))
        digest = _digest(_ROUTING_EVIDENCE_DOMAIN, encoded)
        accepted = campaign_audit_record(
            campaign,
            AuditPhase.OWNER_ROUTING_ACCEPTED,
            detail=f"destinations:{evidence.destination_count}",
        )
        with self._write_transaction() as connection:
            row = connection.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = ?",
                (campaign.campaign_id,),
            ).fetchone()
            if row is None:
                raise TransactionalStoreError(
                    f"owner routing for campaign {campaign.campaign_id} is not staged"
                )
            task = self._decode_owner_routing_task(row)
            if task.status is OutboxStatus.COMPLETED:
                if task.delivery_evidence == evidence:
                    self._insert_audit(connection, accepted)
                    return evidence
                raise TransactionalStoreError(
                    "completed owner routing has conflicting delivery evidence"
                )
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "cannot complete an owner-routing lease owned elsewhere"
                )
            connection.execute(
                """
                UPDATE owner_routing_outbox
                SET status = 'COMPLETED', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = NULL, delivery_evidence = ?,
                    delivery_evidence_sha256 = ?
                WHERE campaign_id = ?
                """,
                (encoded, digest, campaign.campaign_id),
            )
            self._insert_audit(connection, accepted)
        return evidence

    def read_audit_records(self) -> tuple[CampaignAuditRecord, ...]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT material, material_sha256 FROM campaign_audit ORDER BY rowid"
            ).fetchall()
        return tuple(self._decode_audit(row) for row in rows)

    def verify_integrity(self) -> TransactionalIntegrityReport:
        """Run SQLite structural checks plus every application-level checksum."""

        try:
            with closing(self._connect()) as connection:
                result = connection.execute("PRAGMA quick_check").fetchone()
                if result is None or result[0] != "ok":
                    raise TransactionalStoreError("SQLite quick_check failed")
                foreign_keys = connection.execute("PRAGMA foreign_key_check").fetchall()
                if foreign_keys:
                    raise TransactionalStoreError("SQLite foreign_key_check failed")
                self._verify_schema_version(connection)
                receipt_rows = connection.execute(
                    "SELECT material, material_sha256 FROM receipt_records ORDER BY receipt_id"
                ).fetchall()
                dependency_rows = connection.execute(
                    """
                    SELECT receipt_id, evidence_id, datahub_urn, schema_field_urn,
                           evidence_state, evidence_role, observed_at,
                           representation_digest
                    FROM receipt_dependencies
                    ORDER BY receipt_id, evidence_id
                    """
                ).fetchall()
                publication_rows = connection.execute(
                    "SELECT * FROM receipt_publication_outbox ORDER BY receipt_id"
                ).fetchall()
                task_rows = connection.execute(
                    "SELECT * FROM campaign_outbox ORDER BY campaign_id"
                ).fetchall()
                routing_rows = connection.execute(
                    "SELECT * FROM owner_routing_outbox ORDER BY campaign_id"
                ).fetchall()
                audit_rows = connection.execute(
                    "SELECT material, material_sha256 FROM campaign_audit ORDER BY record_id"
                ).fetchall()
                missing_routing = connection.execute(
                    """
                    SELECT campaign_id FROM campaign_outbox AS campaign
                    WHERE campaign.status = 'COMPLETED'
                      AND campaign.write_evidence IS NOT NULL
                      AND NOT EXISTS (
                          SELECT 1 FROM owner_routing_outbox AS routing
                          WHERE routing.campaign_id = campaign.campaign_id
                      )
                    """
                ).fetchall()
                premature_routing = connection.execute(
                    """
                    SELECT routing.campaign_id
                    FROM owner_routing_outbox AS routing
                    JOIN campaign_outbox AS campaign
                      ON campaign.campaign_id = routing.campaign_id
                    WHERE campaign.status != 'COMPLETED'
                       OR campaign.write_evidence IS NULL
                    """
                ).fetchall()
                missing_publications = connection.execute(
                    """
                    SELECT receipt_id FROM receipt_records AS receipt
                    WHERE NOT EXISTS (
                        SELECT 1 FROM receipt_publication_outbox AS publication
                        WHERE publication.receipt_id = receipt.receipt_id
                    )
                    """
                ).fetchall()
        except sqlite3.Error as exc:
            raise TransactionalStoreError("failed to verify transactional store") from exc
        profiles = tuple(self._decode_receipt(row) for row in receipt_rows)
        expected_dependencies = tuple(
            row for profile in profiles for row in _dependency_rows(profile)
        )
        actual_dependencies = tuple(tuple(row) for row in dependency_rows)
        if actual_dependencies != expected_dependencies:
            raise TransactionalStoreError(
                "receipt reverse index diverges from verified receipt material"
            )
        for row in publication_rows:
            self._decode_receipt_publication_task(row)
        for row in task_rows:
            self._decode_task(row)
        for row in routing_rows:
            self._decode_owner_routing_task(row)
        for row in audit_rows:
            self._decode_audit(row)
        if missing_routing:
            raise TransactionalStoreError(
                "completed material campaign has no owner-routing obligation"
            )
        if premature_routing:
            raise TransactionalStoreError(
                "owner-routing obligation exists before campaign completion"
            )
        if missing_publications:
            raise TransactionalStoreError("registered receipt has no publication obligation")
        return TransactionalIntegrityReport(
            receipts=len(receipt_rows),
            dependencies=len(dependency_rows),
            campaigns=len(task_rows),
            audit_records=len(audit_rows),
            owner_routing_tasks=len(routing_rows),
            receipt_publication_tasks=len(publication_rows),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_seconds,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_seconds * 1000)}")
        return connection

    @staticmethod
    def _verify_schema_version(connection: sqlite3.Connection) -> None:
        row = connection.execute(
            "SELECT value FROM state_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if row is None or row[0] != _SCHEMA_VERSION:
            raise TransactionalStoreError("transactional database schema version is unsupported")

    def _write_transaction(self) -> _WriteTransaction:
        return _WriteTransaction(self)

    def _decode_receipt(self, row: sqlite3.Row) -> ReceiptDependencyProfile:
        encoded = _checked_blob(row, "material", "material_sha256", _RECEIPT_DOMAIN)
        material = _mapping(json.loads(encoded), "receipt material")
        receipt = _mapping(material.get("receipt"), "stored receipt")
        try:
            _verify_signer_admission_evidence(
                material.get("signer_admission"),
                receipt,
                signer_trust_policy=self.signer_trust_policy,
            )
            return ReceiptDependencyProfile.from_receipt(
                receipt,
                field_lineage=_parse_lineage(material.get("field_lineage")),
                superseded_by=_optional_text(material, "superseded_by"),
                require_signature=self.require_signature,
                signer_trust_policy=self.signer_trust_policy,
                signer_trust_mode=SignerTrustMode.HISTORICAL,
            )
        except (PolicyInputError, SignerTrustError) as exc:
            raise TransactionalStoreError("stored receipt failed verification") from exc

    def _decode_receipt_publication_task(self, row: sqlite3.Row) -> ReceiptPublicationTask:
        receipt_id = row["receipt_id"]
        if not isinstance(receipt_id, str) or not receipt_id:
            raise TransactionalStoreError("receipt-publication task has an invalid receipt ID")
        try:
            status = OutboxStatus(row["status"])
        except ValueError as exc:
            raise TransactionalStoreError("receipt-publication task has an invalid status") from exc
        attempt_count = row["attempt_count"]
        if (
            isinstance(attempt_count, bool)
            or not isinstance(attempt_count, int)
            or attempt_count < 0
        ):
            raise TransactionalStoreError("receipt-publication task has an invalid attempt count")
        lease_owner = row["lease_owner"]
        lease_expires = row["lease_expires_at_ms"]
        if status is OutboxStatus.LEASED:
            if not isinstance(lease_owner, str) or not lease_owner:
                raise TransactionalStoreError("leased receipt publication has no owner")
            if isinstance(lease_expires, bool) or not isinstance(lease_expires, int):
                raise TransactionalStoreError("leased receipt publication has no expiration")
        elif lease_owner is not None or lease_expires is not None:
            raise TransactionalStoreError("unleased receipt publication contains lease metadata")
        last_error = row["last_error_type"]
        if last_error is not None and (not isinstance(last_error, str) or not last_error):
            raise TransactionalStoreError("receipt-publication task has an invalid error type")
        raw_evidence = row["publication_evidence"]
        raw_digest = row["publication_evidence_sha256"]
        evidence: ReceiptPublicationEvidence | None = None
        if raw_evidence is not None or raw_digest is not None:
            if raw_evidence is None or not isinstance(raw_digest, str):
                raise TransactionalStoreError("receipt publication evidence envelope is incomplete")
            encoded = _blob(raw_evidence)
            if _digest(_PUBLICATION_EVIDENCE_DOMAIN, encoded) != raw_digest:
                raise TransactionalStoreError("receipt publication evidence failed its checksum")
            evidence = _publication_evidence_from_dict(
                _mapping(json.loads(encoded), "receipt publication evidence")
            )
            _validate_publication_evidence(receipt_id, evidence)
        if status is OutboxStatus.COMPLETED and evidence is None:
            raise TransactionalStoreError(
                "completed receipt publication has no publication evidence"
            )
        if status is not OutboxStatus.COMPLETED and evidence is not None:
            raise TransactionalStoreError(
                "incomplete receipt publication already contains publication evidence"
            )
        return ReceiptPublicationTask(
            receipt_id=receipt_id,
            status=status,
            attempt_count=attempt_count,
            lease_owner=lease_owner,
            lease_expires_at_ms=lease_expires,
            last_error_type=last_error,
            publication_evidence=evidence,
        )

    def _decode_task(self, row: sqlite3.Row) -> OutboxTask:
        encoded = _checked_blob(row, "material", "material_sha256", _CAMPAIGN_DOMAIN)
        campaign = _campaign_from_dict(_mapping(json.loads(encoded), "campaign material"))
        try:
            status = OutboxStatus(row["status"])
        except ValueError as exc:
            raise TransactionalStoreError("campaign outbox has an invalid status") from exc
        attempt_count = row["attempt_count"]
        if (
            isinstance(attempt_count, bool)
            or not isinstance(attempt_count, int)
            or attempt_count < 0
        ):
            raise TransactionalStoreError("campaign outbox has an invalid attempt count")
        lease_owner = row["lease_owner"]
        lease_expires = row["lease_expires_at_ms"]
        if status is OutboxStatus.LEASED:
            if not isinstance(lease_owner, str) or not lease_owner:
                raise TransactionalStoreError("leased campaign has no owner")
            if isinstance(lease_expires, bool) or not isinstance(lease_expires, int):
                raise TransactionalStoreError("leased campaign has no expiration")
        elif lease_owner is not None or lease_expires is not None:
            raise TransactionalStoreError("unleased campaign contains lease metadata")
        last_error = row["last_error_type"]
        if last_error is not None and (not isinstance(last_error, str) or not last_error):
            raise TransactionalStoreError("campaign outbox has an invalid error type")
        raw_evidence = row["write_evidence"]
        raw_evidence_digest = row["write_evidence_sha256"]
        evidence: InvalidationWriteEvidence | None = None
        if raw_evidence is not None or raw_evidence_digest is not None:
            if raw_evidence is None or not isinstance(raw_evidence_digest, str):
                raise TransactionalStoreError("campaign write evidence envelope is incomplete")
            evidence_blob = _blob(raw_evidence)
            if _digest(_EVIDENCE_DOMAIN, evidence_blob) != raw_evidence_digest:
                raise TransactionalStoreError("campaign write evidence failed its checksum")
            evidence = _evidence_from_dict(
                _mapping(json.loads(evidence_blob), "campaign write evidence")
            )
            _validate_evidence(campaign, evidence)
        if status is OutboxStatus.COMPLETED and campaign.quarantined and evidence is None:
            raise TransactionalStoreError("completed material campaign has no write evidence")
        if status is not OutboxStatus.COMPLETED and evidence is not None:
            raise TransactionalStoreError("incomplete campaign already contains write evidence")
        return OutboxTask(
            campaign=campaign,
            status=status,
            attempt_count=attempt_count,
            lease_owner=lease_owner,
            lease_expires_at_ms=lease_expires,
            last_error_type=last_error,
            write_evidence=evidence,
        )

    def _decode_owner_routing_task(self, row: sqlite3.Row) -> OwnerRoutingTask:
        campaign_id = row["campaign_id"]
        if not isinstance(campaign_id, str) or not campaign_id:
            raise TransactionalStoreError("owner-routing task has an invalid campaign ID")
        try:
            status = OutboxStatus(row["status"])
        except ValueError as exc:
            raise TransactionalStoreError("owner-routing task has an invalid status") from exc
        attempt_count = row["attempt_count"]
        if (
            isinstance(attempt_count, bool)
            or not isinstance(attempt_count, int)
            or attempt_count < 0
        ):
            raise TransactionalStoreError("owner-routing task has an invalid attempt count")
        lease_owner = row["lease_owner"]
        lease_expires = row["lease_expires_at_ms"]
        if status is OutboxStatus.LEASED:
            if not isinstance(lease_owner, str) or not lease_owner:
                raise TransactionalStoreError("leased owner-routing task has no owner")
            if isinstance(lease_expires, bool) or not isinstance(lease_expires, int):
                raise TransactionalStoreError("leased owner-routing task has no expiration")
        elif lease_owner is not None or lease_expires is not None:
            raise TransactionalStoreError("unleased owner-routing task contains lease metadata")
        last_error = row["last_error_type"]
        if last_error is not None and (not isinstance(last_error, str) or not last_error):
            raise TransactionalStoreError("owner-routing task has an invalid error type")
        raw_evidence = row["delivery_evidence"]
        raw_digest = row["delivery_evidence_sha256"]
        evidence: OwnerRoutingEvidence | None = None
        if raw_evidence is not None or raw_digest is not None:
            if raw_evidence is None or not isinstance(raw_digest, str):
                raise TransactionalStoreError(
                    "owner-routing delivery evidence envelope is incomplete"
                )
            encoded = _blob(raw_evidence)
            if _digest(_ROUTING_EVIDENCE_DOMAIN, encoded) != raw_digest:
                raise TransactionalStoreError("owner-routing delivery evidence failed its checksum")
            evidence = _routing_evidence_from_dict(
                _mapping(json.loads(encoded), "owner-routing delivery evidence")
            )
        if status is OutboxStatus.COMPLETED and evidence is None:
            raise TransactionalStoreError("completed owner-routing task has no delivery evidence")
        if status is not OutboxStatus.COMPLETED and evidence is not None:
            raise TransactionalStoreError(
                "incomplete owner-routing task already contains delivery evidence"
            )
        return OwnerRoutingTask(
            campaign_id=campaign_id,
            status=status,
            attempt_count=attempt_count,
            lease_owner=lease_owner,
            lease_expires_at_ms=lease_expires,
            last_error_type=last_error,
            delivery_evidence=evidence,
        )

    def _insert_audit(
        self,
        connection: sqlite3.Connection,
        record: CampaignAuditRecord,
    ) -> bool:
        encoded = canonicalize(record.to_dict())
        digest = _digest(_AUDIT_DOMAIN, encoded)
        existing = connection.execute(
            "SELECT material, material_sha256 FROM campaign_audit WHERE record_id = ?",
            (record.record_id,),
        ).fetchone()
        if existing is not None:
            if _blob(existing["material"]) == encoded and existing["material_sha256"] == digest:
                return False
            raise TransactionalStoreError(f"audit record {record.record_id} conflicts")
        connection.execute(
            """
            INSERT INTO campaign_audit(
                record_id, campaign_id, phase, material, material_sha256
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (record.record_id, record.campaign_id, record.phase.value, encoded, digest),
        )
        return True

    def _decode_audit(self, row: sqlite3.Row) -> CampaignAuditRecord:
        encoded = _checked_blob(row, "material", "material_sha256", _AUDIT_DOMAIN)
        material = _mapping(json.loads(encoded), "audit material")
        counts = _mapping(material.get("impact_counts"), "audit impact counts")
        parsed_counts: list[tuple[str, int]] = []
        for key, count in counts.items():
            if not isinstance(key, str) or isinstance(count, bool) or not isinstance(count, int):
                raise TransactionalStoreError("audit impact counts are invalid")
            parsed_counts.append((key, count))
        try:
            return CampaignAuditRecord(
                record_id=_text(material, "record_id"),
                campaign_id=_text(material, "campaign_id"),
                change_event_id=_text(material, "change_event_id"),
                incident_urn=_text(material, "incident_urn"),
                policy_version=_text(material, "policy_version"),
                phase=AuditPhase(_text(material, "phase")),
                impact_counts=tuple(sorted(parsed_counts)),
                detail=_text(material, "detail"),
            )
        except ValueError as exc:
            raise TransactionalStoreError("audit phase is invalid") from exc


class _WriteTransaction:
    def __init__(self, store: SQLiteInvalidationStore) -> None:
        self.store = store
        self.connection: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        self.connection = self.store._connect()
        try:
            self.connection.execute("BEGIN IMMEDIATE")
        except sqlite3.Error as exc:
            self.connection.close()
            raise TransactionalStoreError("failed to begin write transaction") from exc
        return self.connection

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> Literal[False]:
        if self.connection is None:  # pragma: no cover - context manager contract
            return False
        try:
            if exc_type is None:
                self.connection.commit()
            else:
                self.connection.rollback()
        except sqlite3.Error as database_error:
            raise TransactionalStoreError("failed to finish write transaction") from database_error
        finally:
            self.connection.close()
        if isinstance(exc, sqlite3.Error):
            raise TransactionalStoreError("transactional database write failed") from exc
        return False


def _campaign_to_dict(campaign: InvalidationCampaign) -> dict[str, Any]:
    return {
        "campaign_id": campaign.campaign_id,
        "incident_urn": campaign.incident_urn,
        "policy_version": campaign.policy_version,
        "change": {
            "event_id": campaign.change.event_id,
            "entity_urn": campaign.change.entity_urn,
            "aspect_name": campaign.change.aspect_name,
            "kind": campaign.change.kind.value,
            "occurred_at": campaign.change.occurred_at,
            "schema_field_urn": campaign.change.schema_field_urn,
            "before_digest": campaign.change.before_digest,
            "after_digest": campaign.change.after_digest,
        },
        "assessments": [
            {
                "receipt_id": item.receipt_id,
                "document_urn": item.document_urn,
                "state": item.state.value,
                "reason_code": item.reason_code,
                "matched_evidence_ids": list(item.matched_evidence_ids),
                "policy_version": item.policy_version,
            }
            for item in campaign.assessments
        ],
    }


def _campaign_from_dict(value: Mapping[str, Any]) -> InvalidationCampaign:
    raw_change = _mapping(value.get("change"), "campaign change")
    try:
        change = NormalizedChange(
            event_id=_text(raw_change, "event_id"),
            entity_urn=_text(raw_change, "entity_urn"),
            aspect_name=_text(raw_change, "aspect_name"),
            kind=ChangeKind(_text(raw_change, "kind")),
            occurred_at=_text(raw_change, "occurred_at"),
            schema_field_urn=_optional_text(raw_change, "schema_field_urn"),
            before_digest=_optional_text(raw_change, "before_digest"),
            after_digest=_optional_text(raw_change, "after_digest"),
        )
    except (ValueError, PolicyInputError) as exc:
        raise TransactionalStoreError("campaign change is invalid") from exc
    raw_assessments = value.get("assessments")
    if not isinstance(raw_assessments, list):
        raise TransactionalStoreError("campaign assessments must be an array")
    assessments: list[ImpactAssessment] = []
    for raw in raw_assessments:
        selected = _mapping(raw, "campaign assessment")
        matched = selected.get("matched_evidence_ids")
        if not isinstance(matched, list) or not all(
            isinstance(item, str) and item for item in matched
        ):
            raise TransactionalStoreError("matched evidence IDs are invalid")
        try:
            assessment = ImpactAssessment(
                receipt_id=_text(selected, "receipt_id"),
                document_urn=_text(selected, "document_urn"),
                state=ImpactState(_text(selected, "state")),
                reason_code=_text(selected, "reason_code"),
                matched_evidence_ids=tuple(matched),
                policy_version=_text(selected, "policy_version"),
            )
        except ValueError as exc:
            raise TransactionalStoreError("campaign assessment is invalid") from exc
        if assessment.policy_version != POLICY_VERSION:
            raise TransactionalStoreError("campaign assessment policy version is unsupported")
        assessments.append(assessment)
    if len({item.receipt_id for item in assessments}) != len(assessments):
        raise TransactionalStoreError("campaign contains duplicate receipt assessments")
    campaign_id = _text(value, "campaign_id")
    incident_urn = _text(value, "incident_urn")
    policy_version = _text(value, "policy_version")
    expected_campaign, expected_incident = campaign_identity(change)
    if campaign_id != expected_campaign or incident_urn != expected_incident:
        raise TransactionalStoreError("campaign identity does not match its change material")
    if policy_version != POLICY_VERSION:
        raise TransactionalStoreError("campaign policy version is unsupported")
    return InvalidationCampaign(
        campaign_id=campaign_id,
        incident_urn=incident_urn,
        change=change,
        assessments=tuple(assessments),
        policy_version=policy_version,
    )


def _evidence_to_dict(evidence: InvalidationWriteEvidence) -> dict[str, Any]:
    return {
        "incident_aspects": list(evidence.incident_aspects),
        "target_summary_verified": evidence.target_summary_verified,
        "quarantined_documents": list(evidence.quarantined_documents),
    }


def _evidence_from_dict(value: Mapping[str, Any]) -> InvalidationWriteEvidence:
    aspects = value.get("incident_aspects")
    documents = value.get("quarantined_documents")
    summary = value.get("target_summary_verified")
    if not isinstance(aspects, list) or not all(isinstance(item, str) for item in aspects):
        raise TransactionalStoreError("write evidence incident aspects are invalid")
    if not isinstance(documents, list) or not all(isinstance(item, str) for item in documents):
        raise TransactionalStoreError("write evidence documents are invalid")
    if not isinstance(summary, bool):
        raise TransactionalStoreError("write evidence summary flag is invalid")
    return InvalidationWriteEvidence(
        incident_aspects=tuple(aspects),
        target_summary_verified=summary,
        quarantined_documents=tuple(documents),
    )


def _validate_evidence(
    campaign: InvalidationCampaign,
    evidence: InvalidationWriteEvidence,
) -> None:
    expected = tuple(item.document_urn for item in campaign.quarantined)
    if not evidence.valid or evidence.quarantined_documents != expected:
        raise TransactionalStoreError("write evidence does not prove the campaign")


def _publication_evidence_to_dict(
    evidence: ReceiptPublicationEvidence,
) -> dict[str, Any]:
    return {
        "document_urn": evidence.document_urn,
        "aspect_names": list(evidence.aspect_names),
        "emission_count": evidence.emission_count,
    }


def _publication_evidence_from_dict(
    value: Mapping[str, Any],
) -> ReceiptPublicationEvidence:
    document_urn = value.get("document_urn")
    aspect_names = value.get("aspect_names")
    emission_count = value.get("emission_count")
    if not isinstance(document_urn, str) or not document_urn:
        raise TransactionalStoreError("publication evidence document URN is invalid")
    if (
        not isinstance(aspect_names, list)
        or not aspect_names
        or len(aspect_names) > 64
        or not all(isinstance(item, str) and item for item in aspect_names)
        or aspect_names != sorted(aspect_names)
        or len(set(aspect_names)) != len(aspect_names)
    ):
        raise TransactionalStoreError("publication evidence aspect names are invalid")
    if isinstance(emission_count, bool) or emission_count != 2:
        raise TransactionalStoreError("publication evidence emission count is invalid")
    return ReceiptPublicationEvidence(
        document_urn=document_urn,
        aspect_names=tuple(aspect_names),
        emission_count=emission_count,
    )


def _validate_publication_evidence(
    receipt_id: str,
    evidence: ReceiptPublicationEvidence,
) -> None:
    parsed = _publication_evidence_from_dict(_publication_evidence_to_dict(evidence))
    prefix = "gbx:receipt:sha256:"
    digest = receipt_id.removeprefix(prefix)
    if (
        not receipt_id.startswith(prefix)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise TransactionalStoreError("publication receipt ID is invalid")
    expected_urn = f"urn:li:document:glassbox.receipt.{digest}"
    if parsed.document_urn != expected_urn:
        raise TransactionalStoreError(
            "publication evidence document URN does not match its receipt"
        )


def _owner_routing_evidence(destinations: tuple[str, ...]) -> OwnerRoutingEvidence:
    if not isinstance(destinations, tuple):
        raise TransactionalStoreError("owner-routing destinations must be a tuple")
    if len(destinations) > 256:
        raise TransactionalStoreError("owner-routing destinations exceed the bounded limit")
    digests: list[str] = []
    for destination in destinations:
        if not isinstance(destination, str) or not destination or len(destination) > 2_048:
            raise TransactionalStoreError("owner-routing destination is invalid")
        digests.append(hashlib.sha256(_DESTINATION_DOMAIN + destination.encode()).hexdigest())
    if len(set(digests)) != len(digests):
        raise TransactionalStoreError("owner-routing destinations contain duplicates")
    return OwnerRoutingEvidence(
        destination_count=len(destinations),
        destination_digests=tuple(sorted(digests)),
    )


def _routing_evidence_to_dict(evidence: OwnerRoutingEvidence) -> dict[str, Any]:
    return {
        "destination_count": evidence.destination_count,
        "destination_digests": list(evidence.destination_digests),
    }


def _routing_evidence_from_dict(value: Mapping[str, Any]) -> OwnerRoutingEvidence:
    count = value.get("destination_count")
    digests = value.get("destination_digests")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0 or count > 256:
        raise TransactionalStoreError("owner-routing destination count is invalid")
    if (
        not isinstance(digests, list)
        or not all(
            isinstance(item, str)
            and len(item) == 64
            and all(character in "0123456789abcdef" for character in item)
            for item in digests
        )
        or digests != sorted(digests)
        or len(set(digests)) != len(digests)
        or len(digests) != count
    ):
        raise TransactionalStoreError("owner-routing destination digests are invalid")
    return OwnerRoutingEvidence(count, tuple(digests))


def _lineage_to_dict(proof: FieldLineageProof) -> dict[str, object]:
    return {
        "coverage": proof.coverage.value,
        "rule_id": proof.rule_id,
        "wildcard_query": proof.wildcard_query,
    }


def _receipt_id(receipt: Mapping[str, Any]) -> str:
    value = receipt.get("receipt_id")
    if not isinstance(value, str) or not value:
        raise TransactionalStoreError("receipt ID must be a non-empty string")
    return value


def _receipt_core_material(material: Mapping[str, Any]) -> dict[str, object]:
    return {
        "receipt": copy.deepcopy(dict(_mapping(material.get("receipt"), "stored receipt"))),
        "field_lineage": copy.deepcopy(
            dict(_mapping(material.get("field_lineage"), "field lineage"))
        ),
        "superseded_by": material.get("superseded_by"),
    }


def _receipt_material_from_row(row: sqlite3.Row) -> Mapping[str, Any]:
    encoded = _checked_blob(row, "material", "material_sha256", _RECEIPT_DOMAIN)
    return _mapping(json.loads(encoded), "receipt material")


def _signer_admission_evidence(
    signer_trust_policy: SignerTrustPolicy | None,
    receipt: Mapping[str, Any],
) -> SignerAdmissionEvidence | None:
    if signer_trust_policy is None:
        return None
    report = signer_trust_policy.verify_receipt(
        receipt,
        mode=SignerTrustMode.ADMISSION,
    )
    if not report.valid:
        codes = ",".join(report.failure_codes) or "SIGNER_TRUST_FAILED"
        raise PolicyInputError(f"refusing untrusted receipt: {codes}")
    return SignerAdmissionEvidence.from_report(report)


def _verify_signer_admission_evidence(
    value: object,
    receipt: Mapping[str, Any],
    *,
    signer_trust_policy: SignerTrustPolicy | None,
) -> None:
    if value is None:
        if signer_trust_policy is not None:
            raise SignerTrustError("stored receipt has no trusted admission evidence")
        return
    if not isinstance(value, Mapping):
        raise SignerTrustError("stored signer admission evidence must be an object")
    evidence = SignerAdmissionEvidence.from_dict(value)
    evidence.verify_receipt_binding(receipt)


def _dependency_rows(profile: ReceiptDependencyProfile) -> tuple[tuple[object, ...], ...]:
    """Return the canonical relational projection of one verified receipt profile."""

    rows = (
        (
            profile.receipt_id,
            item.evidence_id,
            item.datahub_urn,
            item.schema_field_urn,
            item.state.value,
            item.role.value,
            item.observed_at,
            item.representation_digest,
        )
        for item in profile.dependencies
    )
    return tuple(sorted(rows, key=lambda row: (str(row[0]), str(row[1]))))


def _parse_lineage(value: object) -> FieldLineageProof:
    selected = _mapping(value, "field lineage")
    coverage = selected.get("coverage")
    rule_id = selected.get("rule_id")
    wildcard = selected.get("wildcard_query")
    if not isinstance(coverage, str):
        raise TransactionalStoreError("field lineage coverage must be a string")
    if rule_id is not None and not isinstance(rule_id, str):
        raise TransactionalStoreError("field lineage rule_id is invalid")
    if wildcard is not None and not isinstance(wildcard, bool):
        raise TransactionalStoreError("field lineage wildcard flag is invalid")
    try:
        return FieldLineageProof(
            coverage=FieldCoverage(coverage),
            rule_id=rule_id,
            wildcard_query=wildcard,
        )
    except (ValueError, PolicyInputError) as exc:
        raise TransactionalStoreError("field lineage proof is invalid") from exc


def _checked_blob(
    row: sqlite3.Row,
    material_key: str,
    digest_key: str,
    domain: bytes,
) -> bytes:
    encoded = _blob(row[material_key])
    digest = row[digest_key]
    if not isinstance(digest, str) or _digest(domain, encoded) != digest:
        raise TransactionalStoreError(f"stored {material_key} failed its checksum")
    return encoded


def _blob(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, memoryview):
        return value.tobytes()
    raise TransactionalStoreError("database blob has an invalid type")


def _digest(domain: bytes, value: bytes) -> str:
    return hashlib.sha256(domain + value).hexdigest()


def _mapping(value: object, name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TransactionalStoreError(f"{name} must be an object")
    return value


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise TransactionalStoreError(f"field {key!r} must be non-empty")
    return selected


def _optional_text(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is not None and (not isinstance(selected, str) or not selected):
        raise TransactionalStoreError(f"field {key!r} must be non-empty or null")
    return selected


def _positive_int(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TransactionalStoreError(f"{name} must be a positive integer")


def _nonempty(value: str, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise TransactionalStoreError(f"{name} must be non-empty")


__all__ = [
    "OutboxStatus",
    "OutboxTask",
    "OwnerRoutingEvidence",
    "OwnerRoutingTask",
    "ReceiptPublicationEvidence",
    "ReceiptPublicationTask",
    "SQLiteInvalidationStore",
    "TransactionalIntegrityReport",
    "TransactionalStoreError",
]
