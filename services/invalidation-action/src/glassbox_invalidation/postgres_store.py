"""PostgreSQL transactional receipt index and dual invalidation outbox."""

from __future__ import annotations

import copy
import json
import re
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from typing import Any, cast

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from glassbox_dbom.canonical import canonicalize
from glassbox_dbom.trust import SignerTrustError, SignerTrustMode, SignerTrustPolicy
from glassbox_invalidation.audit_log import (
    AuditPhase,
    CampaignAuditRecord,
    campaign_audit_record,
)
from glassbox_invalidation.transactional_store import (
    _AUDIT_DOMAIN,
    _CAMPAIGN_DOMAIN,
    _EVIDENCE_DOMAIN,
    _PUBLICATION_EVIDENCE_DOMAIN,
    _RECEIPT_DOMAIN,
    _ROUTING_EVIDENCE_DOMAIN,
    OutboxStatus,
    OutboxTask,
    OwnerRoutingEvidence,
    OwnerRoutingTask,
    ReceiptPublicationEvidence,
    ReceiptPublicationTask,
    TransactionalIntegrityReport,
    TransactionalStoreError,
    _blob,
    _campaign_from_dict,
    _campaign_to_dict,
    _dependency_rows,
    _digest,
    _evidence_from_dict,
    _evidence_to_dict,
    _lineage_to_dict,
    _mapping,
    _nonempty,
    _optional_text,
    _owner_routing_evidence,
    _parse_lineage,
    _positive_int,
    _publication_evidence_from_dict,
    _publication_evidence_to_dict,
    _receipt_core_material,
    _receipt_id,
    _routing_evidence_from_dict,
    _routing_evidence_to_dict,
    _signer_admission_evidence,
    _text,
    _validate_evidence,
    _validate_publication_evidence,
    _verify_signer_admission_evidence,
)
from glassbox_policy import (
    FieldLineageProof,
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    PolicyInputError,
    ReceiptDependencyProfile,
)

_SCHEMA_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
POSTGRES_STATE_SCHEMA_VERSION = "3"
_POSTGRES_SCHEMA_VERSION = POSTGRES_STATE_SCHEMA_VERSION
_MINIMUM_SERVER_VERSION = 14_00_00

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS state_metadata (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS receipt_records (
        receipt_id TEXT PRIMARY KEY,
        material BYTEA NOT NULL,
        material_sha256 TEXT NOT NULL
    )
    """,
    """
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
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS receipt_dependencies_datahub_urn
        ON receipt_dependencies(datahub_urn)
    """,
    """
    CREATE INDEX IF NOT EXISTS receipt_dependencies_schema_field_urn
        ON receipt_dependencies(schema_field_urn)
    """,
    """
    CREATE TABLE IF NOT EXISTS receipt_publication_outbox (
        receipt_id TEXT PRIMARY KEY
            REFERENCES receipt_records(receipt_id) ON DELETE RESTRICT,
        status TEXT NOT NULL CHECK (status IN ('READY', 'LEASED', 'COMPLETED')),
        attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
        lease_owner TEXT,
        lease_expires_at_ms BIGINT,
        last_error_type TEXT,
        publication_evidence BYTEA,
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_outbox (
        campaign_id TEXT PRIMARY KEY,
        material BYTEA NOT NULL,
        material_sha256 TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('READY', 'LEASED', 'COMPLETED')),
        attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
        lease_owner TEXT,
        lease_expires_at_ms BIGINT,
        last_error_type TEXT,
        write_evidence BYTEA,
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
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS campaign_audit (
        audit_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
        record_id TEXT PRIMARY KEY,
        campaign_id TEXT NOT NULL REFERENCES campaign_outbox(campaign_id) ON DELETE RESTRICT,
        phase TEXT NOT NULL,
        material BYTEA NOT NULL,
        material_sha256 TEXT NOT NULL
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS campaign_audit_campaign_id
        ON campaign_audit(campaign_id)
    """,
    """
    CREATE TABLE IF NOT EXISTS owner_routing_outbox (
        campaign_id TEXT PRIMARY KEY
            REFERENCES campaign_outbox(campaign_id) ON DELETE RESTRICT,
        status TEXT NOT NULL CHECK (status IN ('READY', 'LEASED', 'COMPLETED')),
        attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
        lease_owner TEXT,
        lease_expires_at_ms BIGINT,
        last_error_type TEXT,
        delivery_evidence BYTEA,
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
    )
    """,
)


class PostgresInvalidationStore:
    """Multi-host state adapter using row locks and the PostgreSQL server clock."""

    def __init__(
        self,
        dsn: str,
        *,
        schema: str = "glassbox",
        require_signature: bool = True,
        signer_trust_policy: SignerTrustPolicy | None = None,
        connect_timeout_seconds: float = 10.0,
        initialize_schema: bool = True,
    ) -> None:
        if not dsn:
            raise TransactionalStoreError("PostgreSQL DSN must be non-empty")
        if not _SCHEMA_NAME.fullmatch(schema):
            raise TransactionalStoreError("PostgreSQL schema name is invalid")
        if connect_timeout_seconds <= 0:
            raise TransactionalStoreError("connect_timeout_seconds must be positive")
        self._dsn = dsn
        self.schema = schema
        self.require_signature = require_signature
        self.signer_trust_policy = signer_trust_policy
        self.connect_timeout_seconds = connect_timeout_seconds
        if initialize_schema:
            self._initialize()
        else:
            self._validate_runtime_schema()
        self.verify_integrity()

    def register(
        self,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None = None,
        superseded_by: str | None = None,
    ) -> bool:
        return self.register_many(((receipt, field_lineage, superseded_by),))[0]

    def register_many(
        self,
        registrations: Sequence[tuple[Mapping[str, Any], FieldLineageProof | None, str | None]],
    ) -> tuple[bool, ...]:
        """Register a complete receipt batch in one PostgreSQL transaction."""

        if not registrations:
            return ()
        with self._transaction() as cursor:
            return tuple(
                self._register_receipt(
                    cursor,
                    receipt,
                    field_lineage=field_lineage,
                    superseded_by=superseded_by,
                )
                for receipt, field_lineage, superseded_by in registrations
            )

    def _register_receipt(
        self,
        cursor: Any,
        receipt: Mapping[str, Any],
        *,
        field_lineage: FieldLineageProof | None,
        superseded_by: str | None,
    ) -> bool:
        """Register one receipt inside an existing PostgreSQL transaction."""

        proof = field_lineage or FieldLineageProof()
        core_material = {
            "receipt": copy.deepcopy(dict(receipt)),
            "field_lineage": _lineage_to_dict(proof),
            "superseded_by": superseded_by,
        }
        encoded_core = canonicalize(core_material)
        receipt_id = _receipt_id(receipt)
        cursor.execute(
            """
            SELECT material, material_sha256 FROM receipt_records
            WHERE receipt_id = %s FOR UPDATE
            """,
            (receipt_id,),
        )
        existing = cursor.fetchone()
        if existing is not None:
            existing_encoded = self._checked_blob(
                existing, "material", "material_sha256", _RECEIPT_DOMAIN
            )
            existing_material = _mapping(json.loads(existing_encoded), "receipt material")
            if canonicalize(_receipt_core_material(existing_material)) == encoded_core:
                self._decode_receipt(existing)
                cursor.execute(
                    """
                    SELECT receipt_id FROM receipt_publication_outbox
                    WHERE receipt_id = %s
                    """,
                    (receipt_id,),
                )
                if cursor.fetchone() is None:
                    raise TransactionalStoreError(
                        "registered receipt has no publication obligation"
                    )
                return False
            raise TransactionalStoreError(
                f"receipt {receipt_id} already has conflicting dependency metadata"
            )
        admission = _signer_admission_evidence(self.signer_trust_policy, receipt)
        profile = ReceiptDependencyProfile.from_receipt(
            receipt,
            field_lineage=proof,
            superseded_by=superseded_by,
            require_signature=self.require_signature,
            signer_trust_policy=self.signer_trust_policy,
            signer_trust_mode=(
                SignerTrustMode.HISTORICAL
                if self.signer_trust_policy is not None
                else SignerTrustMode.ADMISSION
            ),
        )
        material = {
            **core_material,
            "signer_admission": admission.to_dict() if admission is not None else None,
        }
        encoded = canonicalize(material)
        digest = _digest(_RECEIPT_DOMAIN, encoded)
        cursor.execute(
            """
            INSERT INTO receipt_records(receipt_id, material, material_sha256)
            VALUES (%s, %s, %s)
            ON CONFLICT (receipt_id) DO NOTHING
            RETURNING receipt_id
            """,
            (profile.receipt_id, encoded, digest),
        )
        if cursor.fetchone() is None:
            cursor.execute(
                """
                SELECT material, material_sha256 FROM receipt_records
                WHERE receipt_id = %s
                """,
                (profile.receipt_id,),
            )
            existing = cursor.fetchone()
            if (
                existing is not None
                and _blob(existing["material"]) == encoded
                and existing["material_sha256"] == digest
            ):
                cursor.execute(
                    """
                    SELECT receipt_id FROM receipt_publication_outbox
                    WHERE receipt_id = %s
                    """,
                    (profile.receipt_id,),
                )
                if cursor.fetchone() is None:
                    raise TransactionalStoreError(
                        "registered receipt has no publication obligation"
                    )
                return False
            raise TransactionalStoreError(
                f"receipt {profile.receipt_id} already has conflicting dependency metadata"
            )
        cursor.executemany(
            """
            INSERT INTO receipt_dependencies(
                receipt_id, evidence_id, datahub_urn, schema_field_urn,
                evidence_state, evidence_role, observed_at, representation_digest
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            _dependency_rows(profile),
        )
        cursor.execute(
            """
            INSERT INTO receipt_publication_outbox(receipt_id, status)
            VALUES (%s, 'READY')
            """,
            (profile.receipt_id,),
        )
        return True

    def get_receipt_publication_task(self, receipt_id: str) -> ReceiptPublicationTask | None:
        with self._read() as cursor:
            cursor.execute(
                "SELECT * FROM receipt_publication_outbox WHERE receipt_id = %s",
                (receipt_id,),
            )
            row = cursor.fetchone()
        return self._decode_receipt_publication_task(row) if row is not None else None

    def list_receipt_publication_tasks(self) -> tuple[ReceiptPublicationTask, ...]:
        with self._read() as cursor:
            cursor.execute("SELECT * FROM receipt_publication_outbox ORDER BY receipt_id")
            rows = cursor.fetchall()
        return tuple(self._decode_receipt_publication_task(row) for row in rows)

    def claim_receipt_publication(
        self,
        receipt_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> ReceiptPublicationTask | None:
        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        _nonempty(worker_id, "worker_id")
        with self._transaction() as cursor:
            task = self._decode_receipt_publication_task(
                self._locked_receipt_publication(cursor, receipt_id)
            )
            if task.status is OutboxStatus.COMPLETED:
                return None
            server_now_ms = self._server_now_ms(cursor)
            if (
                task.status is OutboxStatus.LEASED
                and task.lease_expires_at_ms is not None
                and task.lease_expires_at_ms > server_now_ms
            ):
                return None
            cursor.execute(
                """
                UPDATE receipt_publication_outbox
                SET status = 'LEASED', attempt_count = attempt_count + 1,
                    lease_owner = %s, lease_expires_at_ms = %s, last_error_type = NULL
                WHERE receipt_id = %s RETURNING *
                """,
                (worker_id, server_now_ms + lease_duration_ms, receipt_id),
            )
            claimed = cursor.fetchone()
            if claimed is None:  # pragma: no cover
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
        with self._transaction() as cursor:
            task = self._decode_receipt_publication_task(
                self._locked_receipt_publication(cursor, receipt_id)
            )
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "receipt-publication lease is not owned by this worker"
                )
            cursor.execute(
                """
                UPDATE receipt_publication_outbox SET lease_expires_at_ms = %s
                WHERE receipt_id = %s RETURNING *
                """,
                (self._server_now_ms(cursor) + lease_duration_ms, receipt_id),
            )
            renewed = cursor.fetchone()
            if renewed is None:  # pragma: no cover
                raise TransactionalStoreError("renewed receipt publication disappeared")
            return self._decode_receipt_publication_task(renewed)

    def release_receipt_publication(
        self, receipt_id: str, *, worker_id: str, error_type: str
    ) -> None:
        _nonempty(error_type, "error_type")
        with self._transaction() as cursor:
            task = self._decode_receipt_publication_task(
                self._locked_receipt_publication(cursor, receipt_id)
            )
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "cannot release a receipt-publication lease owned elsewhere"
                )
            cursor.execute(
                """
                UPDATE receipt_publication_outbox
                SET status = 'READY', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = %s WHERE receipt_id = %s
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
        with self._transaction() as cursor:
            task = self._decode_receipt_publication_task(
                self._locked_receipt_publication(cursor, receipt_id)
            )
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
            cursor.execute(
                """
                UPDATE receipt_publication_outbox
                SET status = 'COMPLETED', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = NULL, publication_evidence = %s,
                    publication_evidence_sha256 = %s WHERE receipt_id = %s
                """,
                (encoded, digest, receipt_id),
            )
        return True

    def all_profiles(self) -> tuple[ReceiptDependencyProfile, ...]:
        with self._read() as cursor:
            cursor.execute(
                "SELECT material, material_sha256 FROM receipt_records ORDER BY receipt_id"
            )
            rows = cursor.fetchall()
        return tuple(self._decode_receipt(row) for row in rows)

    def get_receipt(self, receipt_id: str) -> Mapping[str, Any] | None:
        """Return a defensive copy after checksum and receipt verification."""

        with self._read() as cursor:
            cursor.execute(
                """
                SELECT material, material_sha256 FROM receipt_records
                WHERE receipt_id = %s
                """,
                (receipt_id,),
            )
            row = cursor.fetchone()
        if row is None:
            return None
        profile = self._decode_receipt(row)
        encoded = self._checked_blob(row, "material", "material_sha256", _RECEIPT_DOMAIN)
        material = _mapping(json.loads(encoded), "receipt material")
        receipt = _mapping(material.get("receipt"), "stored receipt")
        if receipt.get("receipt_id") != profile.receipt_id:
            raise TransactionalStoreError("stored receipt identity changed after verification")
        return copy.deepcopy(dict(receipt))

    def candidates(self, change: NormalizedChange) -> tuple[ReceiptDependencyProfile, ...]:
        with self._read() as cursor:
            cursor.execute(
                """
                SELECT r.material, r.material_sha256
                FROM receipt_records AS r
                WHERE EXISTS (
                    SELECT 1
                    FROM receipt_dependencies AS d
                    WHERE d.receipt_id = r.receipt_id
                      AND (
                          d.datahub_urn = %s
                          OR d.datahub_urn IS NULL
                          OR d.evidence_state = 'UNKNOWN'
                      )
                )
                ORDER BY r.receipt_id
                """,
                (change.entity_urn,),
            )
            rows = cursor.fetchall()
        return tuple(self._decode_receipt(row) for row in rows)

    def stage_campaign(self, campaign: InvalidationCampaign) -> bool:
        encoded = canonicalize(_campaign_to_dict(campaign))
        digest = _digest(_CAMPAIGN_DOMAIN, encoded)
        classified = campaign_audit_record(
            campaign,
            AuditPhase.CLASSIFIED,
            detail="policy-complete",
        )
        initial_status = OutboxStatus.READY if campaign.quarantined else OutboxStatus.COMPLETED
        with self._transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO campaign_outbox(
                    campaign_id, material, material_sha256, status
                ) VALUES (%s, %s, %s, %s)
                ON CONFLICT (campaign_id) DO NOTHING
                RETURNING campaign_id
                """,
                (campaign.campaign_id, encoded, digest, initial_status.value),
            )
            inserted = cursor.fetchone() is not None
            if not inserted:
                cursor.execute(
                    """
                    SELECT material, material_sha256 FROM campaign_outbox
                    WHERE campaign_id = %s
                    """,
                    (campaign.campaign_id,),
                )
                existing = cursor.fetchone()
                if (
                    existing is None
                    or _blob(existing["material"]) != encoded
                    or existing["material_sha256"] != digest
                ):
                    raise TransactionalStoreError(
                        f"campaign {campaign.campaign_id} has conflicting outbox material"
                    )
            self._insert_audit(cursor, classified)
        return inserted

    def get_task(self, campaign_id: str) -> OutboxTask | None:
        with self._read() as cursor:
            cursor.execute("SELECT * FROM campaign_outbox WHERE campaign_id = %s", (campaign_id,))
            row = cursor.fetchone()
        return self._decode_task(row) if row is not None else None

    def list_tasks(self) -> tuple[OutboxTask, ...]:
        with self._read() as cursor:
            cursor.execute("SELECT * FROM campaign_outbox ORDER BY campaign_id")
            rows = cursor.fetchall()
        return tuple(self._decode_task(row) for row in rows)

    def claim(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OutboxTask | None:
        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        _nonempty(worker_id, "worker_id")
        with self._transaction() as cursor:
            row = self._locked_campaign(cursor, campaign_id)
            task = self._decode_task(row)
            if task.status is OutboxStatus.COMPLETED:
                return None
            server_now_ms = self._server_now_ms(cursor)
            if (
                task.status is OutboxStatus.LEASED
                and task.lease_expires_at_ms is not None
                and task.lease_expires_at_ms > server_now_ms
            ):
                return None
            cursor.execute(
                """
                UPDATE campaign_outbox
                SET status = 'LEASED', attempt_count = attempt_count + 1,
                    lease_owner = %s, lease_expires_at_ms = %s, last_error_type = NULL
                WHERE campaign_id = %s
                RETURNING *
                """,
                (worker_id, server_now_ms + lease_duration_ms, campaign_id),
            )
            claimed = cursor.fetchone()
            if claimed is None:  # pragma: no cover - row lock and primary key protect this
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
        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        with self._transaction() as cursor:
            task = self._decode_task(self._locked_campaign(cursor, campaign_id))
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("campaign lease is not owned by this worker")
            cursor.execute(
                """
                UPDATE campaign_outbox SET lease_expires_at_ms = %s
                WHERE campaign_id = %s RETURNING *
                """,
                (self._server_now_ms(cursor) + lease_duration_ms, campaign_id),
            )
            renewed = cursor.fetchone()
            if renewed is None:  # pragma: no cover - row lock and primary key protect this
                raise TransactionalStoreError("renewed campaign disappeared")
            return self._decode_task(renewed)

    def release(
        self,
        campaign: InvalidationCampaign,
        *,
        worker_id: str,
        error_type: str,
    ) -> None:
        _nonempty(error_type, "error_type")
        failure = campaign_audit_record(
            campaign,
            AuditPhase.DATAHUB_FAILED,
            detail=f"failure:{error_type}",
        )
        with self._transaction() as cursor:
            task = self._decode_task(self._locked_campaign(cursor, campaign.campaign_id))
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("cannot release a campaign lease owned elsewhere")
            cursor.execute(
                """
                UPDATE campaign_outbox
                SET status = 'READY', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = %s
                WHERE campaign_id = %s
                """,
                (error_type, campaign.campaign_id),
            )
            self._insert_audit(cursor, failure)

    def complete(
        self,
        campaign: InvalidationCampaign,
        evidence: InvalidationWriteEvidence,
        *,
        worker_id: str,
    ) -> bool:
        _validate_evidence(campaign, evidence)
        encoded = canonicalize(_evidence_to_dict(evidence))
        digest = _digest(_EVIDENCE_DOMAIN, encoded)
        verified = campaign_audit_record(
            campaign,
            AuditPhase.DATAHUB_VERIFIED,
            detail="direct-readback",
        )
        with self._transaction() as cursor:
            task = self._decode_task(self._locked_campaign(cursor, campaign.campaign_id))
            if task.status is OutboxStatus.COMPLETED:
                if task.write_evidence != evidence:
                    raise TransactionalStoreError(
                        "completed campaign has conflicting write evidence"
                    )
                cursor.execute(
                    "SELECT campaign_id FROM owner_routing_outbox WHERE campaign_id = %s",
                    (campaign.campaign_id,),
                )
                if cursor.fetchone() is None:
                    raise TransactionalStoreError(
                        "completed material campaign has no owner-routing obligation"
                    )
                self._insert_audit(cursor, verified)
                return False
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("cannot complete a campaign lease owned elsewhere")
            cursor.execute(
                """
                UPDATE campaign_outbox
                SET status = 'COMPLETED', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = NULL, write_evidence = %s, write_evidence_sha256 = %s
                WHERE campaign_id = %s
                """,
                (encoded, digest, campaign.campaign_id),
            )
            cursor.execute(
                """
                INSERT INTO owner_routing_outbox(campaign_id, status)
                VALUES (%s, 'READY')
                """,
                (campaign.campaign_id,),
            )
            self._insert_audit(cursor, verified)
        return True

    def get_owner_routing_task(self, campaign_id: str) -> OwnerRoutingTask | None:
        with self._read() as cursor:
            cursor.execute(
                "SELECT * FROM owner_routing_outbox WHERE campaign_id = %s",
                (campaign_id,),
            )
            row = cursor.fetchone()
        return self._decode_owner_routing_task(row) if row is not None else None

    def list_owner_routing_tasks(self) -> tuple[OwnerRoutingTask, ...]:
        with self._read() as cursor:
            cursor.execute("SELECT * FROM owner_routing_outbox ORDER BY campaign_id")
            rows = cursor.fetchall()
        return tuple(self._decode_owner_routing_task(row) for row in rows)

    def claim_owner_routing(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> OwnerRoutingTask | None:
        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        _nonempty(worker_id, "worker_id")
        with self._transaction() as cursor:
            task = self._decode_owner_routing_task(self._locked_owner_routing(cursor, campaign_id))
            if task.status is OutboxStatus.COMPLETED:
                return None
            server_now_ms = self._server_now_ms(cursor)
            if (
                task.status is OutboxStatus.LEASED
                and task.lease_expires_at_ms is not None
                and task.lease_expires_at_ms > server_now_ms
            ):
                return None
            cursor.execute(
                """
                UPDATE owner_routing_outbox
                SET status = 'LEASED', attempt_count = attempt_count + 1,
                    lease_owner = %s, lease_expires_at_ms = %s, last_error_type = NULL
                WHERE campaign_id = %s
                RETURNING *
                """,
                (worker_id, server_now_ms + lease_duration_ms, campaign_id),
            )
            claimed = cursor.fetchone()
            if claimed is None:  # pragma: no cover - row lock and primary key protect this
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
        _positive_int(now_ms, "now_ms")
        _positive_int(lease_duration_ms, "lease_duration_ms")
        with self._transaction() as cursor:
            task = self._decode_owner_routing_task(self._locked_owner_routing(cursor, campaign_id))
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError("owner-routing lease is not owned by this worker")
            cursor.execute(
                """
                UPDATE owner_routing_outbox SET lease_expires_at_ms = %s
                WHERE campaign_id = %s RETURNING *
                """,
                (self._server_now_ms(cursor) + lease_duration_ms, campaign_id),
            )
            renewed = cursor.fetchone()
            if renewed is None:  # pragma: no cover - row lock and primary key protect this
                raise TransactionalStoreError("renewed owner-routing task disappeared")
            return self._decode_owner_routing_task(renewed)

    def release_owner_routing(
        self,
        campaign: InvalidationCampaign,
        *,
        worker_id: str,
        error_type: str,
    ) -> None:
        _nonempty(error_type, "error_type")
        failure = campaign_audit_record(
            campaign,
            AuditPhase.OWNER_ROUTING_FAILED,
            detail=f"failure:{error_type}",
        )
        with self._transaction() as cursor:
            task = self._decode_owner_routing_task(
                self._locked_owner_routing(cursor, campaign.campaign_id)
            )
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "cannot release an owner-routing lease owned elsewhere"
                )
            cursor.execute(
                """
                UPDATE owner_routing_outbox
                SET status = 'READY', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = %s
                WHERE campaign_id = %s
                """,
                (error_type, campaign.campaign_id),
            )
            self._insert_audit(cursor, failure)

    def complete_owner_routing(
        self,
        campaign: InvalidationCampaign,
        destinations: tuple[str, ...],
        *,
        worker_id: str,
    ) -> OwnerRoutingEvidence:
        evidence = _owner_routing_evidence(destinations)
        encoded = canonicalize(_routing_evidence_to_dict(evidence))
        digest = _digest(_ROUTING_EVIDENCE_DOMAIN, encoded)
        accepted = campaign_audit_record(
            campaign,
            AuditPhase.OWNER_ROUTING_ACCEPTED,
            detail=f"destinations:{evidence.destination_count}",
        )
        with self._transaction() as cursor:
            task = self._decode_owner_routing_task(
                self._locked_owner_routing(cursor, campaign.campaign_id)
            )
            if task.status is OutboxStatus.COMPLETED:
                if task.delivery_evidence != evidence:
                    raise TransactionalStoreError(
                        "completed owner routing has conflicting delivery evidence"
                    )
                self._insert_audit(cursor, accepted)
                return evidence
            if task.status is not OutboxStatus.LEASED or task.lease_owner != worker_id:
                raise TransactionalStoreError(
                    "cannot complete an owner-routing lease owned elsewhere"
                )
            cursor.execute(
                """
                UPDATE owner_routing_outbox
                SET status = 'COMPLETED', lease_owner = NULL, lease_expires_at_ms = NULL,
                    last_error_type = NULL, delivery_evidence = %s,
                    delivery_evidence_sha256 = %s
                WHERE campaign_id = %s
                """,
                (encoded, digest, campaign.campaign_id),
            )
            self._insert_audit(cursor, accepted)
        return evidence

    def read_audit_records(self) -> tuple[CampaignAuditRecord, ...]:
        with self._read() as cursor:
            cursor.execute(
                "SELECT material, material_sha256 FROM campaign_audit ORDER BY audit_sequence"
            )
            rows = cursor.fetchall()
        return tuple(self._decode_audit(row) for row in rows)

    def verify_integrity(self) -> TransactionalIntegrityReport:
        with self._read() as cursor:
            self._verify_schema_version(cursor)
            cursor.execute(
                "SELECT material, material_sha256 FROM receipt_records ORDER BY receipt_id"
            )
            receipt_rows = cursor.fetchall()
            cursor.execute(
                """
                SELECT receipt_id, evidence_id, datahub_urn, schema_field_urn,
                       evidence_state, evidence_role, observed_at,
                       representation_digest
                FROM receipt_dependencies
                ORDER BY receipt_id, evidence_id
                """
            )
            dependency_rows = cursor.fetchall()
            cursor.execute("SELECT * FROM receipt_publication_outbox ORDER BY receipt_id")
            publication_rows = cursor.fetchall()
            cursor.execute("SELECT * FROM campaign_outbox ORDER BY campaign_id")
            task_rows = cursor.fetchall()
            cursor.execute("SELECT * FROM owner_routing_outbox ORDER BY campaign_id")
            routing_rows = cursor.fetchall()
            cursor.execute(
                "SELECT material, material_sha256 FROM campaign_audit ORDER BY audit_sequence"
            )
            audit_rows = cursor.fetchall()
            cursor.execute(
                """
                SELECT campaign_id FROM campaign_outbox AS campaign
                WHERE campaign.status = 'COMPLETED'
                  AND campaign.write_evidence IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM owner_routing_outbox AS routing
                      WHERE routing.campaign_id = campaign.campaign_id
                  )
                """
            )
            missing_routing = cursor.fetchall()
            cursor.execute(
                """
                SELECT routing.campaign_id
                FROM owner_routing_outbox AS routing
                JOIN campaign_outbox AS campaign
                  ON campaign.campaign_id = routing.campaign_id
                WHERE campaign.status != 'COMPLETED'
                   OR campaign.write_evidence IS NULL
                """
            )
            premature_routing = cursor.fetchall()
            cursor.execute(
                """
                SELECT receipt_id FROM receipt_records AS receipt
                WHERE NOT EXISTS (
                    SELECT 1 FROM receipt_publication_outbox AS publication
                    WHERE publication.receipt_id = receipt.receipt_id
                )
                """
            )
            missing_publications = cursor.fetchall()
        profiles = tuple(self._decode_receipt(row) for row in receipt_rows)
        expected_dependencies = tuple(
            row for profile in profiles for row in _dependency_rows(profile)
        )
        actual_dependencies = tuple(
            (
                row["receipt_id"],
                row["evidence_id"],
                row["datahub_urn"],
                row["schema_field_urn"],
                row["evidence_state"],
                row["evidence_role"],
                row["observed_at"],
                row["representation_digest"],
            )
            for row in dependency_rows
        )
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

    def _initialize(self) -> None:
        try:
            with self._connection(set_search_path=False) as connection:
                with connection.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(
                            sql.Identifier(self.schema)
                        )
                    )
                    self._set_search_path(cursor)
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s))",
                        (f"glassbox.postgres-schema.{self.schema}",),
                    )
                    cursor.execute("SHOW server_version_num")
                    version = cursor.fetchone()
                    if (
                        version is None
                        or int(version["server_version_num"]) < _MINIMUM_SERVER_VERSION
                    ):
                        raise TransactionalStoreError("PostgreSQL 14 or newer is required")
                    cursor.execute(_DDL[0])
                    cursor.execute("SELECT value FROM state_metadata WHERE key = 'schema_version'")
                    schema_version = cursor.fetchone()
                    if schema_version is None:
                        cursor.execute(
                            """
                            SELECT table_name
                            FROM information_schema.tables
                            WHERE table_schema = %s
                              AND table_name != 'state_metadata'
                            LIMIT 1
                            """,
                            (self.schema,),
                        )
                        if cursor.fetchone() is not None:
                            raise TransactionalStoreError(
                                "PostgreSQL schema has application tables but no schema version"
                            )
                        cursor.execute(
                            """
                            INSERT INTO state_metadata(key, value)
                            VALUES ('schema_version', %s)
                            """,
                            (_POSTGRES_SCHEMA_VERSION,),
                        )
                    elif schema_version["value"] != _POSTGRES_SCHEMA_VERSION:
                        raise TransactionalStoreError(
                            "PostgreSQL state schema version is unsupported"
                        )
                    for statement in _DDL[1:]:
                        cursor.execute(statement)
        except psycopg.Error as exc:
            raise TransactionalStoreError("failed to initialize PostgreSQL store") from exc

    def _validate_runtime_schema(self) -> None:
        """Verify runtime prerequisites without issuing schema or table DDL."""

        try:
            with self._connection(set_search_path=False) as connection:
                with connection.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM information_schema.tables
                            WHERE table_schema = %s AND table_name = 'state_metadata'
                        ) AS initialized
                        """,
                        (self.schema,),
                    )
                    row = cursor.fetchone()
                    if row is None or row["initialized"] is not True:
                        raise TransactionalStoreError(
                            "PostgreSQL state schema is not initialized; run postgres-init"
                        )
                    self._set_search_path(cursor)
                    self._verify_schema_version(cursor)
        except psycopg.Error as exc:
            raise TransactionalStoreError("failed to validate PostgreSQL runtime schema") from exc

    def _connect(self) -> psycopg.Connection[Any]:
        try:
            return psycopg.connect(
                self._dsn,
                connect_timeout=max(1, int(self.connect_timeout_seconds)),
                row_factory=dict_row,
            )
        except psycopg.Error as exc:
            raise TransactionalStoreError("failed to connect to PostgreSQL store") from exc

    @contextmanager
    def _connection(
        self,
        *,
        set_search_path: bool = True,
    ) -> Iterator[psycopg.Connection[Any]]:
        connection = self._connect()
        try:
            if set_search_path:
                with connection.cursor() as cursor:
                    self._set_search_path(cursor)
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @contextmanager
    def _transaction(self) -> Iterator[Any]:
        try:
            with self._connection() as connection:
                with connection.cursor(row_factory=dict_row) as cursor:
                    yield cursor
        except psycopg.Error as exc:
            raise TransactionalStoreError("PostgreSQL transactional write failed") from exc

    @contextmanager
    def _read(self) -> Iterator[Any]:
        try:
            with self._connection() as connection:
                with connection.cursor(row_factory=dict_row) as cursor:
                    yield cursor
        except psycopg.Error as exc:
            raise TransactionalStoreError("PostgreSQL state read failed") from exc

    def _set_search_path(self, cursor: Any) -> None:
        cursor.execute(
            sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(sql.Identifier(self.schema))
        )

    @staticmethod
    def _server_now_ms(cursor: Any) -> int:
        cursor.execute(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms"
        )
        row = cursor.fetchone()
        if row is None or not isinstance(row["now_ms"], int):
            raise TransactionalStoreError("PostgreSQL server clock is invalid")
        return row["now_ms"]

    @staticmethod
    def _locked_campaign(cursor: Any, campaign_id: str) -> Mapping[str, Any]:
        cursor.execute(
            "SELECT * FROM campaign_outbox WHERE campaign_id = %s FOR UPDATE",
            (campaign_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise TransactionalStoreError(f"campaign {campaign_id} is not staged")
        return cast(Mapping[str, Any], row)

    @staticmethod
    def _locked_owner_routing(cursor: Any, campaign_id: str) -> Mapping[str, Any]:
        cursor.execute(
            "SELECT * FROM owner_routing_outbox WHERE campaign_id = %s FOR UPDATE",
            (campaign_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise TransactionalStoreError(f"owner routing for campaign {campaign_id} is not staged")
        return cast(Mapping[str, Any], row)

    @staticmethod
    def _locked_receipt_publication(cursor: Any, receipt_id: str) -> Mapping[str, Any]:
        cursor.execute(
            "SELECT * FROM receipt_publication_outbox WHERE receipt_id = %s FOR UPDATE",
            (receipt_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise TransactionalStoreError(f"receipt publication {receipt_id} is not staged")
        return cast(Mapping[str, Any], row)

    @staticmethod
    def _verify_schema_version(cursor: Any) -> None:
        cursor.execute("SELECT value FROM state_metadata WHERE key = 'schema_version'")
        row = cursor.fetchone()
        if row is None or row["value"] != _POSTGRES_SCHEMA_VERSION:
            raise TransactionalStoreError("PostgreSQL state schema version is unsupported")

    def _decode_receipt(self, row: Mapping[str, Any]) -> ReceiptDependencyProfile:
        encoded = self._checked_blob(row, "material", "material_sha256", _RECEIPT_DOMAIN)
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

    def _decode_receipt_publication_task(self, row: Mapping[str, Any]) -> ReceiptPublicationTask:
        receipt_id = row["receipt_id"]
        if not isinstance(receipt_id, str) or not receipt_id:
            raise TransactionalStoreError("receipt-publication task has an invalid receipt ID")
        status = self._status(row, "receipt-publication task")
        attempt_count = self._attempt_count(row, "receipt-publication task")
        lease_owner, lease_expires = self._lease(row, status, "receipt-publication task")
        last_error = self._last_error(row, "receipt-publication task")
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

    def _decode_task(self, row: Mapping[str, Any]) -> OutboxTask:
        encoded = self._checked_blob(row, "material", "material_sha256", _CAMPAIGN_DOMAIN)
        campaign = _campaign_from_dict(_mapping(json.loads(encoded), "campaign material"))
        status = self._status(row, "campaign outbox")
        attempt_count = self._attempt_count(row, "campaign outbox")
        lease_owner, lease_expires = self._lease(row, status, "campaign")
        last_error = self._last_error(row, "campaign outbox")
        raw_evidence = row["write_evidence"]
        raw_digest = row["write_evidence_sha256"]
        evidence: InvalidationWriteEvidence | None = None
        if raw_evidence is not None or raw_digest is not None:
            if raw_evidence is None or not isinstance(raw_digest, str):
                raise TransactionalStoreError("campaign write evidence envelope is incomplete")
            evidence_blob = _blob(raw_evidence)
            if _digest(_EVIDENCE_DOMAIN, evidence_blob) != raw_digest:
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

    def _decode_owner_routing_task(self, row: Mapping[str, Any]) -> OwnerRoutingTask:
        campaign_id = row["campaign_id"]
        if not isinstance(campaign_id, str) or not campaign_id:
            raise TransactionalStoreError("owner-routing task has an invalid campaign ID")
        status = self._status(row, "owner-routing task")
        attempt_count = self._attempt_count(row, "owner-routing task")
        lease_owner, lease_expires = self._lease(row, status, "owner-routing task")
        last_error = self._last_error(row, "owner-routing task")
        raw_evidence = row["delivery_evidence"]
        raw_digest = row["delivery_evidence_sha256"]
        evidence: OwnerRoutingEvidence | None = None
        if raw_evidence is not None or raw_digest is not None:
            if raw_evidence is None or not isinstance(raw_digest, str):
                raise TransactionalStoreError(
                    "owner-routing delivery evidence envelope is incomplete"
                )
            evidence_blob = _blob(raw_evidence)
            if _digest(_ROUTING_EVIDENCE_DOMAIN, evidence_blob) != raw_digest:
                raise TransactionalStoreError("owner-routing delivery evidence failed its checksum")
            evidence = _routing_evidence_from_dict(
                _mapping(json.loads(evidence_blob), "owner-routing delivery evidence")
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

    def _insert_audit(self, cursor: Any, record: CampaignAuditRecord) -> bool:
        encoded = canonicalize(record.to_dict())
        digest = _digest(_AUDIT_DOMAIN, encoded)
        cursor.execute(
            """
            INSERT INTO campaign_audit(
                record_id, campaign_id, phase, material, material_sha256
            ) VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (record_id) DO NOTHING
            RETURNING record_id
            """,
            (record.record_id, record.campaign_id, record.phase.value, encoded, digest),
        )
        if cursor.fetchone() is not None:
            return True
        cursor.execute(
            """
            SELECT material, material_sha256 FROM campaign_audit WHERE record_id = %s
            """,
            (record.record_id,),
        )
        existing = cursor.fetchone()
        if (
            existing is not None
            and _blob(existing["material"]) == encoded
            and existing["material_sha256"] == digest
        ):
            return False
        raise TransactionalStoreError(f"audit record {record.record_id} conflicts")

    def _decode_audit(self, row: Mapping[str, Any]) -> CampaignAuditRecord:
        encoded = self._checked_blob(row, "material", "material_sha256", _AUDIT_DOMAIN)
        material = _mapping(json.loads(encoded), "audit material")
        counts = _mapping(material.get("impact_counts"), "audit impact counts")
        parsed_counts: list[tuple[str, int]] = []
        for key, count in counts.items():
            if not isinstance(key, str) or isinstance(count, bool) or not isinstance(count, int):
                raise TransactionalStoreError("audit impact counts are invalid")
            parsed_counts.append((key, count))
        try:
            phase = AuditPhase(_text(material, "phase"))
        except ValueError as exc:
            raise TransactionalStoreError("audit phase is invalid") from exc
        return CampaignAuditRecord(
            record_id=_text(material, "record_id"),
            campaign_id=_text(material, "campaign_id"),
            change_event_id=_text(material, "change_event_id"),
            incident_urn=_text(material, "incident_urn"),
            policy_version=_text(material, "policy_version"),
            phase=phase,
            impact_counts=tuple(sorted(parsed_counts)),
            detail=_text(material, "detail"),
        )

    @staticmethod
    def _checked_blob(
        row: Mapping[str, Any],
        material_key: str,
        digest_key: str,
        domain: bytes,
    ) -> bytes:
        encoded = _blob(row[material_key])
        digest = row[digest_key]
        if not isinstance(digest, str) or _digest(domain, encoded) != digest:
            raise TransactionalStoreError(f"stored {material_key} failed its checksum")
        return encoded

    @staticmethod
    def _status(row: Mapping[str, Any], name: str) -> OutboxStatus:
        try:
            return OutboxStatus(row["status"])
        except (TypeError, ValueError) as exc:
            raise TransactionalStoreError(f"{name} has an invalid status") from exc

    @staticmethod
    def _attempt_count(row: Mapping[str, Any], name: str) -> int:
        value = row["attempt_count"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TransactionalStoreError(f"{name} has an invalid attempt count")
        return value

    @staticmethod
    def _lease(
        row: Mapping[str, Any],
        status: OutboxStatus,
        name: str,
    ) -> tuple[str | None, int | None]:
        owner = row["lease_owner"]
        expires = row["lease_expires_at_ms"]
        if status is OutboxStatus.LEASED:
            if not isinstance(owner, str) or not owner:
                raise TransactionalStoreError(f"leased {name} has no owner")
            if isinstance(expires, bool) or not isinstance(expires, int):
                raise TransactionalStoreError(f"leased {name} has no expiration")
        elif owner is not None or expires is not None:
            raise TransactionalStoreError(f"unleased {name} contains lease metadata")
        return owner, expires

    @staticmethod
    def _last_error(row: Mapping[str, Any], name: str) -> str | None:
        value = row["last_error_type"]
        if value is not None and (not isinstance(value, str) or not value):
            raise TransactionalStoreError(f"{name} has an invalid error type")
        return value


__all__ = ["PostgresInvalidationStore"]
