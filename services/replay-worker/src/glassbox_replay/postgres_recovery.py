"""PostgreSQL recovery workflow state linked to the invalidation authority."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, cast

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from glassbox_dbom.canonical import canonicalize
from glassbox_replay.orchestration import (
    RecoveryArtifacts,
    RecoveryAuthority,
    RecoveryEffectEvidence,
    RecoveryJob,
    RecoveryOperation,
    RecoveryStage,
    authorization_from_dict,
    recovery_workflow_id,
)
from glassbox_replay.recovery import RecoveryAuthorization, verify_recovery_authorization

POSTGRES_RECOVERY_SCHEMA_VERSION = "2"
_SCHEMA_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
_MINIMUM_SERVER_VERSION = 14_00_00
_JOB_DOMAIN = b"glassbox.postgres-recovery-job.v1\0"
_ARTIFACT_DOMAIN = b"glassbox.postgres-recovery-artifacts.v2\0"
_EVIDENCE_DOMAIN = b"glassbox.postgres-recovery-evidence.v1\0"
_EVENT_DOMAIN = b"glassbox.postgres-recovery-event.v1\0"

_DDL = (
    """
    CREATE TABLE IF NOT EXISTS recovery_jobs (
        workflow_id TEXT PRIMARY KEY,
        campaign_id TEXT UNIQUE NOT NULL
            REFERENCES campaign_outbox(campaign_id) ON DELETE RESTRICT,
        authorization_id TEXT UNIQUE NOT NULL,
        source_receipt_id TEXT NOT NULL
            REFERENCES receipt_records(receipt_id) ON DELETE RESTRICT,
        bundle_id TEXT NOT NULL,
        job_material BYTEA NOT NULL,
        job_material_sha256 TEXT NOT NULL,
        stage TEXT NOT NULL CHECK (stage IN (
            'AUTHORIZED',
            'ISOLATED_EXECUTION_SUCCEEDED',
            'REPLAY_RECEIPT_PUBLISHED',
            'SUPERSESSION_VERIFIED',
            'INCIDENT_CLOSED'
        )),
        stage_version BIGINT NOT NULL DEFAULT 0 CHECK (stage_version >= 0),
        attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
        lease_operation TEXT CHECK (lease_operation IN (
            'EXECUTE_ISOLATED_REPLAY',
            'PUBLISH_REPLAY_RECEIPT',
            'PUBLISH_SUPERSESSION',
            'CLOSE_INCIDENT'
        )),
        lease_owner TEXT,
        lease_expires_at_ms BIGINT,
        last_error_type TEXT,
        artifacts BYTEA,
        artifacts_sha256 TEXT,
        replay_publication_evidence BYTEA,
        replay_publication_evidence_sha256 TEXT,
        supersession_publication_evidence BYTEA,
        supersession_publication_evidence_sha256 TEXT,
        incident_closure_evidence BYTEA,
        incident_closure_evidence_sha256 TEXT,
        replay_receipt_id TEXT,
        supersession_id TEXT,
        closure_id TEXT,
        CHECK (
            (lease_operation IS NOT NULL AND lease_owner IS NOT NULL
                AND lease_expires_at_ms IS NOT NULL)
            OR
            (lease_operation IS NULL AND lease_owner IS NULL
                AND lease_expires_at_ms IS NULL)
        ),
        CHECK ((artifacts IS NULL) = (artifacts_sha256 IS NULL)),
        CHECK (
            (replay_publication_evidence IS NULL)
            = (replay_publication_evidence_sha256 IS NULL)
        ),
        CHECK (
            (supersession_publication_evidence IS NULL)
            = (supersession_publication_evidence_sha256 IS NULL)
        ),
        CHECK (
            (incident_closure_evidence IS NULL)
            = (incident_closure_evidence_sha256 IS NULL)
        )
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS recovery_jobs_stage
        ON recovery_jobs(stage)
    """,
    """
    CREATE TABLE IF NOT EXISTS recovery_events (
        event_sequence BIGINT GENERATED ALWAYS AS IDENTITY UNIQUE,
        event_id TEXT PRIMARY KEY,
        workflow_id TEXT NOT NULL
            REFERENCES recovery_jobs(workflow_id) ON DELETE RESTRICT,
        stage TEXT NOT NULL,
        stage_version BIGINT NOT NULL CHECK (stage_version >= 0),
        material BYTEA NOT NULL,
        material_sha256 TEXT NOT NULL,
        UNIQUE (workflow_id, stage_version)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS recovery_events_workflow
        ON recovery_events(workflow_id, stage_version)
    """,
)


class RecoveryStoreError(RuntimeError):
    """Raised when durable recovery state is unavailable, corrupt, or conflicting."""


@dataclass(frozen=True)
class RecoveryStateEvent:
    """Append-only evidence of one committed durable checkpoint."""

    event_id: str
    workflow_id: str
    from_stage: str | None
    to_stage: RecoveryStage
    operation: str
    stage_version: int
    attempt_count: int
    artifact_or_evidence_id: str
    recorded_at_ms: int

    @property
    def valid(self) -> bool:
        return self.event_id == _event_id(self._material())

    def to_dict(self) -> dict[str, object]:
        return {"event_id": self.event_id, **self._material()}

    def _material(self) -> dict[str, object]:
        return {
            "workflow_id": self.workflow_id,
            "from_stage": self.from_stage,
            "to_stage": self.to_stage.value,
            "operation": self.operation,
            "stage_version": self.stage_version,
            "attempt_count": self.attempt_count,
            "artifact_or_evidence_id": self.artifact_or_evidence_id,
            "recorded_at_ms": self.recorded_at_ms,
        }


@dataclass(frozen=True)
class RecoveryIntegrityReport:
    """Counts returned only after all workflow and event checks pass."""

    workflows: int
    active_workflows: int
    closed_workflows: int
    events: int


class PostgresRecoveryStore:
    """Server-clock leases and durable raw-free recovery artifacts in PostgreSQL."""

    def __init__(
        self,
        dsn: str,
        authority: RecoveryAuthority,
        *,
        schema: str = "glassbox",
        connect_timeout_seconds: float = 10.0,
        initialize_schema: bool = True,
    ) -> None:
        if not dsn:
            raise RecoveryStoreError("PostgreSQL DSN must be non-empty")
        if not _SCHEMA_NAME.fullmatch(schema):
            raise RecoveryStoreError("PostgreSQL recovery schema name is invalid")
        if connect_timeout_seconds <= 0:
            raise RecoveryStoreError("connect_timeout_seconds must be positive")
        authority_schema = getattr(authority, "schema", schema)
        if authority_schema != schema:
            raise RecoveryStoreError("recovery and invalidation state must use one schema")
        self._dsn = dsn
        self._authority = authority
        self.schema = schema
        self.connect_timeout_seconds = connect_timeout_seconds
        if initialize_schema:
            self._initialize()
        else:
            self._validate_runtime_schema()
        self.verify_integrity()

    def stage_authorized(
        self,
        authorization: RecoveryAuthorization,
        bundle: Mapping[str, Any],
        *,
        evaluated_at: str,
        trusted_signer_fingerprints: Mapping[str, str],
    ) -> bool:
        """Persist one independently verified handoff linked to live Action state."""

        task = self._authority.get_task(authorization.campaign_id)
        source = self._authority.get_receipt(authorization.source_receipt_id)
        if task is None or source is None:
            raise RecoveryStoreError("authorized recovery source state is unavailable")
        verification = verify_recovery_authorization(
            authorization,
            task,
            source,
            bundle,
            evaluated_at=evaluated_at,
            trusted_signer_fingerprints=trusted_signer_fingerprints,
        )
        if not verification.valid:
            raise RecoveryStoreError("recovery authorization failed live-state verification")
        workflow_id = recovery_workflow_id(authorization)
        material = {
            "authorization": authorization.to_dict(),
            "bundle": json.loads(canonicalize(bundle)),
        }
        encoded = canonicalize(material)
        digest = _checksum(_JOB_DOMAIN, encoded)
        with self._transaction() as cursor:
            cursor.execute(
                """
                INSERT INTO recovery_jobs(
                    workflow_id, campaign_id, authorization_id, source_receipt_id,
                    bundle_id, job_material, job_material_sha256, stage
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'AUTHORIZED')
                ON CONFLICT (campaign_id) DO NOTHING
                RETURNING workflow_id
                """,
                (
                    workflow_id,
                    authorization.campaign_id,
                    authorization.authorization_id,
                    authorization.source_receipt_id,
                    authorization.bundle_id,
                    encoded,
                    digest,
                ),
            )
            inserted = cursor.fetchone() is not None
            if not inserted:
                cursor.execute(
                    "SELECT * FROM recovery_jobs WHERE campaign_id = %s FOR UPDATE",
                    (authorization.campaign_id,),
                )
                existing = cursor.fetchone()
                if existing is None or (
                    existing["workflow_id"] != workflow_id
                    or _bytes(existing["job_material"]) != encoded
                    or existing["job_material_sha256"] != digest
                ):
                    raise RecoveryStoreError(
                        "campaign already has a different recovery authorization"
                    )
                return False
            now_ms = self._server_now_ms(cursor)
            self._insert_event(
                cursor,
                workflow_id=workflow_id,
                from_stage=None,
                to_stage=RecoveryStage.AUTHORIZED,
                operation="STAGE_AUTHORIZATION",
                stage_version=0,
                attempt_count=0,
                artifact_or_evidence_id=authorization.authorization_id,
                recorded_at_ms=now_ms,
            )
        return True

    def get(self, campaign_id: str) -> RecoveryJob | None:
        with self._read() as cursor:
            cursor.execute("SELECT * FROM recovery_jobs WHERE campaign_id = %s", (campaign_id,))
            row = cursor.fetchone()
        return self._decode_job(row) if row is not None else None

    def list(self) -> tuple[RecoveryJob, ...]:
        with self._read() as cursor:
            cursor.execute("SELECT * FROM recovery_jobs ORDER BY campaign_id")
            rows = cursor.fetchall()
        return tuple(self._decode_job(row) for row in rows)

    def claim(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> RecoveryJob | None:
        _positive(now_ms, "now_ms")
        _positive(lease_duration_ms, "lease_duration_ms")
        _nonempty(worker_id, "worker_id")
        with self._transaction() as cursor:
            job = self._decode_job(self._locked_job(cursor, campaign_id))
            operation = job.next_operation
            if operation is None:
                return None
            server_now_ms = self._server_now_ms(cursor)
            if (
                job.lease_operation is not None
                and job.lease_expires_at_ms is not None
                and job.lease_expires_at_ms > server_now_ms
            ):
                return None
            cursor.execute(
                """
                UPDATE recovery_jobs
                SET attempt_count = attempt_count + 1,
                    lease_operation = %s,
                    lease_owner = %s,
                    lease_expires_at_ms = %s,
                    last_error_type = NULL
                WHERE campaign_id = %s
                RETURNING *
                """,
                (
                    operation.value,
                    worker_id,
                    server_now_ms + lease_duration_ms,
                    campaign_id,
                ),
            )
            claimed = cursor.fetchone()
            if claimed is None:  # pragma: no cover - primary key and row lock protect this
                raise RecoveryStoreError("claimed recovery workflow disappeared")
            return self._decode_job(claimed)

    def renew(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> RecoveryJob:
        _positive(now_ms, "now_ms")
        _positive(lease_duration_ms, "lease_duration_ms")
        with self._transaction() as cursor:
            job = self._decode_job(self._locked_job(cursor, campaign_id))
            self._require_owned(job, worker_id)
            cursor.execute(
                """
                UPDATE recovery_jobs SET lease_expires_at_ms = %s
                WHERE campaign_id = %s RETURNING *
                """,
                (self._server_now_ms(cursor) + lease_duration_ms, campaign_id),
            )
            renewed = cursor.fetchone()
            if renewed is None:  # pragma: no cover
                raise RecoveryStoreError("renewed recovery workflow disappeared")
            return self._decode_job(renewed)

    def release(self, campaign_id: str, *, worker_id: str, error_type: str) -> None:
        _nonempty(error_type, "error_type")
        with self._transaction() as cursor:
            job = self._decode_job(self._locked_job(cursor, campaign_id))
            self._require_owned(job, worker_id)
            cursor.execute(
                """
                UPDATE recovery_jobs
                SET lease_operation = NULL, lease_owner = NULL,
                    lease_expires_at_ms = NULL, last_error_type = %s
                WHERE campaign_id = %s
                """,
                (error_type, campaign_id),
            )

    def complete_execution(
        self,
        campaign_id: str,
        artifacts: RecoveryArtifacts,
        *,
        worker_id: str,
    ) -> bool:
        if not artifacts.valid:
            raise RecoveryStoreError("recovery execution artifacts are invalid")
        encoded = canonicalize(artifacts.to_dict())
        digest = _checksum(_ARTIFACT_DOMAIN, encoded)
        with self._transaction() as cursor:
            job = self._decode_job(self._locked_job(cursor, campaign_id))
            if job.stage is not RecoveryStage.AUTHORIZED:
                if job.artifacts == artifacts:
                    return False
                raise RecoveryStoreError("recovery execution has conflicting artifacts")
            self._require_owned(
                job,
                worker_id,
                operation=RecoveryOperation.EXECUTE_ISOLATED_REPLAY,
            )
            if (
                artifacts.closure.authorization_id != job.authorization.authorization_id
                or artifacts.closure.campaign_id != job.campaign_id
                or artifacts.closure.source_receipt_id != job.source_receipt_id
                or artifacts.closure.bundle_id != job.bundle_id
            ):
                raise RecoveryStoreError("execution artifacts do not bind the recovery workflow")
            next_stage = RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED
            next_version = job.stage_version + 1
            cursor.execute(
                """
                UPDATE recovery_jobs
                SET stage = %s, stage_version = %s,
                    lease_operation = NULL, lease_owner = NULL,
                    lease_expires_at_ms = NULL, last_error_type = NULL,
                    artifacts = %s, artifacts_sha256 = %s,
                    replay_receipt_id = %s, supersession_id = %s, closure_id = %s
                WHERE campaign_id = %s
                """,
                (
                    next_stage.value,
                    next_version,
                    encoded,
                    digest,
                    artifacts.replay_receipt["receipt_id"],
                    artifacts.supersession.supersession_id,
                    artifacts.closure.closure_id,
                    campaign_id,
                ),
            )
            self._insert_event(
                cursor,
                workflow_id=job.workflow_id,
                from_stage=job.stage.value,
                to_stage=next_stage,
                operation=RecoveryOperation.EXECUTE_ISOLATED_REPLAY.value,
                stage_version=next_version,
                attempt_count=job.attempt_count,
                artifact_or_evidence_id=artifacts.artifact_set_id,
                recorded_at_ms=self._server_now_ms(cursor),
            )
        return True

    def complete_effect(
        self,
        campaign_id: str,
        evidence: RecoveryEffectEvidence,
        *,
        worker_id: str,
    ) -> bool:
        if not evidence.valid or evidence.campaign_id != campaign_id:
            raise RecoveryStoreError("recovery effect evidence is invalid")
        expected_stage, next_stage, column, digest_column = _effect_transition(evidence.operation)
        encoded = canonicalize(evidence.to_dict())
        digest = _checksum(_EVIDENCE_DOMAIN, encoded)
        with self._transaction() as cursor:
            job = self._decode_job(self._locked_job(cursor, campaign_id))
            stored = _evidence_for_operation(job, evidence.operation)
            if _stage_at_or_after(job.stage, next_stage):
                if stored == evidence:
                    return False
                raise RecoveryStoreError("recovery stage has conflicting effect evidence")
            if job.stage is not expected_stage:
                raise RecoveryStoreError("recovery effect attempted out of order")
            self._require_owned(job, worker_id, operation=evidence.operation)
            if job.artifacts is None:
                raise RecoveryStoreError("recovery effect is missing persisted artifacts")
            expected_artifact = _artifact_for_operation(job.artifacts, evidence.operation)
            if evidence.artifact_id != expected_artifact:
                raise RecoveryStoreError("recovery effect evidence binds the wrong artifact")
            next_version = job.stage_version + 1
            statement = sql.SQL(
                """
                UPDATE recovery_jobs
                SET stage = %s, stage_version = %s,
                    lease_operation = NULL, lease_owner = NULL,
                    lease_expires_at_ms = NULL, last_error_type = NULL,
                    {} = %s, {} = %s
                WHERE campaign_id = %s
                """
            ).format(sql.Identifier(column), sql.Identifier(digest_column))
            cursor.execute(
                statement,
                (next_stage.value, next_version, encoded, digest, campaign_id),
            )
            self._insert_event(
                cursor,
                workflow_id=job.workflow_id,
                from_stage=job.stage.value,
                to_stage=next_stage,
                operation=evidence.operation.value,
                stage_version=next_version,
                attempt_count=job.attempt_count,
                artifact_or_evidence_id=evidence.evidence_id,
                recorded_at_ms=self._server_now_ms(cursor),
            )
        return True

    def read_events(self, campaign_id: str | None = None) -> tuple[RecoveryStateEvent, ...]:
        with self._read() as cursor:
            if campaign_id is None:
                cursor.execute(
                    "SELECT material, material_sha256 FROM recovery_events ORDER BY event_sequence"
                )
            else:
                cursor.execute(
                    """
                    SELECT e.material, e.material_sha256
                    FROM recovery_events AS e
                    JOIN recovery_jobs AS j ON j.workflow_id = e.workflow_id
                    WHERE j.campaign_id = %s
                    ORDER BY e.event_sequence
                    """,
                    (campaign_id,),
                )
            rows = cursor.fetchall()
        return tuple(self._decode_event(row) for row in rows)

    def verify_integrity(self) -> RecoveryIntegrityReport:
        with self._read() as cursor:
            self._verify_schema_version(cursor)
            cursor.execute("SELECT * FROM recovery_jobs ORDER BY workflow_id")
            jobs = tuple(self._decode_job(row) for row in cursor.fetchall())
            cursor.execute(
                """
                SELECT material, material_sha256
                FROM recovery_events ORDER BY workflow_id, stage_version
                """
            )
            events = tuple(self._decode_event(row) for row in cursor.fetchall())
            cursor.execute(
                """
                SELECT j.workflow_id, c.status AS campaign_status
                FROM recovery_jobs AS j
                JOIN campaign_outbox AS c ON c.campaign_id = j.campaign_id
                JOIN receipt_records AS r ON r.receipt_id = j.source_receipt_id
                ORDER BY j.workflow_id
                """
            )
            links = cursor.fetchall()
        if len(links) != len(jobs) or any(row["campaign_status"] != "COMPLETED" for row in links):
            raise RecoveryStoreError("recovery workflow lost completed invalidation linkage")
        by_workflow: dict[str, list[RecoveryStateEvent]] = {}
        for event in events:
            by_workflow.setdefault(event.workflow_id, []).append(event)
        for job in jobs:
            selected = by_workflow.get(job.workflow_id, [])
            if len(selected) != job.stage_version + 1:
                raise RecoveryStoreError("recovery event history is incomplete")
            if [item.stage_version for item in selected] != list(range(job.stage_version + 1)):
                raise RecoveryStoreError("recovery event history is out of order")
            if selected[-1].to_stage is not job.stage:
                raise RecoveryStoreError("recovery event history disagrees with workflow stage")
        closed = sum(item.stage is RecoveryStage.INCIDENT_CLOSED for item in jobs)
        return RecoveryIntegrityReport(
            workflows=len(jobs),
            active_workflows=len(jobs) - closed,
            closed_workflows=closed,
            events=len(events),
        )

    def _initialize(self) -> None:
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
                        raise RecoveryStoreError(
                            "invalidation state must be initialized before recovery state"
                        )
                    self._set_search_path(cursor)
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(hashtext(%s))",
                        (f"glassbox.postgres-recovery-schema.{self.schema}",),
                    )
                    cursor.execute("SHOW server_version_num")
                    version = cursor.fetchone()
                    if (
                        version is None
                        or int(version["server_version_num"]) < _MINIMUM_SERVER_VERSION
                    ):
                        raise RecoveryStoreError("PostgreSQL 14 or newer is required")
                    cursor.execute(
                        """
                        CREATE TABLE IF NOT EXISTS recovery_state_metadata (
                            key TEXT PRIMARY KEY,
                            value TEXT NOT NULL
                        )
                        """
                    )
                    cursor.execute(
                        """
                        SELECT value FROM recovery_state_metadata
                        WHERE key = 'schema_version'
                        """
                    )
                    schema_version = cursor.fetchone()
                    if schema_version is None:
                        cursor.execute(
                            """
                            SELECT table_name FROM information_schema.tables
                            WHERE table_schema = %s
                              AND table_name LIKE 'recovery_%%'
                              AND table_name != 'recovery_state_metadata'
                            LIMIT 1
                            """,
                            (self.schema,),
                        )
                        if cursor.fetchone() is not None:
                            raise RecoveryStoreError(
                                "recovery schema has application tables but no version"
                            )
                        cursor.execute(
                            """
                            INSERT INTO recovery_state_metadata(key, value)
                            VALUES ('schema_version', %s)
                            """,
                            (POSTGRES_RECOVERY_SCHEMA_VERSION,),
                        )
                    elif schema_version["value"] != POSTGRES_RECOVERY_SCHEMA_VERSION:
                        raise RecoveryStoreError("recovery schema version is unsupported")
                    for statement in _DDL:
                        cursor.execute(statement)
        except psycopg.Error as exc:
            raise RecoveryStoreError("failed to initialize PostgreSQL recovery store") from exc

    def _validate_runtime_schema(self) -> None:
        try:
            with self._connection(set_search_path=False) as connection:
                with connection.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        """
                        SELECT EXISTS (
                            SELECT 1 FROM information_schema.tables
                            WHERE table_schema = %s
                              AND table_name = 'recovery_state_metadata'
                        ) AS initialized
                        """,
                        (self.schema,),
                    )
                    row = cursor.fetchone()
                    if row is None or row["initialized"] is not True:
                        raise RecoveryStoreError("PostgreSQL recovery schema is not initialized")
                    self._set_search_path(cursor)
                    self._verify_schema_version(cursor)
        except psycopg.Error as exc:
            raise RecoveryStoreError("failed to validate PostgreSQL recovery schema") from exc

    def _decode_job(self, row: Mapping[str, Any]) -> RecoveryJob:
        encoded = self._checked(row, "job_material", "job_material_sha256", _JOB_DOMAIN)
        value = _json_mapping(encoded, "recovery job material")
        authorization = authorization_from_dict(_mapping(value, "authorization"))
        bundle = _mapping(value, "bundle")
        try:
            stage = RecoveryStage(_text(row, "stage"))
            lease_operation = (
                RecoveryOperation(_text(row, "lease_operation"))
                if row.get("lease_operation") is not None
                else None
            )
        except ValueError as exc:
            raise RecoveryStoreError("recovery workflow enum value is invalid") from exc
        artifacts = self._optional_artifacts(row)
        job = RecoveryJob(
            workflow_id=_text(row, "workflow_id"),
            authorization=authorization,
            bundle=bundle,
            stage=stage,
            stage_version=_integer(row, "stage_version"),
            attempt_count=_integer(row, "attempt_count"),
            lease_operation=lease_operation,
            lease_owner=_optional_text(row, "lease_owner"),
            lease_expires_at_ms=_optional_integer(row, "lease_expires_at_ms"),
            last_error_type=_optional_text(row, "last_error_type"),
            artifacts=artifacts,
            replay_publication=self._optional_evidence(
                row,
                "replay_publication_evidence",
                "replay_publication_evidence_sha256",
            ),
            supersession_publication=self._optional_evidence(
                row,
                "supersession_publication_evidence",
                "supersession_publication_evidence_sha256",
            ),
            incident_closure=self._optional_evidence(
                row,
                "incident_closure_evidence",
                "incident_closure_evidence_sha256",
            ),
        )
        if (
            not job.valid
            or row.get("campaign_id") != job.campaign_id
            or row.get("authorization_id") != job.authorization.authorization_id
            or row.get("source_receipt_id") != job.source_receipt_id
            or row.get("bundle_id") != job.bundle_id
        ):
            raise RecoveryStoreError("persisted recovery workflow failed verification")
        if artifacts is not None and (
            row.get("replay_receipt_id") != artifacts.replay_receipt.get("receipt_id")
            or row.get("supersession_id") != artifacts.supersession.supersession_id
            or row.get("closure_id") != artifacts.closure.closure_id
        ):
            raise RecoveryStoreError("persisted recovery artifact identity columns drifted")
        return job

    def _optional_artifacts(self, row: Mapping[str, Any]) -> RecoveryArtifacts | None:
        if row.get("artifacts") is None:
            if row.get("artifacts_sha256") is not None:
                raise RecoveryStoreError("recovery artifact checksum exists without material")
            return None
        encoded = self._checked(row, "artifacts", "artifacts_sha256", _ARTIFACT_DOMAIN)
        return RecoveryArtifacts.from_dict(_json_mapping(encoded, "recovery artifacts"))

    def _optional_evidence(
        self,
        row: Mapping[str, Any],
        column: str,
        digest_column: str,
    ) -> RecoveryEffectEvidence | None:
        if row.get(column) is None:
            if row.get(digest_column) is not None:
                raise RecoveryStoreError("recovery evidence checksum exists without material")
            return None
        encoded = self._checked(row, column, digest_column, _EVIDENCE_DOMAIN)
        return RecoveryEffectEvidence.from_dict(_json_mapping(encoded, "recovery evidence"))

    def _decode_event(self, row: Mapping[str, Any]) -> RecoveryStateEvent:
        encoded = self._checked(row, "material", "material_sha256", _EVENT_DOMAIN)
        value = _json_mapping(encoded, "recovery event")
        try:
            to_stage = RecoveryStage(_text(value, "to_stage"))
        except ValueError as exc:
            raise RecoveryStoreError("recovery event stage is invalid") from exc
        event = RecoveryStateEvent(
            event_id=_text(value, "event_id"),
            workflow_id=_text(value, "workflow_id"),
            from_stage=_optional_text(value, "from_stage"),
            to_stage=to_stage,
            operation=_text(value, "operation"),
            stage_version=_integer(value, "stage_version"),
            attempt_count=_integer(value, "attempt_count"),
            artifact_or_evidence_id=_text(value, "artifact_or_evidence_id"),
            recorded_at_ms=_integer(value, "recorded_at_ms"),
        )
        if not event.valid:
            raise RecoveryStoreError("recovery event content address is invalid")
        return event

    def _insert_event(
        self,
        cursor: Any,
        *,
        workflow_id: str,
        from_stage: str | None,
        to_stage: RecoveryStage,
        operation: str,
        stage_version: int,
        attempt_count: int,
        artifact_or_evidence_id: str,
        recorded_at_ms: int,
    ) -> None:
        material: dict[str, object] = {
            "workflow_id": workflow_id,
            "from_stage": from_stage,
            "to_stage": to_stage.value,
            "operation": operation,
            "stage_version": stage_version,
            "attempt_count": attempt_count,
            "artifact_or_evidence_id": artifact_or_evidence_id,
            "recorded_at_ms": recorded_at_ms,
        }
        event_id = _event_id(material)
        encoded = canonicalize({"event_id": event_id, **material})
        cursor.execute(
            """
            INSERT INTO recovery_events(
                event_id, workflow_id, stage, stage_version, material, material_sha256
            ) VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                event_id,
                workflow_id,
                to_stage.value,
                stage_version,
                encoded,
                _checksum(_EVENT_DOMAIN, encoded),
            ),
        )

    @staticmethod
    def _require_owned(
        job: RecoveryJob,
        worker_id: str,
        *,
        operation: RecoveryOperation | None = None,
    ) -> None:
        if (
            job.lease_operation is None
            or job.lease_owner != worker_id
            or (operation is not None and job.lease_operation is not operation)
        ):
            raise RecoveryStoreError("recovery lease is not owned by this worker")

    @staticmethod
    def _server_now_ms(cursor: Any) -> int:
        cursor.execute(
            "SELECT floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms"
        )
        row = cursor.fetchone()
        if row is None or not isinstance(row["now_ms"], int):
            raise RecoveryStoreError("PostgreSQL server clock is invalid")
        return row["now_ms"]

    @staticmethod
    def _verify_schema_version(cursor: Any) -> None:
        cursor.execute("SELECT value FROM recovery_state_metadata WHERE key = 'schema_version'")
        row = cursor.fetchone()
        if row is None or row["value"] != POSTGRES_RECOVERY_SCHEMA_VERSION:
            raise RecoveryStoreError("recovery schema version is unsupported")

    @staticmethod
    def _locked_job(cursor: Any, campaign_id: str) -> Mapping[str, Any]:
        cursor.execute(
            "SELECT * FROM recovery_jobs WHERE campaign_id = %s FOR UPDATE",
            (campaign_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise RecoveryStoreError("recovery workflow is not staged")
        return cast(Mapping[str, Any], row)

    @staticmethod
    def _checked(
        row: Mapping[str, Any],
        column: str,
        digest_column: str,
        domain: bytes,
    ) -> bytes:
        encoded = _bytes(row.get(column))
        expected = row.get(digest_column)
        if not isinstance(expected, str) or _checksum(domain, encoded) != expected:
            raise RecoveryStoreError(f"{column} checksum verification failed")
        return encoded

    def _connect(self) -> psycopg.Connection[Any]:
        try:
            return psycopg.connect(
                self._dsn,
                connect_timeout=max(1, int(self.connect_timeout_seconds)),
                row_factory=dict_row,
            )
        except psycopg.Error as exc:
            raise RecoveryStoreError("failed to connect to PostgreSQL recovery state") from exc

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
            raise RecoveryStoreError("PostgreSQL recovery transaction failed") from exc

    @contextmanager
    def _read(self) -> Iterator[Any]:
        try:
            with self._connection() as connection:
                with connection.cursor(row_factory=dict_row) as cursor:
                    yield cursor
        except psycopg.Error as exc:
            raise RecoveryStoreError("PostgreSQL recovery read failed") from exc

    def _set_search_path(self, cursor: Any) -> None:
        cursor.execute(
            sql.SQL("SET LOCAL search_path TO {}, pg_catalog").format(sql.Identifier(self.schema))
        )


def _effect_transition(
    operation: RecoveryOperation,
) -> tuple[RecoveryStage, RecoveryStage, str, str]:
    if operation is RecoveryOperation.PUBLISH_REPLAY_RECEIPT:
        return (
            RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
            RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
            "replay_publication_evidence",
            "replay_publication_evidence_sha256",
        )
    if operation is RecoveryOperation.PUBLISH_SUPERSESSION:
        return (
            RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
            RecoveryStage.SUPERSESSION_VERIFIED,
            "supersession_publication_evidence",
            "supersession_publication_evidence_sha256",
        )
    if operation is RecoveryOperation.CLOSE_INCIDENT:
        return (
            RecoveryStage.SUPERSESSION_VERIFIED,
            RecoveryStage.INCIDENT_CLOSED,
            "incident_closure_evidence",
            "incident_closure_evidence_sha256",
        )
    raise RecoveryStoreError("execution must be completed with execution artifacts")


def _artifact_for_operation(
    artifacts: RecoveryArtifacts,
    operation: RecoveryOperation,
) -> str:
    if operation is RecoveryOperation.PUBLISH_REPLAY_RECEIPT:
        return cast(str, artifacts.replay_receipt["receipt_id"])
    if operation is RecoveryOperation.PUBLISH_SUPERSESSION:
        return artifacts.supersession.supersession_id
    if operation is RecoveryOperation.CLOSE_INCIDENT:
        return artifacts.closure.closure_id
    raise RecoveryStoreError("execution has no remote effect evidence")


def _evidence_for_operation(
    job: RecoveryJob,
    operation: RecoveryOperation,
) -> RecoveryEffectEvidence | None:
    if operation is RecoveryOperation.PUBLISH_REPLAY_RECEIPT:
        return job.replay_publication
    if operation is RecoveryOperation.PUBLISH_SUPERSESSION:
        return job.supersession_publication
    if operation is RecoveryOperation.CLOSE_INCIDENT:
        return job.incident_closure
    return None


def _stage_at_or_after(current: RecoveryStage, expected: RecoveryStage) -> bool:
    order = {stage: index for index, stage in enumerate(RecoveryStage)}
    return order[current] >= order[expected]


def _event_id(material: Mapping[str, object]) -> str:
    return (
        "gbx:recovery-event:sha256:"
        + hashlib.sha256(_EVENT_DOMAIN + canonicalize(material)).hexdigest()
    )


def _checksum(domain: bytes, value: bytes) -> str:
    return hashlib.sha256(domain + value).hexdigest()


def _bytes(value: object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray | memoryview):
        return bytes(value)
    raise RecoveryStoreError("persisted recovery material is not binary")


def _json_mapping(value: bytes, name: str) -> Mapping[str, Any]:
    selected = json.loads(value)
    if not isinstance(selected, Mapping):
        raise RecoveryStoreError(f"{name} must be an object")
    return cast(Mapping[str, Any], selected)


def _mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise RecoveryStoreError(f"{key} must be an object")
    return cast(Mapping[str, Any], selected)


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise RecoveryStoreError(f"{key} must be a non-empty string")
    return selected


def _optional_text(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is None:
        return None
    if not isinstance(selected, str):
        raise RecoveryStoreError(f"{key} must be a string or null")
    return selected


def _integer(value: Mapping[str, Any], key: str) -> int:
    selected = value.get(key)
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise RecoveryStoreError(f"{key} must be an integer")
    return selected


def _optional_integer(value: Mapping[str, Any], key: str) -> int | None:
    selected = value.get(key)
    if selected is None:
        return None
    if not isinstance(selected, int) or isinstance(selected, bool):
        raise RecoveryStoreError(f"{key} must be an integer or null")
    return selected


def _positive(value: int, name: str) -> None:
    if value <= 0:
        raise RecoveryStoreError(f"{name} must be positive")


def _nonempty(value: str, name: str) -> None:
    if not value:
        raise RecoveryStoreError(f"{name} must be non-empty")


__all__ = [
    "POSTGRES_RECOVERY_SCHEMA_VERSION",
    "PostgresRecoveryStore",
    "RecoveryIntegrityReport",
    "RecoveryStateEvent",
    "RecoveryStoreError",
]
