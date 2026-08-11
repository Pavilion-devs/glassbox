"""Explicitly initialized single-node control state with encrypted secrets."""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from glassbox_control.crypto import EncryptedSecret, SecretBox, datahub_secret_aad

SCHEMA_VERSION = 1
CONNECTION_ID = "primary"


class ControlStoreError(RuntimeError):
    """Raised when control state is missing, incompatible, or corrupt."""


@dataclass(frozen=True)
class DataHubConnection:
    """Decrypted server-side DataHub connection. Never serialize this object."""

    server_url: str
    ui_url: str | None
    token: str
    probe: dict[str, Any]
    verified_at: str


_SCHEMA = """
CREATE TABLE control_metadata (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema_version INTEGER NOT NULL
);
INSERT INTO control_metadata(singleton, schema_version) VALUES (1, 1);

CREATE TABLE datahub_connections (
    connection_id TEXT PRIMARY KEY,
    organization TEXT NOT NULL,
    server_url TEXT NOT NULL,
    ui_url TEXT,
    token_nonce BLOB NOT NULL,
    token_ciphertext BLOB NOT NULL,
    token_key_id TEXT NOT NULL,
    probe_json TEXT NOT NULL,
    verified_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE ingestion_keys (
    key_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    display_prefix TEXT NOT NULL,
    secret_digest TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT
);

CREATE TABLE control_audit_events (
    event_id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    outcome TEXT NOT NULL,
    detail_json TEXT NOT NULL
);
CREATE INDEX control_audit_time_idx
    ON control_audit_events(occurred_at DESC, event_id DESC);
"""


class ControlStore:
    """Transactional low-write control state for one self-hosted deployment."""

    def __init__(
        self,
        path: Path,
        secret_box: SecretBox,
        *,
        organization: str = "default",
        initialize: bool = False,
    ) -> None:
        if not organization or len(organization) > 128:
            raise ValueError("organization must contain 1 to 128 characters")
        self.path = path
        self._secret_box = secret_box
        self.organization = organization
        if initialize:
            self._initialize()
        self._verify_schema()

    def _initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            raise ControlStoreError("control database already exists")
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript(_SCHEMA)
            connection.commit()
        finally:
            connection.close()
        self.path.chmod(0o600)

    def _connect(self) -> sqlite3.Connection:
        if not self.path.is_file():
            raise ControlStoreError("control database is not initialized")
        connection = sqlite3.connect(self.path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _verify_schema(self) -> None:
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT schema_version FROM control_metadata WHERE singleton = 1"
                ).fetchone()
        except sqlite3.Error as exc:
            raise ControlStoreError("control database schema is unavailable") from exc
        if row is None or row["schema_version"] != SCHEMA_VERSION:
            raise ControlStoreError("control database schema version is unsupported")

    def save_datahub_connection(
        self,
        *,
        server_url: str,
        ui_url: str | None,
        token: str,
        probe: dict[str, Any],
        actor: str,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        selected_now = _timestamp(now)
        encrypted = self._secret_box.encrypt(
            token,
            aad=datahub_secret_aad(
                organization=self.organization,
                connection_id=CONNECTION_ID,
            ),
        )
        probe_json = _bounded_json(probe)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO datahub_connections(
                    connection_id, organization, server_url, ui_url,
                    token_nonce, token_ciphertext, token_key_id, probe_json,
                    verified_at, updated_at, updated_by
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(connection_id) DO UPDATE SET
                    organization = excluded.organization,
                    server_url = excluded.server_url,
                    ui_url = excluded.ui_url,
                    token_nonce = excluded.token_nonce,
                    token_ciphertext = excluded.token_ciphertext,
                    token_key_id = excluded.token_key_id,
                    probe_json = excluded.probe_json,
                    verified_at = excluded.verified_at,
                    updated_at = excluded.updated_at,
                    updated_by = excluded.updated_by
                """,
                (
                    CONNECTION_ID,
                    self.organization,
                    server_url,
                    ui_url,
                    encrypted.nonce,
                    encrypted.ciphertext,
                    encrypted.key_id,
                    probe_json,
                    selected_now,
                    selected_now,
                    actor,
                ),
            )
            self._audit(
                connection,
                actor=actor,
                action="DATAHUB_CONNECTION_SAVED",
                target=CONNECTION_ID,
                outcome="SUCCEEDED",
                detail={"server_origin": server_url, "write_proof": probe.get("write_proof")},
                occurred_at=selected_now,
            )
            connection.commit()
        summary = self.connection_summary()
        if summary is None:  # pragma: no cover - transaction invariant
            raise ControlStoreError("saved DataHub connection is unavailable")
        return summary

    def connection_summary(self) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT server_url, ui_url, probe_json, verified_at, updated_at, updated_by
                FROM datahub_connections WHERE connection_id = ? AND organization = ?
                """,
                (CONNECTION_ID, self.organization),
            ).fetchone()
        if row is None:
            return None
        return {
            "connection_id": CONNECTION_ID,
            "server_url": row["server_url"],
            "ui_url": row["ui_url"],
            "probe": json.loads(row["probe_json"]),
            "verified_at": row["verified_at"],
            "updated_at": row["updated_at"],
            "updated_by": row["updated_by"],
            "credential_state": "ENCRYPTED",
        }

    def load_datahub_connection(self) -> DataHubConnection | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT server_url, ui_url, token_nonce, token_ciphertext, token_key_id,
                       probe_json, verified_at
                FROM datahub_connections WHERE connection_id = ? AND organization = ?
                """,
                (CONNECTION_ID, self.organization),
            ).fetchone()
        if row is None:
            return None
        encrypted = EncryptedSecret(
            nonce=bytes(row["token_nonce"]),
            ciphertext=bytes(row["token_ciphertext"]),
            key_id=row["token_key_id"],
        )
        try:
            token = self._secret_box.decrypt(
                encrypted,
                aad=datahub_secret_aad(
                    organization=self.organization,
                    connection_id=CONNECTION_ID,
                ),
            )
        except Exception as exc:
            raise ControlStoreError("DataHub credential decryption failed") from exc
        return DataHubConnection(
            server_url=row["server_url"],
            ui_url=row["ui_url"],
            token=token,
            probe=json.loads(row["probe_json"]),
            verified_at=row["verified_at"],
        )

    def create_ingestion_key(
        self,
        *,
        name: str,
        actor: str,
        now: datetime | None = None,
    ) -> tuple[dict[str, Any], str]:
        selected_name = name.strip()
        if not 2 <= len(selected_name) <= 80:
            raise ValueError("ingestion key name must contain 2 to 80 characters")
        clear, display_prefix, digest = self._secret_box.issue_ingestion_key()
        key_id = f"ik_{uuid.uuid4().hex}"
        created_at = _timestamp(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO ingestion_keys(
                    key_id, name, display_prefix, secret_digest, created_at, created_by
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (key_id, selected_name, display_prefix, digest, created_at, actor),
            )
            self._audit(
                connection,
                actor=actor,
                action="INGESTION_KEY_CREATED",
                target=key_id,
                outcome="SUCCEEDED",
                detail={"name": selected_name},
                occurred_at=created_at,
            )
            connection.commit()
        return (
            {
                "key_id": key_id,
                "name": selected_name,
                "display_prefix": display_prefix,
                "created_at": created_at,
                "created_by": actor,
                "state": "ACTIVE",
            },
            clear,
        )

    def list_ingestion_keys(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT key_id, name, display_prefix, created_at, created_by,
                       revoked_at, revoked_by
                FROM ingestion_keys ORDER BY created_at DESC, key_id DESC
                """
            ).fetchall()
        return [
            {
                "key_id": row["key_id"],
                "name": row["name"],
                "display_prefix": row["display_prefix"],
                "created_at": row["created_at"],
                "created_by": row["created_by"],
                "revoked_at": row["revoked_at"],
                "revoked_by": row["revoked_by"],
                "state": "REVOKED" if row["revoked_at"] else "ACTIVE",
            }
            for row in rows
        ]

    def revoke_ingestion_key(
        self,
        key_id: str,
        *,
        actor: str,
        now: datetime | None = None,
    ) -> bool:
        revoked_at = _timestamp(now)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = connection.execute(
                """
                UPDATE ingestion_keys SET revoked_at = ?, revoked_by = ?
                WHERE key_id = ? AND revoked_at IS NULL
                """,
                (revoked_at, actor, key_id),
            ).rowcount
            if changed:
                self._audit(
                    connection,
                    actor=actor,
                    action="INGESTION_KEY_REVOKED",
                    target=key_id,
                    outcome="SUCCEEDED",
                    detail={},
                    occurred_at=revoked_at,
                )
            connection.commit()
        return bool(changed)

    def authorize_ingestion_key(self, clear: str) -> bool:
        digest = self._secret_box.ingestion_key_digest(clear)
        if not digest:
            return False
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT secret_digest FROM ingestion_keys
                WHERE secret_digest = ? AND revoked_at IS NULL
                """,
                (digest,),
            ).fetchone()
        return row is not None and self._secret_box.ingestion_key_matches(
            clear, row["secret_digest"]
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        *,
        actor: str,
        action: str,
        target: str,
        outcome: str,
        detail: dict[str, Any],
        occurred_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO control_audit_events(
                event_id, occurred_at, actor, action, target, outcome, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                f"evt_{uuid.uuid4().hex}",
                occurred_at,
                actor,
                action,
                target,
                outcome,
                _bounded_json(detail),
            ),
        )


def _timestamp(value: datetime | None) -> str:
    selected = value or datetime.now(UTC)
    if selected.tzinfo is None or selected.utcoffset() is None:
        raise ValueError("control timestamps must be timezone-aware")
    return selected.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _bounded_json(value: dict[str, Any]) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 32 * 1024:
        raise ValueError("control metadata exceeds 32 KiB")
    return encoded
