"""Security and contract tests for the self-hosted control plane."""

from __future__ import annotations

import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from starlette.testclient import TestClient

from glassbox_control.crypto import SecretBox, datahub_secret_aad
from glassbox_control.datahub import normalize_datahub_url
from glassbox_control.server import build_app
from glassbox_control.store import ControlStore, ControlStoreError

MASTER_KEY = bytes(range(32))
API_TOKEN = "control-api-token-that-is-deliberately-long-enough"
NOW = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)


def _store(tmp_path: Path) -> ControlStore:
    return ControlStore(
        tmp_path / "control.sqlite3",
        SecretBox(MASTER_KEY),
        organization="glassbox-test",
        initialize=True,
    )


def test_secret_box_binds_ciphertext_and_ingestion_keys() -> None:
    box = SecretBox(MASTER_KEY, key_id="test-v1")
    aad = datahub_secret_aad(organization="org", connection_id="primary")
    encrypted = box.encrypt("never-store-me-clear", aad=aad)

    assert box.decrypt(encrypted, aad=aad) == "never-store-me-clear"
    with pytest.raises(InvalidTag):
        box.decrypt(encrypted, aad=aad + b"-other")

    clear, prefix, digest = box.issue_ingestion_key()
    assert clear.startswith("gbx_ingest_")
    assert clear.startswith(prefix)
    assert clear not in digest
    assert box.ingestion_key_matches(clear, digest)
    assert not box.ingestion_key_matches(clear + "x", digest)


def test_control_store_encrypts_connection_and_revokes_named_keys(tmp_path: Path) -> None:
    store = _store(tmp_path)
    report = {
        "connection": "PROVEN",
        "authentication": "PROVEN",
        "sdk_compatibility": "PROVEN",
        "write_proof": "PROVEN",
    }
    summary = store.save_datahub_connection(
        server_url="https://gms.example.com",
        ui_url="https://datahub.example.com",
        token="datahub-service-account-secret",
        probe=report,
        actor="admin@example.com",
        now=NOW,
    )

    assert summary["credential_state"] == "ENCRYPTED"
    assert "token" not in summary
    loaded = store.load_datahub_connection()
    assert loaded is not None
    assert loaded.token == "datahub-service-account-secret"

    with sqlite3.connect(store.path) as connection:
        row = connection.execute(
            "SELECT token_ciphertext, probe_json FROM datahub_connections"
        ).fetchone()
    assert b"datahub-service-account-secret" not in bytes(row[0])
    assert "datahub-service-account-secret" not in row[1]

    key, clear = store.create_ingestion_key(
        name="Production pricing agent",
        actor="admin@example.com",
        now=NOW,
    )
    assert store.authorize_ingestion_key(clear)
    assert store.revoke_ingestion_key(key["key_id"], actor="admin@example.com", now=NOW)
    assert not store.authorize_ingestion_key(clear)
    assert store.list_ingestion_keys()[0]["state"] == "REVOKED"


def test_control_store_requires_explicit_bootstrap_and_matching_key(tmp_path: Path) -> None:
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(ControlStoreError, match="not initialized"):
        ControlStore(path, SecretBox(MASTER_KEY))

    store = ControlStore(path, SecretBox(MASTER_KEY), initialize=True)
    store.save_datahub_connection(
        server_url="http://datahub-gms:8080",
        ui_url=None,
        token="secret",
        probe={"write_proof": "PROVEN"},
        actor="operator",
        now=NOW,
    )
    mismatched = ControlStore(path, SecretBox(bytes(reversed(MASTER_KEY))))
    with pytest.raises(ControlStoreError, match="decryption failed"):
        mismatched.load_datahub_connection()


class FakeTester:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def test(self, *, server_url: str, token: str, write_proof: bool) -> dict[str, Any]:
        self.calls.append({"server_url": server_url, "token": token, "write_proof": write_proof})
        return {
            "contract_version": "glassbox.datahub-connection.v1",
            "connection": "PROVEN",
            "authentication": "PROVEN",
            "sdk_compatibility": "PROVEN",
            "sdk_version": "1.6.0.15",
            "server_version": "1.6.0",
            "write_proof": "PROVEN" if write_proof else "UNVERIFIED",
            "probe_document_urn": (
                "urn:li:document:glassbox.connection.probe" if write_proof else None
            ),
            "raw_content_returned": False,
        }


class FakePublicationReadback:
    def __init__(self) -> None:
        self.calls: list[dict[str, str]] = []

    def verify(self, *, server_url: str, token: str, receipt_id: str) -> dict[str, Any]:
        self.calls.append({"server_url": server_url, "token": token, "receipt_id": receipt_id})
        digest = receipt_id.removeprefix("gbx:receipt:sha256:")
        aspects = ["documentInfo", "globalTags", "status"]
        return {
            "contract_version": "glassbox.publication-readback.v1",
            "receipt_id": receipt_id,
            "document_urn": f"urn:li:document:glassbox.receipt.{digest}",
            "verification_state": "VERIFIED_NOW",
            "aspect_names": aspects,
            "aspect_count": len(aspects),
            "raw_content_returned": False,
        }


def _headers(role: str = "admin") -> dict[str, str]:
    return {
        "authorization": f"Bearer {API_TOKEN}",
        "x-glassbox-subject": "admin@example.com",
        "x-glassbox-role": role,
    }


def test_control_api_enforces_service_auth_roles_and_real_proof_before_save(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    tester = FakeTester()
    app = build_app(store, internal_token=API_TOKEN, tester=tester)
    payload = {
        "server_url": "https://gms.example.com/",
        "ui_url": "https://datahub.example.com/",
        "token": "datahub-secret",
        "write_proof": True,
    }
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/api/v1/connection").status_code == 401
        forbidden = client.put(
            "/api/v1/connection",
            headers=_headers("viewer"),
            json=payload,
        )
        assert forbidden.status_code == 403

        tested = client.post("/api/v1/connection/test", headers=_headers(), json=payload)
        saved = client.put("/api/v1/connection", headers=_headers(), json=payload)
        fetched = client.get("/api/v1/connection", headers=_headers("viewer"))

    assert tested.status_code == 200
    assert tested.json()["persisted"] is False
    assert saved.status_code == 200
    assert saved.json()["connection"]["credential_state"] == "ENCRYPTED"
    assert "datahub-secret" not in saved.text
    assert fetched.json()["configured"] is True
    assert tester.calls[-1]["server_url"] == "https://gms.example.com"


def test_control_api_returns_one_time_key_and_revocation_is_immediate(tmp_path: Path) -> None:
    store = _store(tmp_path)
    app = build_app(store, internal_token=API_TOKEN, tester=FakeTester())
    with TestClient(app) as client:
        created = client.post(
            "/api/v1/ingestion-keys",
            headers=_headers(),
            json={"name": "CI agent"},
        )
        clear = created.json()["secret"]
        key_id = created.json()["key"]["key_id"]
        listed = client.get("/api/v1/ingestion-keys", headers=_headers())
        revoked = client.delete(f"/api/v1/ingestion-keys/{key_id}", headers=_headers())

    assert created.status_code == 201
    assert clear.startswith("gbx_ingest_")
    assert clear not in listed.text
    assert store.authorize_ingestion_key(clear) is False
    assert revoked.json()["state"] == "REVOKED"


def test_control_api_performs_bounded_fresh_publication_readback(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.save_datahub_connection(
        server_url="https://gms.example.com",
        ui_url="https://datahub.example.com",
        token="datahub-service-account-secret",
        probe={"write_proof": "PROVEN"},
        actor="admin@example.com",
        now=NOW,
    )
    readback = FakePublicationReadback()
    app = build_app(
        store,
        internal_token=API_TOKEN,
        tester=FakeTester(),
        publication_readback=readback,
    )
    receipt_id = "gbx:receipt:sha256:" + "a" * 64

    with TestClient(app) as client:
        verified = client.get(
            f"/api/v1/publications/{receipt_id}/readback",
            headers=_headers("viewer"),
        )
        rejected = client.get(
            "/api/v1/publications/not-a-receipt/readback",
            headers=_headers("viewer"),
        )

    assert verified.status_code == 200
    assert verified.json()["verification_state"] == "VERIFIED_NOW"
    assert verified.json()["aspect_count"] == 3
    assert verified.json()["raw_content_returned"] is False
    assert readback.calls == [
        {
            "server_url": "https://gms.example.com",
            "token": "datahub-service-account-secret",
            "receipt_id": receipt_id,
        }
    ]
    assert "datahub-service-account-secret" not in verified.text
    assert rejected.status_code == 400
    assert rejected.json()["error"]["code"] == "INVALID_ARGUMENT"


@pytest.mark.parametrize(
    "value",
    [
        "datahub.example.com",
        "ftp://datahub.example.com",
        "https://user:pass@datahub.example.com",
        "https://datahub.example.com/api/graphql",
        "https://datahub.example.com?token=nope",
    ],
)
def test_datahub_origins_reject_ambiguous_or_credentialed_urls(value: str) -> None:
    with pytest.raises(ValueError):
        normalize_datahub_url(value, label="DataHub URL")
