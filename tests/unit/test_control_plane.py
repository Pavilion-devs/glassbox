"""Security and contract tests for the self-hosted control plane."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.exceptions import InvalidTag
from starlette.testclient import TestClient

from glassbox_control import datahub as datahub_module
from glassbox_control.crypto import SecretBox, datahub_secret_aad
from glassbox_control.datahub import DataHubConnectionTestError, normalize_datahub_url
from glassbox_control.server import build_app
from glassbox_control.server import main as control_main
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


def test_secret_box_rejects_invalid_keys_values_and_key_selectors() -> None:
    with pytest.raises(ValueError, match="exactly 32 bytes"):
        SecretBox(b"short")
    with pytest.raises(ValueError, match="1 to 64 characters"):
        SecretBox(MASTER_KEY, key_id="")
    with pytest.raises(ValueError, match="unset"):
        SecretBox.from_base64url("")
    with pytest.raises(ValueError, match="valid base64url"):
        SecretBox.from_base64url("not-ascii-☕")

    encoded = SecretBox.generate_base64url()
    box = SecretBox.from_base64url(encoded, key_id="primary")
    with pytest.raises(ValueError, match="non-empty"):
        box.encrypt("", aad=b"scope")
    encrypted = box.encrypt("secret", aad=b"scope")
    with pytest.raises(ValueError, match="unavailable key ID"):
        SecretBox(MASTER_KEY, key_id="replacement").decrypt(encrypted, aad=b"scope")
    assert box.ingestion_key_digest("invalid") == ""
    assert not box.ingestion_key_matches("invalid", "")


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


def test_control_store_rejects_invalid_bootstrap_and_bounded_metadata(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="organization"):
        ControlStore(tmp_path / "bad-org.sqlite3", SecretBox(MASTER_KEY), organization="")

    store = _store(tmp_path)
    with pytest.raises(ControlStoreError, match="already exists"):
        ControlStore(store.path, SecretBox(MASTER_KEY), initialize=True)
    with pytest.raises(ValueError, match="2 to 80"):
        store.create_ingestion_key(name="x", actor="operator")
    with pytest.raises(ValueError, match="timezone-aware"):
        store.create_ingestion_key(
            name="valid key",
            actor="operator",
            now=NOW.replace(tzinfo=None),
        )
    with pytest.raises(ValueError, match="exceeds 32 KiB"):
        store.save_datahub_connection(
            server_url="https://gms.example.com",
            ui_url=None,
            token="secret",
            probe={"oversized": "x" * (33 * 1024)},
            actor="operator",
            now=NOW,
        )
    assert store.authorize_ingestion_key("invalid") is False

    unavailable = tmp_path / "unavailable.sqlite3"
    with sqlite3.connect(unavailable) as connection:
        connection.execute("CREATE TABLE unrelated (value TEXT)")
    with pytest.raises(ControlStoreError, match="schema is unavailable"):
        ControlStore(unavailable, SecretBox(MASTER_KEY))

    with sqlite3.connect(store.path) as connection:
        connection.execute("UPDATE control_metadata SET schema_version = 999")
    with pytest.raises(ControlStoreError, match="version is unsupported"):
        ControlStore(store.path, SecretBox(MASTER_KEY))


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


class FailingTester:
    def test(self, *, server_url: str, token: str, write_proof: bool) -> dict[str, Any]:
        raise DataHubConnectionTestError("CONNECTION", "TimeoutError")


class UnprovenTester(FakeTester):
    def test(self, *, server_url: str, token: str, write_proof: bool) -> dict[str, Any]:
        report = super().test(server_url=server_url, token=token, write_proof=write_proof)
        report["write_proof"] = "UNVERIFIED"
        return report


class FailingPublicationReadback:
    def verify(self, *, server_url: str, token: str, receipt_id: str) -> dict[str, Any]:
        raise DataHubConnectionTestError("PUBLICATION_READBACK", "TimeoutError")


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


def test_control_api_returns_bounded_errors_for_invalid_inputs_and_remote_failures(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    receipt_id = "gbx:receipt:sha256:" + "b" * 64
    with pytest.raises(ValueError, match="at least 32"):
        build_app(store, internal_token="short")

    app = build_app(store, internal_token=API_TOKEN, tester=FailingTester())
    incomplete_identity = {"authorization": f"Bearer {API_TOKEN}"}
    with TestClient(app) as client:
        empty_connection = client.get("/api/v1/connection", headers=_headers("viewer"))
        assert client.get("/api/v1/connection", headers=incomplete_identity).status_code == 403
        assert client.get(f"/api/v1/publications/{receipt_id}/readback").status_code == 401
        assert client.post("/api/v1/connection/test", json={}).status_code == 401
        assert client.get("/api/v1/ingestion-keys").status_code == 401
        assert client.post("/api/v1/ingestion-keys", json={}).status_code == 401
        assert client.delete(f"/api/v1/ingestion-keys/ik_{'a' * 32}").status_code == 401
        missing_connection = client.get(
            f"/api/v1/publications/{receipt_id}/readback",
            headers=_headers("viewer"),
        )
        malformed = client.post(
            "/api/v1/connection/test",
            headers={**_headers(), "content-type": "application/json"},
            content=b"{",
        )
        invalid_length = client.post(
            "/api/v1/connection/test",
            headers={
                **_headers(),
                "content-type": "application/json",
                "content-length": "not-a-number",
            },
            content=b"{}",
        )
        oversized = client.post(
            "/api/v1/connection/test",
            headers=_headers(),
            json={"padding": "x" * (33 * 1024)},
        )
        non_object = client.post(
            "/api/v1/connection/test",
            headers=_headers(),
            json=["not", "an", "object"],
        )
        remote_failure = client.post(
            "/api/v1/connection/test",
            headers=_headers(),
            json={
                "server_url": "https://gms.example.com",
                "token": "secret",
                "write_proof": True,
            },
        )
        invalid_key_name = client.post(
            "/api/v1/ingestion-keys",
            headers=_headers(),
            json={"name": 42},
        )
        invalid_key_id = client.delete("/api/v1/ingestion-keys/not-a-key", headers=_headers())
        missing_key = client.delete(
            f"/api/v1/ingestion-keys/ik_{'a' * 32}",
            headers=_headers(),
        )

    assert empty_connection.json()["configured"] is False
    assert missing_connection.status_code == 409
    assert missing_connection.json()["error"]["code"] == "DATAHUB_NOT_CONFIGURED"
    assert malformed.status_code == 400
    assert invalid_length.status_code == 400
    assert oversized.status_code == 400
    assert non_object.status_code == 400
    assert remote_failure.status_code == 422
    assert remote_failure.json()["error"]["code"] == "DATAHUB_TEST_FAILED"
    assert "TimeoutError" in remote_failure.text
    assert invalid_key_name.status_code == 400
    assert invalid_key_id.status_code == 400
    assert missing_key.status_code == 404


@pytest.mark.parametrize(
    "payload",
    [
        {"token": "secret", "write_proof": True},
        {
            "server_url": "https://gms.example.com",
            "ui_url": 42,
            "token": "secret",
            "write_proof": True,
        },
        {"server_url": "https://gms.example.com", "write_proof": True},
        {
            "server_url": "https://gms.example.com",
            "token": "secret",
            "write_proof": "yes",
        },
    ],
)
def test_control_api_rejects_incomplete_connection_contracts(
    tmp_path: Path,
    payload: dict[str, Any],
) -> None:
    app = build_app(_store(tmp_path), internal_token=API_TOKEN, tester=FakeTester())
    with TestClient(app) as client:
        result = client.post(
            "/api/v1/connection/test",
            headers=_headers(),
            json=payload,
        )
    assert result.status_code == 400
    assert result.json()["error"]["code"] == "INVALID_ARGUMENT"


def test_control_api_requires_write_proof_and_bounds_readback_failures(tmp_path: Path) -> None:
    store = _store(tmp_path)
    app = build_app(store, internal_token=API_TOKEN, tester=UnprovenTester())
    connection = {
        "server_url": "https://gms.example.com",
        "token": "datahub-secret",
        "write_proof": False,
    }
    with TestClient(app) as client:
        proof_required = client.put(
            "/api/v1/connection",
            headers=_headers(),
            json=connection,
        )
        unproven = client.put(
            "/api/v1/connection",
            headers=_headers(),
            json={**connection, "write_proof": True},
        )

    assert proof_required.status_code == 400
    assert unproven.status_code == 422
    assert "ProofNotEstablished" in unproven.text

    store.save_datahub_connection(
        server_url="https://gms.example.com",
        ui_url=None,
        token="datahub-secret",
        probe={"write_proof": "PROVEN"},
        actor="operator",
        now=NOW,
    )
    failing_app = build_app(
        store,
        internal_token=API_TOKEN,
        tester=FakeTester(),
        publication_readback=FailingPublicationReadback(),
    )
    receipt_id = "gbx:receipt:sha256:" + "c" * 64
    with TestClient(failing_app) as client:
        failed = client.get(
            f"/api/v1/publications/{receipt_id}/readback",
            headers=_headers("viewer"),
        )
    assert failed.status_code == 502
    assert failed.json()["error"]["code"] == "DATAHUB_READBACK_FAILED"
    assert "datahub-secret" not in failed.text


def test_control_api_bounds_unavailable_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store(tmp_path)
    receipt_id = "gbx:receipt:sha256:" + "d" * 64

    def unavailable(*args: Any, **kwargs: Any) -> Any:
        raise ControlStoreError("synthetic unavailable state")

    monkeypatch.setattr(store, "load_datahub_connection", unavailable)
    readback_app = build_app(store, internal_token=API_TOKEN, tester=FakeTester())
    with TestClient(readback_app) as client:
        readback = client.get(
            f"/api/v1/publications/{receipt_id}/readback",
            headers=_headers("viewer"),
        )
    assert readback.status_code == 503
    assert readback.json()["error"]["code"] == "CONTROL_STATE_UNAVAILABLE"

    monkeypatch.setattr(store, "load_datahub_connection", lambda: None)
    monkeypatch.setattr(store, "save_datahub_connection", unavailable)
    save_app = build_app(store, internal_token=API_TOKEN, tester=FakeTester())
    with TestClient(save_app) as client:
        saved = client.put(
            "/api/v1/connection",
            headers=_headers(),
            json={
                "server_url": "https://gms.example.com",
                "token": "datahub-secret",
                "write_proof": True,
            },
        )
    assert saved.status_code == 503
    assert saved.json()["error"]["code"] == "CONTROL_STATE_UNAVAILABLE"


def test_control_cli_initializes_reopens_serves_and_reports_bounded_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database = tmp_path / "control.sqlite3"
    master_key_env = "GLASSBOX_TEST_CONTROL_MASTER_KEY"
    api_token_env = "GLASSBOX_TEST_CONTROL_API_TOKEN"
    monkeypatch.setenv(master_key_env, SecretBox.generate_base64url())
    monkeypatch.setenv(api_token_env, API_TOKEN)

    assert control_main(["master-key"]) == 0
    generated = capsys.readouterr().out.strip()
    assert SecretBox.from_base64url(generated).key_id == "control-v1"

    common = [
        "--database",
        str(database),
        "--organization",
        "test-org",
        "--master-key-env",
        master_key_env,
    ]
    assert control_main(["init", *common]) == 0
    initialized = json.loads(capsys.readouterr().out)
    assert initialized["initialized"] is True
    assert initialized["raw_content_returned"] is False

    assert control_main(["init", *common, "--if-needed"]) == 0
    reopened = json.loads(capsys.readouterr().out)
    assert reopened["initialized"] is False

    uvicorn_calls: list[dict[str, Any]] = []

    def fake_run(app: Any, **kwargs: Any) -> None:
        uvicorn_calls.append({"app": app, **kwargs})

    monkeypatch.setattr("uvicorn.run", fake_run)
    assert (
        control_main(
            [
                "serve",
                *common,
                "--bind",
                "127.0.0.2",
                "--port",
                "9876",
                "--api-token-env",
                api_token_env,
            ]
        )
        == 0
    )
    assert uvicorn_calls[0]["host"] == "127.0.0.2"
    assert uvicorn_calls[0]["port"] == 9876
    assert uvicorn_calls[0]["access_log"] is False

    monkeypatch.delenv(master_key_env)
    assert control_main(["serve", *common, "--api-token-env", api_token_env]) == 2
    failure = json.loads(capsys.readouterr().err)
    assert failure == {
        "error_type": "ValueError",
        "raw_content_returned": False,
        "valid": False,
    }


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


def test_datahub_server_version_accepts_known_config_shapes() -> None:
    assert datahub_module._server_version(None) is None
    assert datahub_module._server_version({"datahub": {"version": "1.6.0"}}) == "1.6.0"
    assert datahub_module._server_version({"versions": {"acryldata/datahub": "1.5.0"}}) == "1.5.0"
    assert datahub_module._server_version({"version": "1.4.0"}) == "1.4.0"
    assert datahub_module._server_version({}) is None
