from __future__ import annotations

import sys
from pathlib import Path

import pytest

import glassbox_forensics.server as server_module
import glassbox_invalidation.postgres_store as postgres_module


class FakeMCPServer:
    def __init__(self) -> None:
        self.runs = 0

    def run(self) -> None:
        self.runs += 1


def test_forensics_main_builds_jsonl_service_from_explicit_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeMCPServer()
    monkeypatch.setattr(server_module, "build_server", lambda service: transport)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "glassbox-forensics-mcp",
            "--receipt-store",
            str(tmp_path / "receipts.jsonl"),
            "--allow-untrusted-signers",
        ],
    )

    server_module.main()

    assert transport.runs == 1


def test_forensics_main_builds_postgres_live_service_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeMCPServer()
    created: list[dict[str, object]] = []

    class FakePostgresStore:
        def __init__(self, dsn: str, **kwargs: object) -> None:
            created.append({"dsn": dsn, **kwargs})

    monkeypatch.setattr(postgres_module, "PostgresInvalidationStore", FakePostgresStore)
    monkeypatch.setattr(server_module, "build_server", lambda service: transport)
    monkeypatch.setenv("GLASSBOX_FORENSICS_TEST_DSN", "postgresql://local-test")
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "glassbox-forensics-mcp",
            "--state-postgres-dsn-env",
            "GLASSBOX_FORENSICS_TEST_DSN",
            "--state-postgres-schema",
            "forensics_test",
            "--allow-untrusted-signers",
        ],
    )

    server_module.main()

    assert transport.runs == 1
    assert created[0]["dsn"] == "postgresql://local-test"
    assert created[0]["schema"] == "forensics_test"
    assert created[0]["initialize_schema"] is False


def test_forensics_environment_path_helpers_do_not_invent_configuration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GLASSBOX_RECEIPT_STORE_PATH", raising=False)
    monkeypatch.delenv("GLASSBOX_SIGNER_TRUST_POLICY_PATH", raising=False)
    assert server_module._path_from_environment() is None
    assert server_module._trust_path_from_environment() is None
    monkeypatch.setenv("GLASSBOX_RECEIPT_STORE_PATH", str(tmp_path / "receipts.jsonl"))
    monkeypatch.setenv("GLASSBOX_SIGNER_TRUST_POLICY_PATH", str(tmp_path / "policy.json"))
    assert server_module._path_from_environment() == tmp_path / "receipts.jsonl"
    assert server_module._trust_path_from_environment() == tmp_path / "policy.json"


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        [
            "--receipt-store",
            "receipts.jsonl",
            "--state-postgres-dsn-env",
            "GLASSBOX_TEST_DSN",
            "--allow-untrusted-signers",
        ],
        [
            "--receipt-store",
            "receipts.jsonl",
            "--allow-unsigned",
            "--signer-trust-policy",
            "policy.json",
        ],
        [
            "--state-postgres-dsn-env",
            "GLASSBOX_MISSING_FORENSICS_DSN",
            "--allow-untrusted-signers",
        ],
    ],
)
def test_forensics_main_rejects_ambiguous_or_incomplete_authority_configuration(
    arguments: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GLASSBOX_RECEIPT_STORE_PATH", raising=False)
    monkeypatch.delenv("GLASSBOX_SIGNER_TRUST_POLICY_PATH", raising=False)
    monkeypatch.delenv("GLASSBOX_MISSING_FORENSICS_DSN", raising=False)
    monkeypatch.setattr(sys, "argv", ["glassbox-forensics-mcp", *arguments])

    with pytest.raises(SystemExit) as raised:
        server_module.main()

    assert raised.value.code == 2
