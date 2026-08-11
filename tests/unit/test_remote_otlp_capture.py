"""Tests for the bounded hosted OTLP filming helper."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar

import pytest

from glassbox_compiler import CompilationProfile, Environment, compile_otlp_json
from glassbox_dbom import verify_receipt
from scripts import remote_otlp_capture


def _response(*, registration: str = "INSERTED", write_performed: bool = True) -> bytes:
    return json.dumps(
        {
            "valid": True,
            "code": "ReceiptPublished",
            "raw_content_returned": False,
            "detail": {
                "valid": True,
                "receipt_id": "gbx:receipt:sha256:" + "a" * 64,
                "state": {
                    "registration": registration,
                    "readback_verified": True,
                    "field_lineage": {
                        "coverage": "ASSET_ONLY",
                        "rule_id": "glassbox.asset-lineage.v1",
                        "wildcard_query": False,
                    },
                },
                "datahub": {
                    "valid": True,
                    "receipt_id": "gbx:receipt:sha256:" + "a" * 64,
                    "document_urn": "urn:li:document:glassbox.receipt." + "a" * 64,
                    "aspect_names": ["documentInfo", "documentKey"],
                    "emissions": 2,
                },
                "publication": {
                    "attempt_count": 1,
                    "datahub_write_performed": write_performed,
                },
                "raw_content_returned": False,
            },
        }
    ).encode()


def test_capture_payload_executes_real_agent_and_compiles_raw_free() -> None:
    body = remote_otlp_capture.build_capture_payload(
        "devpost-03b-test",
        started_at=datetime(2026, 8, 10, 12, 0, tzinfo=UTC),
    )
    payload = json.loads(body)
    spans = payload["resourceSpans"][0]["scopeSpans"][0]["spans"]
    receipt = compile_otlp_json(
        payload,
        profile=CompilationProfile(
            environment=Environment.DEV,
            output_kind="pricing-recommendation",
            output_mime_type="application/json",
        ),
    )

    assert len(spans) == 2
    assert verify_receipt(receipt).valid
    assert receipt["agent"]["id"] == "glassbox.demo.pricing-agent"
    assert receipt["evidence"][0]["datahub_urn"].endswith("commerce.orders,PROD)")
    assert b"demo-secret" not in body
    assert b"authorization" not in body.lower()
    assert b"synthetic-devpost-customer" not in body


def test_capture_payload_is_deterministic_for_label_and_start_time() -> None:
    started_at = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
    first = remote_otlp_capture.build_capture_payload("devpost-a", started_at=started_at)
    second = remote_otlp_capture.build_capture_payload("devpost-a", started_at=started_at)
    different = remote_otlp_capture.build_capture_payload("devpost-b", started_at=started_at)

    assert first == second
    assert first != different


def test_capture_payload_file_is_created_once_and_exactly_reused(tmp_path: Path) -> None:
    started_at = datetime(2026, 8, 10, 12, 0, tzinfo=UTC)
    first = remote_otlp_capture.load_or_create_capture_payload(
        "devpost-file",
        directory=tmp_path,
        started_at=started_at,
    )
    second = remote_otlp_capture.load_or_create_capture_payload(
        "devpost-file",
        directory=tmp_path,
        started_at=datetime(2026, 8, 11, 12, 0, tzinfo=UTC),
    )

    assert first.created is True
    assert second.created is False
    assert first.body == second.body == first.path.read_bytes()
    assert first.sha256 == second.sha256
    assert first.path.stat().st_mode & 0o777 == 0o600


class _FakeResponse:
    def __init__(self, status: int, body: bytes) -> None:
        self.status = status
        self._body = body

    def read(self, limit: int) -> bytes:
        return self._body[:limit]


class _FakeConnection:
    instances: ClassVar[list[_FakeConnection]] = []
    response: ClassVar[_FakeResponse] = _FakeResponse(200, _response())

    def __init__(self, host: str, port: int, timeout: int) -> None:
        self.host = host
        self.port = port
        self.timeout = timeout
        self.request_data: dict[str, Any] = {}
        self.closed = False
        self.instances.append(self)

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes,
        headers: dict[str, str],
    ) -> None:
        self.request_data = {"method": method, "path": path, "body": body, "headers": headers}

    def getresponse(self) -> _FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def test_sender_uses_fixed_tls_endpoint_and_returns_bounded_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeConnection.instances.clear()
    _FakeConnection.response = _FakeResponse(200, _response())
    monkeypatch.setattr(remote_otlp_capture, "HTTPSConnection", _FakeConnection)
    body = remote_otlp_capture.build_capture_payload(
        "devpost-send",
        started_at=datetime(2026, 8, 10, 12, 0, tzinfo=UTC),
    )

    proof = remote_otlp_capture.send_capture_payload(body, "x" * 48)

    connection = _FakeConnection.instances[0]
    assert (connection.host, connection.port, connection.timeout) == ("glassboxhq.xyz", 443, 30)
    assert connection.request_data["method"] == "POST"
    assert connection.request_data["path"] == "/v1/traces"
    assert connection.request_data["body"] == body
    assert connection.request_data["headers"]["Authorization"] == "Bearer " + "x" * 48
    assert connection.closed is True
    assert proof.registration == "INSERTED"
    assert proof.datahub_write_performed is True


def test_sender_failure_is_sanitized_and_never_echoes_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _FakeConnection.instances.clear()
    _FakeConnection.response = _FakeResponse(
        401,
        json.dumps(
            {"valid": False, "code": "Unauthorized", "raw_content_returned": False}
        ).encode(),
    )
    monkeypatch.setattr(remote_otlp_capture, "HTTPSConnection", _FakeConnection)
    token = "super-secret-ingestion-key-" + "x" * 32
    body = remote_otlp_capture.build_capture_payload(
        "devpost-reject",
        started_at=datetime(2026, 8, 10, 12, 0, tzinfo=UTC),
    )

    with pytest.raises(remote_otlp_capture.RemoteCaptureError) as raised:
        remote_otlp_capture.send_capture_payload(body, token)

    assert "HTTP 401 · Unauthorized" in str(raised.value)
    assert token not in str(raised.value)


@pytest.mark.parametrize("capture_id", ["", "UPPER", "bad/slash", "-leading", "trailing-"])
def test_capture_id_rejects_unsafe_paths(capture_id: str) -> None:
    with pytest.raises(ValueError, match="capture ID"):
        remote_otlp_capture.build_capture_payload(capture_id)
