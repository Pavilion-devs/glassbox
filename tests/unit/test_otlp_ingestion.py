"""OTLP/HTTP JSON ingestion and OpenTelemetry normalization tests."""

from __future__ import annotations

import base64
import http.client
import json
import threading
from collections.abc import Mapping
from copy import deepcopy
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from examples.deterministic_pricing_agent import build_pricing_agent
from examples.end_to_end_receipt import DemoClock, DemoIds

from glassbox import GlassBox, OpenTelemetrySpanSink
from glassbox.otel import GENAI_SEMCONV_SCHEMA_URL, OTelSpanRecord, OTelSpanStatus
from glassbox_compiler import (
    BoundedOTLPHTTPServer,
    CompilationProfile,
    Environment,
    LiveReceiptPipeline,
    OTLPIngestionError,
    OTLPReceiverConfig,
    compile_otlp_json,
    make_otlp_handler,
    normalize_otel_spans,
    parse_otlp_json,
)
from glassbox_compiler.publication import ReceiptPublicationWorker
from glassbox_datahub import ReceiptEmitter, receipt_document_urn
from glassbox_dbom import SigningKey, verify_receipt
from glassbox_invalidation import OutboxStatus, SQLiteInvalidationStore


class FakeOTLPReceiptBackend:
    def __init__(self, *, aspects: tuple[str, ...] = ("documentInfo",)) -> None:
        self.emissions = 0
        self.aspects = aspects

    def upsert_receipt(self, receipt: Mapping[str, Any]) -> str:
        self.emissions += 1
        return receipt_document_urn(str(receipt["receipt_id"]))

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        del urn
        return self.aspects


def _spans() -> tuple[OTelSpanRecord, ...]:
    spans: list[OTelSpanRecord] = []
    runtime = GlassBox(
        OpenTelemetrySpanSink(spans.append),
        id_generator=DemoIds(),
        clock=DemoClock(),
    )
    build_pricing_agent(runtime)("synthetic-otlp-customer")
    return tuple(spans)


def _profile(*, signed: bool = False) -> CompilationProfile:
    return CompilationProfile(
        environment=Environment.DEV,
        output_kind="pricing-recommendation",
        output_mime_type="application/json",
        signing_keys=(
            (SigningKey("otlp-live-receipt-test", Ed25519PrivateKey.generate()),) if signed else ()
        ),
    )


def _otlp_payload(spans: tuple[OTelSpanRecord, ...]) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "schemaUrl": GENAI_SEMCONV_SCHEMA_URL,
                        "spans": [_otlp_span(span) for span in spans],
                    }
                ]
            }
        ]
    }


def _otlp_span(span: OTelSpanRecord) -> dict[str, Any]:
    return {
        "traceId": base64.b64encode(bytes.fromhex(span.trace_id)).decode(),
        "spanId": base64.b64encode(bytes.fromhex(span.span_id)).decode(),
        **(
            {"parentSpanId": base64.b64encode(bytes.fromhex(span.parent_span_id)).decode()}
            if span.parent_span_id
            else {}
        ),
        "name": span.name,
        "kind": "SPAN_KIND_INTERNAL",
        "startTimeUnixNano": str(_timestamp_nanos(span.start_time)),
        "endTimeUnixNano": str(_timestamp_nanos(span.end_time)),
        "attributes": _attributes(span.attributes),
        "events": [
            {
                "name": event.name,
                "timeUnixNano": str(_timestamp_nanos(event.occurred_at)),
                "attributes": _attributes(event.attributes),
            }
            for event in span.events
        ],
        "status": {
            "code": (
                "STATUS_CODE_ERROR" if span.status is OTelSpanStatus.ERROR else "STATUS_CODE_UNSET"
            )
        },
    }


def _attributes(attributes: Mapping[str, object]) -> list[dict[str, Any]]:
    return [{"key": key, "value": _any_value(value)} for key, value in sorted(attributes.items())]


def _any_value(value: object) -> dict[str, object]:
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    assert isinstance(value, str)
    return {"stringValue": value}


def _timestamp_nanos(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int(parsed.timestamp()) * 1_000_000_000 + parsed.microsecond * 1_000


def test_completed_otel_spans_normalize_and_compile_without_raw_values() -> None:
    spans = _spans()
    events = normalize_otel_spans(spans)
    receipt = compile_otlp_json(_otlp_payload(spans), profile=_profile())

    assert [event.kind.value for event in events] == [
        "glassbox.run.started",
        "glassbox.evidence.observed",
        "glassbox.action.finished",
        "glassbox.run.finished",
    ]
    assert events[1].attributes["evidence.source_span_id"] == "2222222222222222"
    assert verify_receipt(receipt).valid
    assert receipt["evidence"][0]["source_span_id"] == "2222222222222222"
    assert receipt["actions"][0]["tool_id"] == "glassbox.demo.pricing-policy"
    assert receipt["replay"]["eligibility"] == "ELIGIBLE"


def test_otlp_compilation_automatically_registers_and_publishes(tmp_path: Path) -> None:
    state = SQLiteInvalidationStore(tmp_path / "otlp-live-state.sqlite3")
    backend = FakeOTLPReceiptBackend()

    receipt, report = LiveReceiptPipeline(
        state,
        ReceiptEmitter(backend),
    ).compile_otlp_and_publish(
        _otlp_payload(_spans()),
        profile=_profile(signed=True),
    )

    assert report.valid
    assert state.get_receipt(receipt["receipt_id"]) == receipt
    assert backend.emissions == 2


def _receiver_request(
    server: BoundedOTLPHTTPServer,
    body: bytes,
    *,
    content_type: str = "application/json",
    authorization: str | None = "Bearer receiver-secret",
) -> tuple[int, dict[str, Any]]:
    connection = http.client.HTTPConnection(
        str(server.server_address[0]), int(server.server_address[1]), timeout=5
    )
    headers = {"Content-Type": content_type}
    if authorization is not None:
        headers["Authorization"] = authorization
    try:
        connection.request("POST", "/v1/traces", body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read())
    finally:
        connection.close()


def _start_receiver(
    tmp_path: Path,
    *,
    backend: FakeOTLPReceiptBackend,
    max_body_bytes: int = 4 * 1024 * 1024,
) -> tuple[
    BoundedOTLPHTTPServer,
    threading.Thread,
    SQLiteInvalidationStore,
    CompilationProfile,
]:
    state = SQLiteInvalidationStore(tmp_path / "receiver-state.sqlite3")
    profile = _profile(signed=True)
    pipeline = LiveReceiptPipeline(state, ReceiptEmitter(backend))
    handler = make_otlp_handler(
        pipeline,
        profile,
        config=OTLPReceiverConfig(
            bearer_token="receiver-secret",
            max_body_bytes=max_body_bytes,
        ),
    )
    server = BoundedOTLPHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread, state, profile


def _stop_receiver(server: BoundedOTLPHTTPServer, thread: threading.Thread) -> None:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)


def test_otlp_receiver_acknowledges_only_sealed_publication_and_retries_zero_write(
    tmp_path: Path,
) -> None:
    backend = FakeOTLPReceiptBackend()
    server, thread, state, _ = _start_receiver(tmp_path, backend=backend)
    body = json.dumps(_otlp_payload(_spans())).encode()
    try:
        first_status, first = _receiver_request(server, body)
        second_status, second = _receiver_request(server, body)
    finally:
        _stop_receiver(server, thread)

    assert first_status == second_status == 200
    assert first["valid"] and second["valid"]
    assert first["detail"]["publication"]["datahub_write_performed"] is True
    assert second["detail"]["publication"]["datahub_write_performed"] is False
    assert backend.emissions == 2
    tasks = state.list_receipt_publication_tasks()
    assert len(tasks) == 1 and tasks[0].status is OutboxStatus.COMPLETED


def test_otlp_receiver_failure_remains_durable_and_independent_worker_recovers(
    tmp_path: Path,
) -> None:
    backend = FakeOTLPReceiptBackend(aspects=())
    server, thread, state, _ = _start_receiver(tmp_path, backend=backend)
    try:
        status, response = _receiver_request(server, json.dumps(_otlp_payload(_spans())).encode())
    finally:
        _stop_receiver(server, thread)

    assert status == 503
    assert response["code"] == "PublicationUnavailable"
    task = state.list_receipt_publication_tasks()[0]
    assert task.status is OutboxStatus.READY
    assert task.attempt_count == 1
    assert task.last_error_type == "ReceiptEmissionError"

    backend.aspects = ("documentInfo",)
    outcomes = ReceiptPublicationWorker(
        state, ReceiptEmitter(backend), worker_id="recovery-worker"
    ).drain()
    assert outcomes == (None,)
    completed = state.list_receipt_publication_tasks()[0]
    assert completed.status is OutboxStatus.COMPLETED
    assert completed.attempt_count == 2
    assert backend.emissions == 4


def test_otlp_receiver_rejects_unauthorized_malformed_and_oversized_requests(
    tmp_path: Path,
) -> None:
    backend = FakeOTLPReceiptBackend()
    server, thread, state, _ = _start_receiver(tmp_path, backend=backend, max_body_bytes=32)
    try:
        unauthorized, _ = _receiver_request(server, b"{}", authorization="Bearer wrong-secret")
        unsupported, _ = _receiver_request(server, b"{}", content_type="text/plain")
        malformed, _ = _receiver_request(server, b"{")
        oversized, _ = _receiver_request(server, b"x" * 33)
    finally:
        _stop_receiver(server, thread)

    assert unauthorized == 401
    assert unsupported == 415
    assert malformed == 400
    assert oversized == 413
    assert backend.emissions == 0
    assert state.verify_integrity().receipts == 0


def test_official_protobuf_json_base64_ids_and_nanoseconds_are_decoded() -> None:
    records = parse_otlp_json(_otlp_payload(_spans()))
    run = next(span for span in records if span.name.startswith("invoke_agent"))

    assert run.trace_id == "0123456789abcdef0123456789abcdef"
    assert run.span_id == "1111111111111111"
    assert run.start_time == "2026-08-06T12:00:00.000000000Z"
    assert run.end_time == "2026-08-06T12:00:04.000000000Z"


def test_multiple_agent_spans_require_an_explicit_selection() -> None:
    spans = _spans()
    run = next(span for span in spans if span.name.startswith("invoke_agent"))
    second = OTelSpanRecord(
        **{**run.__dict__, "span_id": "aaaaaaaaaaaaaaaa", "name": "invoke_agent second"}
    )

    with pytest.raises(OTLPIngestionError, match="exactly one available"):
        normalize_otel_spans((*spans, second))
    selected = normalize_otel_spans((*spans, second), run_span_id=run.span_id)
    assert selected[0].span_id == run.span_id


def test_dropped_provenance_and_oversized_payloads_fail_closed() -> None:
    payload = _otlp_payload(_spans())
    payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["droppedAttributesCount"] = 1
    with pytest.raises(OTLPIngestionError, match="dropped attributes"):
        parse_otlp_json(payload)

    with pytest.raises(OTLPIngestionError, match="max_spans=1"):
        parse_otlp_json(_otlp_payload(_spans()), max_spans=1)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.pop("resourceSpans"),
        lambda payload: payload["resourceSpans"][0]["scopeSpans"][0].pop("schemaUrl"),
        lambda payload: payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0].update(
            {"traceId": "not-base64"}
        ),
        lambda payload: payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0].update(
            {"kind": "SPAN_KIND_SERVER"}
        ),
    ],
)
def test_malformed_otlp_envelopes_are_rejected(mutation: Any) -> None:
    payload = deepcopy(_otlp_payload(_spans()))
    mutation(payload)
    with pytest.raises(OTLPIngestionError):
        parse_otlp_json(payload)


def test_duplicate_attributes_and_complex_any_values_are_rejected() -> None:
    payload = _otlp_payload(_spans())
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"].append(deepcopy(span["attributes"][0]))
    with pytest.raises(OTLPIngestionError, match="duplicates attribute"):
        parse_otlp_json(payload)

    payload = _otlp_payload(_spans())
    span = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["attributes"][0]["value"] = {"arrayValue": {"values": []}}
    with pytest.raises(OTLPIngestionError, match="scalar OTLP AnyValue"):
        parse_otlp_json(payload)


def test_temporal_and_status_contradictions_fail_closed() -> None:
    spans = _spans()
    run_index = next(
        index for index, span in enumerate(spans) if span.name.startswith("invoke_agent")
    )
    run = spans[run_index]
    broken = list(spans)
    broken[run_index] = replace(run, end_time="2026-08-06T11:59:59Z")
    with pytest.raises(OTLPIngestionError, match="ends before it starts"):
        normalize_otel_spans(broken)

    broken[run_index] = replace(run, status=OTelSpanStatus.ERROR)
    with pytest.raises(OTLPIngestionError, match="status conflicts"):
        normalize_otel_spans(broken)
