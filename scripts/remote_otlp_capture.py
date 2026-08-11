"""Send the fixed GlassBox pricing-agent scenario to the hosted OTLP receiver.

This is a filming helper, not a general-purpose mutation client. It accepts no
endpoint, payload, DataHub URN, or customer-data argument. The ingestion key is
read only from ``GLASSBOX_CAPTURE_INGESTION_KEY`` and is never printed. A
capture ID selects a privacy-safe payload file under the ignored ``.glassbox``
directory; rerunning the same ID sends those exact bytes again so the later
zero-write redelivery proof is honest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.client import HTTPSConnection
from pathlib import Path
from typing import Any

from examples.deterministic_pricing_agent import build_pricing_agent

from glassbox import GlassBox, OpenTelemetrySpanSink
from glassbox.otel import GENAI_SEMCONV_SCHEMA_URL, OTelSpanRecord, OTelSpanStatus

ENDPOINT_HOST = "glassboxhq.xyz"
ENDPOINT_PATH = "/v1/traces"
ENDPOINT_URL = f"https://{ENDPOINT_HOST}{ENDPOINT_PATH}"
TOKEN_ENVIRONMENT_VARIABLE = "GLASSBOX_CAPTURE_INGESTION_KEY"
DEFAULT_CAPTURE_DIRECTORY = Path(".glassbox/captures")
MAX_RESPONSE_BYTES = 64 * 1024
MAX_STORED_PAYLOAD_BYTES = 4 * 1024 * 1024
_CAPTURE_ID = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?\Z")


class RemoteCaptureError(RuntimeError):
    """A bounded, secret-free failure safe to show in a filmed terminal."""


class CaptureIds:
    """Derive stable trace, span, and run IDs from one bounded capture label."""

    def __init__(self, capture_id: str) -> None:
        self.capture_id = _validated_capture_id(capture_id)
        self._span_index = 0

    def trace_id(self) -> str:
        return _derived_hex("trace", self.capture_id, length=32)

    def span_id(self) -> str:
        self._span_index += 1
        return _derived_hex(f"span-{self._span_index}", self.capture_id, length=16)

    def run_id(self) -> str:
        return f"glassbox-devpost-{self.capture_id}"


class CaptureClock:
    """Provide ordered UTC event times for one real, locally executed run."""

    def __init__(self, started_at: datetime | None = None) -> None:
        selected = started_at or datetime.now(UTC).replace(microsecond=0)
        if selected.tzinfo is None or selected.utcoffset() is None:
            raise ValueError("capture start time must be timezone-aware")
        self._next = selected.astimezone(UTC)

    def __call__(self) -> datetime:
        current = self._next
        self._next += timedelta(seconds=1)
        return current


@dataclass(frozen=True)
class CapturePayload:
    """Exact OTLP bytes retained for a later idempotent redelivery."""

    body: bytes
    path: Path
    created: bool

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()


@dataclass(frozen=True)
class CaptureProof:
    """Strict raw-free projection of the hosted receiver acknowledgement."""

    status: int
    code: str
    receipt_id: str
    registration: str
    state_readback_verified: bool
    document_urn: str
    aspect_names: tuple[str, ...]
    publication_attempt_count: int
    datahub_write_performed: bool


def build_capture_payload(
    capture_id: str,
    *,
    started_at: datetime | None = None,
) -> bytes:
    """Execute the allowlisted pricing agent and serialize its two OTLP spans."""

    selected_id = _validated_capture_id(capture_id)
    spans: list[OTelSpanRecord] = []
    runtime = GlassBox(
        OpenTelemetrySpanSink(spans.append),
        id_generator=CaptureIds(selected_id),
        clock=CaptureClock(started_at),
    )
    build_pricing_agent(runtime)("synthetic-devpost-customer")
    payload = {
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
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_or_create_capture_payload(
    capture_id: str,
    *,
    directory: Path = DEFAULT_CAPTURE_DIRECTORY,
    started_at: datetime | None = None,
) -> CapturePayload:
    """Create one payload atomically, or reuse its exact previously stored bytes."""

    selected_id = _validated_capture_id(capture_id)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = directory / f"{selected_id}.otlp.json"
    try:
        body = path.read_bytes()
    except FileNotFoundError:
        body = build_capture_payload(selected_id, started_at=started_at)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(body)
        except BaseException:
            path.unlink(missing_ok=True)
            raise
        return CapturePayload(body=body, path=path, created=True)
    _validate_stored_payload(body)
    return CapturePayload(body=body, path=path, created=False)


def send_capture_payload(body: bytes, ingestion_key: str) -> CaptureProof:
    """POST exact OTLP bytes to the fixed production endpoint."""

    token = ingestion_key.strip()
    if len(token) < 32:
        raise RemoteCaptureError(
            f"{TOKEN_ENVIRONMENT_VARIABLE} is missing or is not a complete ingestion key"
        )
    _validate_stored_payload(body)
    connection = HTTPSConnection(ENDPOINT_HOST, 443, timeout=30)
    try:
        connection.request(
            "POST",
            ENDPOINT_PATH,
            body=body,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "User-Agent": "glassbox-devpost-capture/0.1",
            },
        )
        response = connection.getresponse()
        response_body = response.read(MAX_RESPONSE_BYTES + 1)
        if len(response_body) > MAX_RESPONSE_BYTES:
            raise RemoteCaptureError("hosted receiver returned an oversized response")
        return _parse_response(response.status, response_body)
    except (OSError, TimeoutError) as exc:
        raise RemoteCaptureError(f"hosted receiver was unavailable ({type(exc).__name__})") from exc
    finally:
        connection.close()


def render_capture_proof(
    capture_id: str,
    payload: CapturePayload,
    proof: CaptureProof,
) -> str:
    """Render a compact, secret-free terminal card for Screen Studio."""

    payload_state = "CREATED" if payload.created else "REUSED EXACT BYTES"
    write_state = "PERFORMED" if proof.datahub_write_performed else "ZERO WRITES"
    lines = (
        ("GlassBox", "hosted causal capture"),
        ("Scenario", "deterministic pricing agent"),
        ("Endpoint", ENDPOINT_URL),
        ("Capture", capture_id),
        ("OTLP payload", f"{payload_state} · sha256:{payload.sha256[:16]}…"),
        ("Transport", f"HTTP {proof.status} · {proof.code}"),
        ("Registration", proof.registration),
        ("Receipt", proof.receipt_id),
        ("DataHub", proof.document_urn),
        ("Readback", f"VERIFIED · {len(proof.aspect_names)} persisted aspects"),
        (
            "Publication",
            f"{write_state} · attempt {proof.publication_attempt_count}",
        ),
        ("Raw content", "NOT RETURNED"),
    )
    return "\n".join(f"{label:<13} {value}" for label, value in lines)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="glassbox-remote-otlp-capture",
        description=(
            "Run the fixed pricing-agent scenario against the hosted GlassBox OTLP endpoint. "
            "The same capture ID reuses the exact stored payload for redelivery."
        ),
    )
    parser.add_argument(
        "--capture-id",
        default="devpost-03b-01",
        help="lowercase filming label (letters, digits, and hyphens; default: %(default)s)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        capture_id = _validated_capture_id(args.capture_id)
        token = os.getenv(TOKEN_ENVIRONMENT_VARIABLE, "")
        payload = load_or_create_capture_payload(capture_id)
        proof = send_capture_payload(payload.body, token)
    except (RemoteCaptureError, ValueError) as exc:
        print(f"GlassBox capture failed: {exc}", file=sys.stderr)
        return 1
    print(render_capture_proof(capture_id, payload, proof))
    return 0


def _validated_capture_id(value: str) -> str:
    if not _CAPTURE_ID.fullmatch(value):
        raise ValueError("capture ID must be 1-48 lowercase letters, digits, or interior hyphens")
    return value


def _derived_hex(namespace: str, capture_id: str, *, length: int) -> str:
    material = f"glassbox.devpost.capture.v1:{namespace}:{capture_id}".encode()
    return hashlib.sha256(material).hexdigest()[:length]


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
    if not isinstance(value, str):
        raise ValueError("capture span attribute is not an OTLP scalar")
    return {"stringValue": value}


def _timestamp_nanos(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("OTLP timestamp must be timezone-aware")
    utc = parsed.astimezone(UTC)
    return int(utc.timestamp()) * 1_000_000_000 + utc.microsecond * 1_000


def _validate_stored_payload(body: bytes) -> None:
    if not body or len(body) > MAX_STORED_PAYLOAD_BYTES:
        raise RemoteCaptureError("stored OTLP payload is empty or exceeds the receiver limit")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemoteCaptureError("stored OTLP payload is not valid JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {"resourceSpans"}:
        raise RemoteCaptureError("stored OTLP payload is not the fixed capture envelope")


def _parse_response(status: int, body: bytes) -> CaptureProof:
    try:
        response = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RemoteCaptureError(f"hosted receiver returned invalid JSON (HTTP {status})") from exc
    if not isinstance(response, dict):
        raise RemoteCaptureError(f"hosted receiver returned an invalid envelope (HTTP {status})")
    code = response.get("code")
    safe_code = code if isinstance(code, str) and code else "UnknownResponse"
    if status != 200:
        raise RemoteCaptureError(
            f"hosted receiver rejected the trace (HTTP {status} · {safe_code})"
        )
    if response.get("valid") is not True or safe_code != "ReceiptPublished":
        raise RemoteCaptureError("hosted receiver did not return a valid publication proof")
    if response.get("raw_content_returned") is not False:
        raise RemoteCaptureError("hosted receiver did not confirm the raw-free response boundary")

    detail = _mapping(response, "detail")
    state = _mapping(detail, "state")
    datahub = _mapping(detail, "datahub")
    publication = _mapping(detail, "publication")
    receipt_id = _string(detail, "receipt_id")
    registration = _string(state, "registration")
    if registration not in {"INSERTED", "REUSED"}:
        raise RemoteCaptureError("hosted receiver returned an unknown registration state")
    if state.get("readback_verified") is not True or datahub.get("valid") is not True:
        raise RemoteCaptureError("hosted receiver did not prove state and DataHub readback")
    document_urn = _string(datahub, "document_urn")
    aspects = datahub.get("aspect_names")
    if (
        not isinstance(aspects, list)
        or not aspects
        or not all(isinstance(item, str) and item for item in aspects)
    ):
        raise RemoteCaptureError("hosted receiver returned invalid DataHub aspect evidence")
    attempt_count = publication.get("attempt_count")
    write_performed = publication.get("datahub_write_performed")
    if not isinstance(attempt_count, int) or attempt_count < 1:
        raise RemoteCaptureError("hosted receiver returned an invalid publication attempt count")
    if not isinstance(write_performed, bool):
        raise RemoteCaptureError("hosted receiver returned an invalid publication write state")
    return CaptureProof(
        status=status,
        code=safe_code,
        receipt_id=receipt_id,
        registration=registration,
        state_readback_verified=True,
        document_urn=document_urn,
        aspect_names=tuple(aspects),
        publication_attempt_count=attempt_count,
        datahub_write_performed=write_performed,
    )


def _mapping(source: Mapping[str, object], key: str) -> Mapping[str, object]:
    value = source.get(key)
    if not isinstance(value, Mapping):
        raise RemoteCaptureError(f"hosted receiver omitted {key} proof")
    return value


def _string(source: Mapping[str, object], key: str) -> str:
    value = source.get(key)
    if not isinstance(value, str) or not value:
        raise RemoteCaptureError(f"hosted receiver omitted {key} proof")
    return value


if __name__ == "__main__":
    raise SystemExit(main())
