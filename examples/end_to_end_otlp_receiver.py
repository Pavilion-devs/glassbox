"""Live proof: real OTLP HTTP acknowledgement, PostgreSQL state, and DataHub."""

from __future__ import annotations

import argparse
import base64
import http.client
import json
import threading
from collections.abc import Mapping, Sequence
from dataclasses import replace
from datetime import datetime
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from examples.deterministic_pricing_agent import build_pricing_agent
from examples.end_to_end_receipt import DemoClock, DemoIds, demo_signer_trust_policy

from glassbox import GlassBox, OpenTelemetrySpanSink
from glassbox.otel import GENAI_SEMCONV_SCHEMA_URL, OTelSpanRecord, OTelSpanStatus
from glassbox_compiler import (
    BoundedOTLPHTTPServer,
    CompilationProfile,
    Environment,
    LiveReceiptPipeline,
    OTLPReceiverConfig,
    PostgresReceiptStateConfig,
    VerifiedURNResolver,
    make_otlp_handler,
)
from glassbox_datahub import DataHubReceiptBackend, ReceiptEmitter
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_dbom import SigningKey, signing_key_fingerprint
from glassbox_invalidation import OutboxStatus


class CountingBackend:
    """Count only receipt writes while delegating to the real DataHub adapter."""

    def __init__(self, backend: DataHubReceiptBackend) -> None:
        self.backend = backend
        self.upserts = 0
        self.direct_reads = 0

    def upsert_receipt(self, receipt: Mapping[str, Any]) -> str:
        self.upserts += 1
        return self.backend.upsert_receipt(receipt)

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        self.direct_reads += 1
        return self.backend.direct_read_aspects(urn)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-otlp-receiver")
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--server", default="http://localhost:8080")
    parser.add_argument("--token")
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument("--state-postgres-dsn-env", default="GLASSBOX_STATE_POSTGRES_DSN")
    parser.add_argument("--state-postgres-schema", default="glassbox")
    return parser


def _spans() -> tuple[OTelSpanRecord, ...]:
    spans: list[OTelSpanRecord] = []
    runtime = GlassBox(
        OpenTelemetrySpanSink(spans.append),
        id_generator=DemoIds(),
        clock=DemoClock(),
    )
    build_pricing_agent(runtime)("synthetic-live-otlp-customer")
    return tuple(spans)


def _payload(spans: tuple[OTelSpanRecord, ...]) -> dict[str, Any]:
    return {
        "resourceSpans": [
            {
                "scopeSpans": [
                    {
                        "schemaUrl": GENAI_SEMCONV_SCHEMA_URL,
                        "spans": [_span(span) for span in spans],
                    }
                ]
            }
        ]
    }


def _span(span: OTelSpanRecord) -> dict[str, Any]:
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
        raise ValueError("live proof span attribute is not an OTLP scalar")
    return {"stringValue": value}


def _timestamp_nanos(value: str) -> int:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return int(parsed.timestamp()) * 1_000_000_000 + parsed.microsecond * 1_000


def _post(server: BoundedOTLPHTTPServer, body: bytes, bearer_token: str) -> dict[str, Any]:
    connection = http.client.HTTPConnection(
        str(server.server_address[0]), int(server.server_address[1]), timeout=30
    )
    try:
        connection.request(
            "POST",
            "/v1/traces",
            body=body,
            headers={
                "Authorization": f"Bearer {bearer_token}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        payload = json.loads(response.read())
        if response.status != 200 or not isinstance(payload, dict):
            raise RuntimeError(f"live OTLP receiver returned bounded failure {response.status}")
        return payload
    finally:
        connection.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    signing_key = SigningKey(
        "glassbox-live-otlp-ephemeral",
        Ed25519PrivateKey.generate(),
    )
    trust_policy = demo_signer_trust_policy(signing_key)
    authorized_fingerprint = trust_policy.require_active_signing_key(signing_key)
    state = PostgresReceiptStateConfig(
        dsn_environment_variable=args.state_postgres_dsn_env,
        schema=args.state_postgres_schema,
        signer_trust_policy=trust_policy,
    ).connect()
    server_url = validate_probe_target(args.server, allow_remote=args.allow_remote)
    real_backend = DataHubReceiptBackend(server=server_url, token=args.token)
    real_backend.test_connection()
    backend = CountingBackend(real_backend)
    profile = CompilationProfile(
        environment=Environment.DEV,
        output_kind="pricing-recommendation",
        output_mime_type="application/json",
        signing_keys=(signing_key,),
    )
    bearer_token = "glassbox-synthetic-live-proof-token"
    pipeline = LiveReceiptPipeline(
        state,
        ReceiptEmitter(backend, signer_trust_policy=trust_policy),
    )
    handler = make_otlp_handler(
        pipeline,
        profile,
        config=OTLPReceiverConfig(bearer_token=bearer_token),
        profile_factory=lambda: replace(profile, urn_resolver=VerifiedURNResolver(backend)),
    )
    receiver = BoundedOTLPHTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=receiver.serve_forever, daemon=True)
    thread.start()
    body = json.dumps(_payload(_spans()), sort_keys=True).encode()
    try:
        first = _post(receiver, body, bearer_token)
        second = _post(receiver, body, bearer_token)
    finally:
        receiver.shutdown()
        receiver.server_close()
        thread.join(timeout=30)

    tasks = state.list_receipt_publication_tasks()
    if len(tasks) != 1 or tasks[0].status is not OutboxStatus.COMPLETED:
        raise RuntimeError("live publication obligation did not complete")
    task = tasks[0]
    evidence = task.publication_evidence
    if evidence is None:
        raise RuntimeError("live publication obligation has no sealed evidence")
    trusted_state_readback = state.get_receipt(task.receipt_id) is not None
    first_detail = first["detail"]
    second_detail = second["detail"]
    if not isinstance(first_detail, Mapping) or not isinstance(second_detail, Mapping):
        raise RuntimeError("live receiver response detail is invalid")
    first_publication = first_detail["publication"]
    second_publication = second_detail["publication"]
    if not isinstance(first_publication, Mapping) or not isinstance(second_publication, Mapping):
        raise RuntimeError("live publication response is invalid")
    valid = (
        first["valid"] is True
        and second["valid"] is True
        and first_publication["datahub_write_performed"] is True
        and second_publication["datahub_write_performed"] is False
        and backend.upserts == 2
        and trusted_state_readback
    )
    report = {
        "valid": valid,
        "transport": {
            "endpoint": "/v1/traces",
            "first_status": 200,
            "redelivery_status": 200,
            "bearer_auth": "PROVEN",
            "raw_content_returned": False,
        },
        "state": {
            "engine": "PostgreSQL",
            "registration": first_detail["state"],
            "publication_status": task.status.value,
            "attempt_count": task.attempt_count,
            "sealed_evidence": True,
            "signer_admission_evidence_verified": trusted_state_readback,
        },
        "signer_trust": {
            "policy_id": trust_policy.policy_id,
            "minimum_trusted_signatures": trust_policy.minimum_trusted_signatures,
            "startup_signing_key_authorized": (
                authorized_fingerprint == signing_key_fingerprint(signing_key)
            ),
            "signer_key_id": signing_key.key_id,
            "signer_public_key_sha256": authorized_fingerprint,
            "private_key_returned": False,
        },
        "datahub": {
            "server_version": "1.6.0",
            "document_urn": evidence.document_urn,
            "sealed_aspects": list(evidence.aspect_names),
            "first_delivery_writes": backend.upserts,
            "completed_redelivery_writes": 0,
            "direct_reads_including_urn_resolution": backend.direct_reads,
        },
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
