"""Bounded OTLP/HTTP receiver and durable receipt-publication recovery command."""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from glassbox_compiler.compiler import CompilationProfile, Environment
from glassbox_compiler.errors import CompilationError
from glassbox_compiler.publication import (
    LiveReceiptPipeline,
    LiveReceiptPipelineError,
    PostgresReceiptStateConfig,
    ReceiptPublicationWorker,
)
from glassbox_compiler.urns import URNResolutionError, VerifiedURNResolver
from glassbox_datahub import DataHubReceiptBackend, ReceiptEmitter
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_dbom import SigningKey
from glassbox_dbom.trust import (
    SignerTrustPolicy,
    load_signer_trust_policy,
    signing_key_from_base64url,
)
from glassbox_invalidation import TransactionalStoreError
from glassbox_policy import FieldCoverage, FieldLineageProof, PolicyInputError

_LOOPBACK_NAMES = frozenset({"localhost", "ip6-localhost"})


@dataclass(frozen=True)
class OTLPReceiverConfig:
    """Transport limits and authentication for one receiver instance."""

    bearer_token: str | None = field(default=None, repr=False)
    max_body_bytes: int = 4 * 1024 * 1024
    max_spans: int = 10_000
    request_timeout_seconds: float = 30.0
    run_span_id: str | None = None

    def __post_init__(self) -> None:
        if self.bearer_token is not None and not self.bearer_token:
            raise ValueError("receiver bearer token must be non-empty or null")
        if self.max_body_bytes <= 0:
            raise ValueError("receiver body limit must be positive")
        if self.max_spans <= 0:
            raise ValueError("receiver span limit must be positive")
        if self.request_timeout_seconds <= 0:
            raise ValueError("receiver request timeout must be positive")


class BoundedOTLPHTTPServer(HTTPServer):
    """Single-flight HTTP server with a bounded kernel accept queue."""

    request_queue_size = 128
    allow_reuse_address = True

    def handle_error(self, request: object, client_address: object) -> None:
        """Suppress raw exception and peer details from stderr."""

        del request, client_address


def make_otlp_handler(
    pipeline: LiveReceiptPipeline,
    profile: CompilationProfile,
    *,
    field_lineage: FieldLineageProof | None = None,
    config: OTLPReceiverConfig | None = None,
    profile_factory: Callable[[], CompilationProfile] | None = None,
) -> type[BaseHTTPRequestHandler]:
    """Create an injectable handler that acknowledges only sealed publication."""

    selected_config = config or OTLPReceiverConfig()
    proof = field_lineage or FieldLineageProof()

    class OTLPHandler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "GlassBoxOTLP/0.1"
        sys_version = ""

        def setup(self) -> None:
            super().setup()
            self.connection.settimeout(selected_config.request_timeout_seconds)

        def handle_expect_100(self) -> bool:
            self.close_connection = True
            self._respond(HTTPStatus.EXPECTATION_FAILED, "ExpectContinueUnsupported")
            return False

        def do_POST(self) -> None:
            if self.path != "/v1/traces":
                self.close_connection = True
                self._respond(HTTPStatus.NOT_FOUND, "RouteNotFound")
                return
            if not self._authorized():
                self.close_connection = True
                self._respond(
                    HTTPStatus.UNAUTHORIZED,
                    "Unauthorized",
                    extra_headers={"WWW-Authenticate": "Bearer"},
                )
                return
            if self.headers.get("Transfer-Encoding") is not None:
                self.close_connection = True
                self._respond(HTTPStatus.BAD_REQUEST, "TransferEncodingUnsupported")
                return
            content_types = self.headers.get_all("Content-Type", failobj=[])
            if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != (
                "application/json"
            ):
                self.close_connection = True
                self._respond(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "UnsupportedMediaType")
                return
            lengths = self.headers.get_all("Content-Length", failobj=[])
            if len(lengths) != 1:
                self.close_connection = True
                self._respond(HTTPStatus.LENGTH_REQUIRED, "ContentLengthRequired")
                return
            try:
                content_length = int(lengths[0], 10)
            except ValueError:
                self.close_connection = True
                self._respond(HTTPStatus.BAD_REQUEST, "InvalidContentLength")
                return
            if content_length <= 0:
                self._respond(HTTPStatus.BAD_REQUEST, "EmptyPayload")
                return
            if content_length > selected_config.max_body_bytes:
                self.close_connection = True
                self._respond(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "PayloadTooLarge")
                return
            try:
                body = self.rfile.read(content_length)
                if len(body) != content_length:
                    self.close_connection = True
                    self._respond(HTTPStatus.BAD_REQUEST, "IncompletePayload")
                    return
                payload = json.loads(body)
                if not isinstance(payload, Mapping):
                    raise ValueError("OTLP envelope must be an object")
                _, report = pipeline.compile_otlp_and_publish(
                    payload,
                    profile=profile_factory() if profile_factory is not None else profile,
                    run_span_id=selected_config.run_span_id,
                    max_spans=selected_config.max_spans,
                    field_lineage=proof,
                )
            except URNResolutionError as exc:
                if exc.__cause__ is not None:
                    self._respond(
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "URNResolutionUnavailable",
                        detail={"failure_type": type(exc.__cause__).__name__},
                    )
                else:
                    self._respond(HTTPStatus.BAD_REQUEST, "InvalidOTLPRequest")
                return
            except LiveReceiptPipelineError as exc:
                self._respond(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "PublicationUnavailable",
                    detail={"stage": exc.stage.value, "failure_type": exc.failure_type},
                )
                return
            except (PolicyInputError, TransactionalStoreError) as exc:
                self._respond(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "PublicationUnavailable",
                    detail={"failure_type": type(exc).__name__},
                )
                return
            except (UnicodeDecodeError, json.JSONDecodeError, ValueError, CompilationError):
                self._respond(HTTPStatus.BAD_REQUEST, "InvalidOTLPRequest")
                return
            except Exception:
                self._respond(HTTPStatus.INTERNAL_SERVER_ERROR, "InternalFailure")
                return
            if not report.valid:
                self._respond(HTTPStatus.SERVICE_UNAVAILABLE, "PublicationProofInvalid")
                return
            self._respond(HTTPStatus.OK, "ReceiptPublished", detail=report.to_dict())

        def do_GET(self) -> None:
            self.close_connection = True
            self._respond(HTTPStatus.METHOD_NOT_ALLOWED, "MethodNotAllowed")

        def do_PUT(self) -> None:
            self.do_GET()

        def do_PATCH(self) -> None:
            self.do_GET()

        def do_DELETE(self) -> None:
            self.do_GET()

        def log_message(self, message_format: str, *args: object) -> None:
            del message_format, args

        def _authorized(self) -> bool:
            token = selected_config.bearer_token
            if token is None:
                return True
            authorization = self.headers.get("Authorization")
            return authorization is not None and hmac.compare_digest(
                authorization.encode(), f"Bearer {token}".encode()
            )

        def _respond(
            self,
            status: HTTPStatus,
            code: str,
            *,
            detail: Mapping[str, object] | None = None,
            extra_headers: Mapping[str, str] | None = None,
        ) -> None:
            response: dict[str, object] = {
                "valid": status is HTTPStatus.OK,
                "code": code,
                "raw_content_returned": False,
            }
            if detail is not None:
                response["detail"] = dict(detail)
            encoded = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
            self.send_response(status.value)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if extra_headers is not None:
                for name, value in extra_headers.items():
                    self.send_header(name, value)
            self.end_headers()
            self.wfile.write(encoded)

    return OTLPHandler


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-otlp-receiver")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Receive OTLP traces and publish receipts")
    _add_live_options(serve)
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=4318)
    serve.add_argument("--bearer-token-env", default="GLASSBOX_OTLP_BEARER_TOKEN")
    serve.add_argument("--allow-unauthenticated-remote", action="store_true")
    serve.add_argument("--max-body-bytes", type=int, default=4 * 1024 * 1024)
    serve.add_argument("--max-spans", type=int, default=10_000)
    serve.add_argument("--request-timeout-seconds", type=float, default=30.0)
    serve.add_argument("--run-span-id")
    serve.add_argument("--signing-key-env", default="GLASSBOX_RECEIPT_SIGNING_KEY")
    serve.add_argument("--signing-key-id", required=True)
    serve.add_argument("--environment", choices=[item.value for item in Environment], required=True)
    serve.add_argument("--output-kind", required=True)
    serve.add_argument("--output-mime-type", required=True)
    serve.add_argument("--redaction-policy-id", default="glassbox.default-deny-v1")
    serve.add_argument(
        "--field-coverage",
        choices=[item.value for item in FieldCoverage],
        default=FieldCoverage.NONE.value,
    )
    serve.add_argument("--field-rule")
    serve.add_argument("--wildcard-query", choices=("true", "false", "unknown"), default="unknown")

    drain = commands.add_parser("drain", help="Recover pending publication obligations")
    _add_live_options(drain)
    drain.add_argument("--limit", type=int, default=100)
    return parser


def _add_live_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state-dsn-env", default="GLASSBOX_STATE_POSTGRES_DSN")
    parser.add_argument("--state-schema", default="glassbox")
    parser.add_argument("--state-connect-timeout-seconds", type=float, default=10.0)
    parser.add_argument("--datahub-server", default="http://localhost:8080")
    parser.add_argument("--datahub-token-env", default="DATAHUB_GMS_TOKEN")
    parser.add_argument("--allow-remote-datahub", action="store_true")
    parser.add_argument("--worker-id")
    parser.add_argument("--lease-duration-ms", type=int, default=60_000)
    parser.add_argument(
        "--signer-trust-policy-env",
        default="GLASSBOX_SIGNER_TRUST_POLICY_PATH",
        help="environment variable containing the trusted-signer policy path",
    )


def _optional_secret(environment_name: str) -> str | None:
    value = os.getenv(environment_name)
    return value or None


def _required_secret(environment_name: str, description: str) -> str:
    value = _optional_secret(environment_name)
    if value is None:
        raise ValueError(f"configured {description} environment variable is unset")
    return value


def _signing_key(environment_name: str, key_id: str) -> SigningKey:
    encoded = _required_secret(environment_name, "signing-key")
    return signing_key_from_base64url(key_id, encoded)


def _loopback_bind(host: str) -> bool:
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _wildcard(value: str) -> bool | None:
    return True if value == "true" else False if value == "false" else None


def _live_components(
    args: argparse.Namespace,
) -> tuple[Any, ReceiptEmitter, DataHubReceiptBackend, SignerTrustPolicy]:
    trust_policy_path = Path(
        _required_secret(args.signer_trust_policy_env, "signer-trust-policy path")
    )
    trust_policy = load_signer_trust_policy(trust_policy_path)
    state = PostgresReceiptStateConfig(
        dsn_environment_variable=args.state_dsn_env,
        schema=args.state_schema,
        connect_timeout_seconds=args.state_connect_timeout_seconds,
        signer_trust_policy=trust_policy,
    ).connect()
    server = validate_probe_target(args.datahub_server, allow_remote=args.allow_remote_datahub)
    backend = DataHubReceiptBackend(server=server, token=_optional_secret(args.datahub_token_env))
    backend.test_connection()
    return (
        state,
        ReceiptEmitter(backend, signer_trust_policy=trust_policy),
        backend,
        trust_policy,
    )


def _run(args: argparse.Namespace) -> int:
    state, emitter, backend, trust_policy = _live_components(args)
    if args.command == "drain":
        worker = ReceiptPublicationWorker(
            state,
            emitter,
            worker_id=args.worker_id,
            lease_duration_ms=args.lease_duration_ms,
        )
        outcomes = worker.drain(limit=args.limit)
        failures = [item for item in outcomes if item is not None]
        print(
            json.dumps(
                {
                    "valid": not failures,
                    "attempted": len(outcomes),
                    "completed": len(outcomes) - len(failures),
                    "failed": len(failures),
                    "failure_types": sorted(item.failure_type for item in failures),
                    "raw_content_returned": False,
                },
                sort_keys=True,
            )
        )
        return 0 if not failures else 1

    bearer_token = _optional_secret(args.bearer_token_env)
    if (
        not _loopback_bind(args.bind)
        and bearer_token is None
        and not (args.allow_unauthenticated_remote)
    ):
        raise ValueError(
            "non-loopback receiver bind requires bearer auth or explicit unsafe override"
        )
    signing_key = _signing_key(args.signing_key_env, args.signing_key_id)
    trust_policy.require_active_signing_key(signing_key)
    profile = CompilationProfile(
        environment=Environment(args.environment),
        output_kind=args.output_kind,
        output_mime_type=args.output_mime_type,
        redaction_policy_id=args.redaction_policy_id,
        signing_keys=(signing_key,),
    )
    proof = FieldLineageProof(
        coverage=FieldCoverage(args.field_coverage),
        rule_id=args.field_rule,
        wildcard_query=_wildcard(args.wildcard_query),
    )
    pipeline = LiveReceiptPipeline(
        state,
        emitter,
        worker_id=args.worker_id,
        lease_duration_ms=args.lease_duration_ms,
    )
    config = OTLPReceiverConfig(
        bearer_token=bearer_token,
        max_body_bytes=args.max_body_bytes,
        max_spans=args.max_spans,
        request_timeout_seconds=args.request_timeout_seconds,
        run_span_id=args.run_span_id,
    )
    server = BoundedOTLPHTTPServer(
        (args.bind, args.port),
        make_otlp_handler(
            pipeline,
            profile,
            field_lineage=proof,
            config=config,
            profile_factory=lambda: replace(profile, urn_resolver=VerifiedURNResolver(backend)),
        ),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _run(args)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "valid": False,
                    "error_type": type(exc).__name__,
                    "raw_content_returned": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
