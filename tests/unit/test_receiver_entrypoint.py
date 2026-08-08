from __future__ import annotations

import base64
import json
from argparse import Namespace
from http import HTTPStatus
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

import glassbox_compiler.receiver as receiver_module
from glassbox_compiler.publication import LiveReceiptPipelineError, PublicationStage
from glassbox_compiler.receiver import OTLPReceiverConfig
from glassbox_compiler.urns import URNResolutionError
from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    signing_key_fingerprint,
    signing_key_public_key,
)
from glassbox_invalidation import TransactionalStoreError
from glassbox_policy import PolicyInputError


def _key() -> SigningKey:
    return SigningKey("receiver-entrypoint-key", Ed25519PrivateKey.generate())


def _policy(key: SigningKey) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id="receiver-entrypoint-policy",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=key.key_id,
                public_key=signing_key_public_key(key),
                public_key_sha256=signing_key_fingerprint(key),
                status=SignerStatus.ACTIVE,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"bearer_token": ""},
        {"max_body_bytes": 0},
        {"max_spans": 0},
        {"request_timeout_seconds": 0},
    ],
)
def test_receiver_config_rejects_empty_auth_and_nonpositive_limits(
    kwargs: dict[str, Any],
) -> None:
    with pytest.raises(ValueError):
        OTLPReceiverConfig(**kwargs)


def test_receiver_environment_helpers_are_closed_and_secret_indirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GLASSBOX_TEST_OPTIONAL", raising=False)
    assert receiver_module._optional_secret("GLASSBOX_TEST_OPTIONAL") is None
    with pytest.raises(ValueError, match="environment variable is unset"):
        receiver_module._required_secret("GLASSBOX_TEST_OPTIONAL", "test secret")
    monkeypatch.setenv("GLASSBOX_TEST_OPTIONAL", "secret-value")
    assert receiver_module._required_secret("GLASSBOX_TEST_OPTIONAL", "test secret") == (
        "secret-value"
    )
    assert receiver_module._loopback_bind("localhost")
    assert receiver_module._loopback_bind("127.0.0.1")
    assert not receiver_module._loopback_bind("not-an-ip")
    assert receiver_module._wildcard("true") is True
    assert receiver_module._wildcard("false") is False
    assert receiver_module._wildcard("unknown") is None


def test_receiver_loads_signing_key_from_indirect_environment_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    encoded = (
        base64.urlsafe_b64encode(
            private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    monkeypatch.setenv("GLASSBOX_TEST_SIGNING_KEY", encoded)

    loaded = receiver_module._signing_key("GLASSBOX_TEST_SIGNING_KEY", "test-key")

    assert loaded.key_id == "test-key"
    assert loaded.private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    ) == private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def test_bounded_server_suppresses_peer_and_exception_details() -> None:
    server = object.__new__(receiver_module.BoundedOTLPHTTPServer)
    server.handle_error(object(), ("203.0.113.1", 4318))


def test_live_component_factory_connects_and_preflights_without_returning_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = object()
    policy = object()
    backend_calls: list[str] = []
    policy_path = tmp_path / "policy.json"
    policy_path.write_text("{}", encoding="utf-8")
    monkeypatch.setenv("GLASSBOX_TEST_POLICY_PATH", str(policy_path))

    class FakeStateConfig:
        def __init__(self, **kwargs: Any) -> None:
            assert kwargs["dsn_environment_variable"] == "GLASSBOX_TEST_DSN"
            assert kwargs["schema"] == "glassbox_test"
            assert kwargs["signer_trust_policy"] is policy

        def connect(self) -> object:
            return state

    class FakeBackend:
        def __init__(self, *, server: str, token: str | None) -> None:
            assert server == "http://127.0.0.1:8080"
            assert token is None

        def test_connection(self) -> None:
            backend_calls.append("tested")

    class FakeEmitter:
        def __init__(self, backend: object, *, signer_trust_policy: object) -> None:
            assert isinstance(backend, FakeBackend)
            assert signer_trust_policy is policy

    monkeypatch.setattr(receiver_module, "load_signer_trust_policy", lambda path: policy)
    monkeypatch.setattr(receiver_module, "PostgresReceiptStateConfig", FakeStateConfig)
    monkeypatch.setattr(
        receiver_module,
        "validate_probe_target",
        lambda server, allow_remote: server,
    )
    monkeypatch.setattr(receiver_module, "DataHubReceiptBackend", FakeBackend)
    monkeypatch.setattr(receiver_module, "ReceiptEmitter", FakeEmitter)
    args = Namespace(
        signer_trust_policy_env="GLASSBOX_TEST_POLICY_PATH",
        state_dsn_env="GLASSBOX_TEST_DSN",
        state_schema="glassbox_test",
        state_connect_timeout_seconds=3.0,
        datahub_server="http://127.0.0.1:8080",
        allow_remote_datahub=False,
        datahub_token_env="GLASSBOX_TEST_DATAHUB_TOKEN",
    )

    selected_state, emitter, backend, selected_policy = receiver_module._live_components(args)

    assert selected_state is state
    assert isinstance(emitter, FakeEmitter)
    assert isinstance(backend, FakeBackend)
    assert selected_policy is policy
    assert backend_calls == ["tested"]


@pytest.mark.parametrize("fail", [False, True])
def test_drain_entrypoint_reports_bounded_completion(
    fail: bool,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    outcome = SimpleNamespace(failure_type="SyntheticFailure") if fail else None

    class FakeWorker:
        def __init__(self, *args: object, **kwargs: object) -> None:
            assert kwargs["worker_id"] == "drain-worker"

        def drain(self, *, limit: int) -> tuple[object | None, ...]:
            assert limit == 2
            return (outcome,)

    monkeypatch.setattr(receiver_module, "_live_components", lambda args: (1, 2, 3, 4))
    monkeypatch.setattr(receiver_module, "ReceiptPublicationWorker", FakeWorker)
    args = Namespace(
        command="drain",
        worker_id="drain-worker",
        lease_duration_ms=1_000,
        limit=2,
    )

    code = receiver_module._run(args)
    report = json.loads(capsys.readouterr().out)

    assert code == (1 if fail else 0)
    assert report["valid"] is not fail
    assert report["attempted"] == 1
    assert report["failed"] == (1 if fail else 0)
    assert report["raw_content_returned"] is False


def _serve_args(**overrides: Any) -> Namespace:
    values: dict[str, Any] = {
        "command": "serve",
        "bearer_token_env": "GLASSBOX_TEST_BEARER",
        "bind": "127.0.0.1",
        "allow_unauthenticated_remote": False,
        "signing_key_env": "GLASSBOX_TEST_SIGNING_KEY",
        "signing_key_id": "receiver-entrypoint-key",
        "environment": "DEV",
        "output_kind": "recommendation",
        "output_mime_type": "application/json",
        "redaction_policy_id": "glassbox.default-deny-v1",
        "field_coverage": "NONE",
        "field_rule": None,
        "wildcard_query": "unknown",
        "worker_id": "receiver-worker",
        "lease_duration_ms": 1_000,
        "max_body_bytes": 1_024,
        "max_spans": 10,
        "request_timeout_seconds": 2.0,
        "run_span_id": None,
        "port": 4318,
    }
    values.update(overrides)
    return Namespace(**values)


@pytest.mark.parametrize("interrupt", [False, True])
def test_serve_entrypoint_preflights_signer_builds_server_and_always_closes(
    interrupt: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _key()
    policy = _policy(key)
    monkeypatch.setattr(
        receiver_module,
        "_live_components",
        lambda args: (object(), object(), object(), policy),
    )
    monkeypatch.setattr(receiver_module, "_signing_key", lambda environment, key_id: key)
    server_state: dict[str, bool] = {}

    class FakeServer:
        def __init__(self, address: tuple[str, int], handler: object) -> None:
            assert address == ("127.0.0.1", 4318)
            assert handler is not None

        def serve_forever(self) -> None:
            server_state["served"] = True
            if interrupt:
                raise KeyboardInterrupt

        def server_close(self) -> None:
            server_state["closed"] = True

    monkeypatch.setattr(receiver_module, "BoundedOTLPHTTPServer", FakeServer)

    assert receiver_module._run(_serve_args()) == 0
    assert server_state == {"served": True, "closed": True}


def test_serve_entrypoint_refuses_unauthenticated_remote_bind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key = _key()
    monkeypatch.setattr(
        receiver_module,
        "_live_components",
        lambda args: (object(), object(), object(), _policy(key)),
    )
    with pytest.raises(ValueError, match="requires bearer auth"):
        receiver_module._run(_serve_args(bind="0.0.0.0"))


def test_receiver_main_returns_run_result_and_redacts_unhandled_errors(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(receiver_module, "_run", lambda args: 7)
    assert receiver_module.main(["drain"]) == 7

    def fail(args: Namespace) -> int:
        del args
        raise RuntimeError("never-print-sensitive-detail")

    monkeypatch.setattr(receiver_module, "_run", fail)
    assert receiver_module.main(["drain"]) == 2
    error = capsys.readouterr().err
    assert "RuntimeError" in error
    assert "never-print-sensitive-detail" not in error


class FakeHeaders:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = values or {}

    def get(self, name: str, default: str | None = None) -> str | None:
        return self.values.get(name, default)

    def get_all(self, name: str, failobj: list[str] | None = None) -> list[str]:
        selected = self.values.get(name)
        return [selected] if selected is not None else list(failobj or [])


def _direct_handler(
    pipeline: object,
    *,
    headers: dict[str, str] | None = None,
    body: bytes = b"{}",
    path: str = "/v1/traces",
    config: OTLPReceiverConfig | None = None,
    include_content_length: bool = True,
) -> tuple[Any, list[tuple[HTTPStatus, str, object, object]]]:
    handler_type = receiver_module.make_otlp_handler(
        pipeline,
        receiver_module.CompilationProfile(
            environment=receiver_module.Environment.DEV,
            output_kind="test",
            output_mime_type="application/json",
        ),
        config=config or OTLPReceiverConfig(),
    )
    handler = object.__new__(handler_type)
    selected_headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
        **(headers or {}),
    }
    if not include_content_length:
        selected_headers.pop("Content-Length")
    handler.path = path
    handler.headers = FakeHeaders(selected_headers)
    handler.rfile = BytesIO(body)
    handler.close_connection = False
    responses: list[tuple[HTTPStatus, str, object, object]] = []
    handler._respond = lambda status, code, detail=None, extra_headers=None: responses.append(
        (status, code, detail, extra_headers)
    )
    return handler, responses


@pytest.mark.parametrize(
    ("path", "headers", "body", "config", "expected"),
    [
        ("/wrong", {}, b"{}", None, "RouteNotFound"),
        (
            "/v1/traces",
            {},
            b"{}",
            OTLPReceiverConfig(bearer_token="required"),
            "Unauthorized",
        ),
        (
            "/v1/traces",
            {"Transfer-Encoding": "chunked"},
            b"{}",
            None,
            "TransferEncodingUnsupported",
        ),
        (
            "/v1/traces",
            {"Content-Type": "text/plain"},
            b"{}",
            None,
            "UnsupportedMediaType",
        ),
        ("/v1/traces", {"Content-Length": "bad"}, b"{}", None, "InvalidContentLength"),
        ("/v1/traces", {"Content-Length": "0"}, b"", None, "EmptyPayload"),
        (
            "/v1/traces",
            {},
            b"{}",
            OTLPReceiverConfig(max_body_bytes=1),
            "PayloadTooLarge",
        ),
        ("/v1/traces", {"Content-Length": "3"}, b"{}", None, "IncompletePayload"),
    ],
)
def test_handler_rejects_transport_ambiguity_before_pipeline(
    path: str,
    headers: dict[str, str],
    body: bytes,
    config: OTLPReceiverConfig | None,
    expected: str,
) -> None:
    handler, responses = _direct_handler(
        object(),
        headers=headers,
        body=body,
        path=path,
        config=config,
    )

    handler.do_POST()

    assert responses[0][1] == expected


def test_handler_requires_exact_content_length_and_object_envelope() -> None:
    missing_length, missing_responses = _direct_handler(object(), include_content_length=False)
    missing_length.do_POST()
    assert missing_responses[0][1] == "ContentLengthRequired"

    non_object, non_object_responses = _direct_handler(object(), body=b"[]")
    non_object.do_POST()
    assert non_object_responses[0][1] == "InvalidOTLPRequest"


@pytest.mark.parametrize(
    ("failure", "expected"),
    [
        (ValueError("invalid"), "InvalidOTLPRequest"),
        (URNResolutionError("invalid urn"), "InvalidOTLPRequest"),
        (
            LiveReceiptPipelineError(PublicationStage.STATE_REGISTRATION, "DatabaseError"),
            "PublicationUnavailable",
        ),
        (PolicyInputError("policy"), "PublicationUnavailable"),
        (TransactionalStoreError("state"), "PublicationUnavailable"),
        (RuntimeError("unexpected"), "InternalFailure"),
    ],
)
def test_handler_maps_pipeline_failures_to_bounded_protocol_errors(
    failure: Exception,
    expected: str,
) -> None:
    class FailingPipeline:
        def compile_otlp_and_publish(self, *args: object, **kwargs: object) -> None:
            raise failure

    handler, responses = _direct_handler(FailingPipeline())

    handler.do_POST()

    assert responses[0][1] == expected
    assert "policy" not in repr(responses)
    assert "unexpected" not in repr(responses)


def test_handler_distinguishes_resolution_outage_invalid_proof_and_success() -> None:
    unavailable = URNResolutionError("unavailable")
    unavailable.__cause__ = ConnectionError("secret endpoint")

    class ResolutionOutage:
        def compile_otlp_and_publish(self, *args: object, **kwargs: object) -> None:
            raise unavailable

    handler, responses = _direct_handler(ResolutionOutage())
    handler.do_POST()
    assert responses[0][1] == "URNResolutionUnavailable"
    assert responses[0][2] == {"failure_type": "ConnectionError"}

    class ReportingPipeline:
        def __init__(self, valid: bool) -> None:
            self.valid = valid

        def compile_otlp_and_publish(
            self, *args: object, **kwargs: object
        ) -> tuple[object, SimpleNamespace]:
            return object(), SimpleNamespace(
                valid=self.valid,
                to_dict=lambda: {"valid": self.valid},
            )

    invalid_handler, invalid_responses = _direct_handler(ReportingPipeline(False))
    invalid_handler.do_POST()
    assert invalid_responses[0][1] == "PublicationProofInvalid"
    valid_handler, valid_responses = _direct_handler(ReportingPipeline(True))
    valid_handler.do_POST()
    assert valid_responses[0][0] is HTTPStatus.OK
    assert valid_responses[0][1] == "ReceiptPublished"


def test_handler_method_refusals_expectation_and_actual_response_are_raw_free() -> None:
    handler, responses = _direct_handler(object())
    assert handler.handle_expect_100() is False
    handler.do_GET()
    handler.do_PUT()
    handler.do_PATCH()
    handler.do_DELETE()
    handler.log_message("secret %s", "value")
    assert responses[0][1] == "ExpectContinueUnsupported"
    assert [item[1] for item in responses[1:]] == ["MethodNotAllowed"] * 4

    response_handler, _ = _direct_handler(object())
    status: list[int] = []
    headers: list[tuple[str, str]] = []
    response_handler.send_response = lambda value: status.append(value)
    response_handler.send_header = lambda name, value: headers.append((name, value))
    response_handler.end_headers = lambda: None
    response_handler.wfile = BytesIO()
    response_handler._respond = type(response_handler)._respond.__get__(response_handler)
    response_handler._respond(
        HTTPStatus.UNAUTHORIZED,
        "Unauthorized",
        detail={"failure_type": "AuthError"},
        extra_headers={"WWW-Authenticate": "Bearer"},
    )
    encoded = response_handler.wfile.getvalue()
    assert status == [401]
    assert json.loads(encoded)["raw_content_returned"] is False
    assert ("WWW-Authenticate", "Bearer") in headers
