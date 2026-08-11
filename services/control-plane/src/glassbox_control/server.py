"""Authenticated GlassBox control-plane HTTP service and bootstrap CLI."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Protocol

from glassbox_control.crypto import SecretBox
from glassbox_control.datahub import (
    DataHubConnectionTester,
    DataHubConnectionTestError,
    DataHubPublicationReadbackVerifier,
    normalize_datahub_url,
)
from glassbox_control.store import ControlStore, ControlStoreError

_MAX_REQUEST_BYTES = 32 * 1024
_ROLES = {"viewer": 1, "operator": 2, "admin": 3}


class ConnectionTester(Protocol):
    def test(self, *, server_url: str, token: str, write_proof: bool) -> dict[str, Any]: ...


class PublicationReadbackVerifier(Protocol):
    def verify(self, *, server_url: str, token: str, receipt_id: str) -> dict[str, Any]: ...


def build_app(
    store: ControlStore,
    *,
    internal_token: str,
    tester: ConnectionTester | None = None,
    publication_readback: PublicationReadbackVerifier | None = None,
) -> Any:
    """Build the private API. Identity headers are trusted only with service auth."""

    try:
        from starlette.applications import Starlette
        from starlette.requests import Request
        from starlette.responses import JSONResponse
        from starlette.routing import Route
    except ImportError as exc:  # pragma: no cover - optional dependency boundary
        raise RuntimeError("glassbox-control requires the control optional dependencies") from exc

    if len(internal_token) < 32:
        raise ValueError("control API token must contain at least 32 characters")
    selected_tester = tester or DataHubConnectionTester()
    selected_publication_readback = publication_readback or DataHubPublicationReadbackVerifier()

    def response(payload: Mapping[str, Any], status_code: int = 200) -> Any:
        return JSONResponse(
            dict(payload),
            status_code=status_code,
            headers={
                "Cache-Control": "no-store",
                "X-Content-Type-Options": "nosniff",
                "Referrer-Policy": "no-referrer",
            },
        )

    def error(code: str, message: str, status_code: int) -> Any:
        return response(
            {
                "contract_version": "glassbox.control-api.v1",
                "error": {"code": code, "message": message},
                "raw_content_returned": False,
            },
            status_code,
        )

    def principal(request: Any, required_role: str) -> tuple[str, str] | Any:
        authorization = request.headers.get("authorization")
        expected = f"Bearer {internal_token}"
        if authorization is None or not hmac.compare_digest(
            authorization.encode(), expected.encode()
        ):
            return error("UNAUTHENTICATED", "Service authentication failed.", 401)
        subject = request.headers.get("x-glassbox-subject", "").strip()
        role = request.headers.get("x-glassbox-role", "").strip().lower()
        if not subject or role not in _ROLES:
            return error("INVALID_IDENTITY", "Operator identity is incomplete.", 403)
        if _ROLES[role] < _ROLES[required_role]:
            return error("FORBIDDEN", "This operation requires a higher role.", 403)
        return subject[:254], role

    async def body(request: Any) -> dict[str, Any]:
        raw_length = request.headers.get("content-length")
        if raw_length is not None:
            try:
                if int(raw_length) > _MAX_REQUEST_BYTES:
                    raise ValueError("request body exceeds 32 KiB")
            except ValueError as exc:
                raise ValueError("request body length is invalid") from exc
        raw = await request.body()
        if len(raw) > _MAX_REQUEST_BYTES:
            raise ValueError("request body exceeds 32 KiB")
        try:
            value = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body must be a JSON object") from exc
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    async def health(_: Request) -> Any:
        return response(
            {
                "status": "ok",
                "service": "glassbox-control",
                "contract_version": "glassbox.control-api.v1",
            }
        )

    async def get_connection(request: Request) -> Any:
        selected = principal(request, "viewer")
        if not isinstance(selected, tuple):
            return selected
        connection = store.connection_summary()
        return response(
            {
                "contract_version": "glassbox.control-api.v1",
                "configured": connection is not None,
                "connection": connection,
                "raw_content_returned": False,
            }
        )

    async def verify_publication_readback(request: Request) -> Any:
        selected = principal(request, "viewer")
        if not isinstance(selected, tuple):
            return selected
        receipt_id = request.path_params["receipt_id"]
        try:
            _require_receipt_id(receipt_id)
            connection = store.load_datahub_connection()
            if connection is None:
                return error(
                    "DATAHUB_NOT_CONFIGURED",
                    "A verified DataHub connection is required.",
                    409,
                )
            report = selected_publication_readback.verify(
                server_url=connection.server_url,
                token=connection.token,
                receipt_id=receipt_id,
            )
        except DataHubConnectionTestError as exc:
            return error(
                "DATAHUB_READBACK_FAILED",
                f"DataHub verification failed at {exc.stage} ({exc.failure_type}).",
                502,
            )
        except ControlStoreError:
            return error("CONTROL_STATE_UNAVAILABLE", "Control state is unavailable.", 503)
        except ValueError as exc:
            return error("INVALID_ARGUMENT", str(exc), 400)
        return response(report)

    async def test_connection(request: Request) -> Any:
        selected = principal(request, "admin")
        if not isinstance(selected, tuple):
            return selected
        try:
            payload = await body(request)
            server_url, _, token, write_proof = _connection_input(payload)
            report = selected_tester.test(
                server_url=server_url,
                token=token,
                write_proof=write_proof,
            )
        except DataHubConnectionTestError as exc:
            return error(
                "DATAHUB_TEST_FAILED",
                f"DataHub verification failed at {exc.stage} ({exc.failure_type}).",
                422,
            )
        except ValueError as exc:
            return error("INVALID_ARGUMENT", str(exc), 400)
        return response(
            {
                "contract_version": "glassbox.control-api.v1",
                "report": report,
                "persisted": False,
                "raw_content_returned": False,
            }
        )

    async def save_connection(request: Request) -> Any:
        selected = principal(request, "admin")
        if not isinstance(selected, tuple):
            return selected
        subject, _ = selected
        try:
            payload = await body(request)
            server_url, ui_url, token, write_proof = _connection_input(payload)
            if not write_proof:
                raise ValueError("saving requires the DataHub write/readback proof")
            report = selected_tester.test(
                server_url=server_url,
                token=token,
                write_proof=True,
            )
            if report.get("write_proof") != "PROVEN":
                raise DataHubConnectionTestError("WRITE_READBACK", "ProofNotEstablished")
            summary = store.save_datahub_connection(
                server_url=server_url,
                ui_url=ui_url,
                token=token,
                probe=report,
                actor=subject,
            )
        except DataHubConnectionTestError as exc:
            return error(
                "DATAHUB_TEST_FAILED",
                f"DataHub verification failed at {exc.stage} ({exc.failure_type}).",
                422,
            )
        except ValueError as exc:
            return error("INVALID_ARGUMENT", str(exc), 400)
        except ControlStoreError:
            return error("CONTROL_STATE_UNAVAILABLE", "Control state is unavailable.", 503)
        return response(
            {
                "contract_version": "glassbox.control-api.v1",
                "configured": True,
                "connection": summary,
                "raw_content_returned": False,
            }
        )

    async def list_keys(request: Request) -> Any:
        selected = principal(request, "admin")
        if not isinstance(selected, tuple):
            return selected
        return response(
            {
                "contract_version": "glassbox.control-api.v1",
                "keys": store.list_ingestion_keys(),
                "raw_content_returned": False,
            }
        )

    async def create_key(request: Request) -> Any:
        selected = principal(request, "admin")
        if not isinstance(selected, tuple):
            return selected
        subject, _ = selected
        try:
            payload = await body(request)
            name = payload.get("name")
            if not isinstance(name, str):
                raise ValueError("ingestion key name is required")
            summary, clear = store.create_ingestion_key(name=name, actor=subject)
        except ValueError as exc:
            return error("INVALID_ARGUMENT", str(exc), 400)
        return response(
            {
                "contract_version": "glassbox.control-api.v1",
                "key": summary,
                "secret": clear,
                "secret_display": "RETURNED_ONCE",
                "raw_content_returned": False,
            },
            201,
        )

    async def revoke_key(request: Request) -> Any:
        selected = principal(request, "admin")
        if not isinstance(selected, tuple):
            return selected
        subject, _ = selected
        key_id = request.path_params["key_id"]
        if not key_id.startswith("ik_") or len(key_id) != 35:
            return error("INVALID_ARGUMENT", "ingestion key ID is invalid", 400)
        if not store.revoke_ingestion_key(key_id, actor=subject):
            return error("NOT_FOUND", "Active ingestion key was not found.", 404)
        return response(
            {
                "contract_version": "glassbox.control-api.v1",
                "key_id": key_id,
                "state": "REVOKED",
                "raw_content_returned": False,
            }
        )

    return Starlette(
        debug=False,
        routes=[
            Route("/health", health, methods=["GET"]),
            Route("/api/v1/connection", get_connection, methods=["GET"]),
            Route(
                "/api/v1/publications/{receipt_id}/readback",
                verify_publication_readback,
                methods=["GET"],
            ),
            Route("/api/v1/connection/test", test_connection, methods=["POST"]),
            Route("/api/v1/connection", save_connection, methods=["PUT"]),
            Route("/api/v1/ingestion-keys", list_keys, methods=["GET"]),
            Route("/api/v1/ingestion-keys", create_key, methods=["POST"]),
            Route("/api/v1/ingestion-keys/{key_id}", revoke_key, methods=["DELETE"]),
        ],
    )


def _connection_input(payload: Mapping[str, Any]) -> tuple[str, str | None, str, bool]:
    raw_server = payload.get("server_url")
    raw_ui = payload.get("ui_url")
    token = payload.get("token")
    write_proof = payload.get("write_proof", False)
    if not isinstance(raw_server, str):
        raise ValueError("DataHub GMS URL is required")
    if raw_ui is not None and not isinstance(raw_ui, str):
        raise ValueError("DataHub UI URL must be a string")
    if not isinstance(token, str) or not token.strip():
        raise ValueError("DataHub service-account token is required")
    if not isinstance(write_proof, bool):
        raise ValueError("write_proof must be a boolean")
    server_url = normalize_datahub_url(raw_server, label="DataHub GMS URL")
    ui_url = normalize_datahub_url(raw_ui, label="DataHub UI URL") if raw_ui else None
    return server_url, ui_url, token.strip(), write_proof


def _require_receipt_id(receipt_id: str) -> None:
    prefix = "gbx:receipt:sha256:"
    digest = receipt_id.removeprefix(prefix)
    if (
        not receipt_id.startswith(prefix)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("receipt_id must be a GlassBox SHA-256 content address")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-control")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("master-key", help="Generate a new base64url deployment master key")
    init = commands.add_parser("init", help="Initialize an empty control database")
    _store_options(init)
    init.add_argument(
        "--if-needed",
        action="store_true",
        help="verify an existing compatible database instead of failing",
    )
    serve = commands.add_parser("serve", help="Run the private authenticated control API")
    _store_options(serve)
    serve.add_argument("--bind", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8790)
    serve.add_argument("--api-token-env", default="GLASSBOX_CONTROL_API_TOKEN")
    return parser


def _store_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--database",
        type=Path,
        default=Path(os.getenv("GLASSBOX_CONTROL_DB_PATH", ".glassbox/control.sqlite3")),
    )
    parser.add_argument("--organization", default=os.getenv("GLASSBOX_ORGANIZATION", "default"))
    parser.add_argument("--master-key-env", default="GLASSBOX_CONTROL_MASTER_KEY")
    parser.add_argument(
        "--master-key-id",
        default=os.getenv("GLASSBOX_CONTROL_MASTER_KEY_ID", "control-v1"),
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "master-key":
        print(SecretBox.generate_base64url())
        return 0
    try:
        encoded_key = os.getenv(args.master_key_env, "")
        secret_box = SecretBox.from_base64url(encoded_key, key_id=args.master_key_id)
        initialize = args.command == "init" and not (args.if_needed and args.database.exists())
        store = ControlStore(
            args.database,
            secret_box,
            organization=args.organization,
            initialize=initialize,
        )
        if args.command == "init":
            print(
                json.dumps(
                    {
                        "valid": True,
                        "database": str(args.database),
                        "initialized": initialize,
                        "schema_version": 1,
                        "raw_content_returned": False,
                    },
                    sort_keys=True,
                )
            )
            return 0
        internal_token = os.getenv(args.api_token_env, "")
        app = build_app(store, internal_token=internal_token)
        import uvicorn

        uvicorn.run(app, host=args.bind, port=args.port, access_log=False)
        return 0
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
