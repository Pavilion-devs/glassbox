"""Thin MCP transport for the protocol-neutral GlassBox forensics service."""

from __future__ import annotations

import argparse
import hmac
import os
from pathlib import Path
from typing import Any

from glassbox_dbom import load_signer_trust_policy
from glassbox_forensics.live_state import (
    TransactionalCampaignReader,
    TransactionalReceiptPublicationReader,
)
from glassbox_forensics.service import (
    ForensicsInputError,
    ForensicsNotFoundError,
    ForensicsService,
)
from glassbox_invalidation import VerifiedReceiptStore
from glassbox_policy import ChangeKind, NormalizedChange


class MCPDependencyError(RuntimeError):
    """Raised when the optional MCP transport dependency is unavailable."""


def build_server(service: ForensicsService, *, http_bearer_token: str | None = None) -> Any:
    """Create the MCP server without putting policy inside the transport layer."""

    try:
        from mcp.server import MCPServer
        from mcp.types import ToolAnnotations
    except ImportError as exc:  # pragma: no cover - exercised without optional extra
        raise MCPDependencyError(
            "the MCP transport requires the 'mcp' optional dependency"
        ) from exc

    server = MCPServer(
        "GlassBox Agent Decision Forensics",
        version="0.1.0",
        instructions=(
            "Read-only decision evidence. Use DataHub MCP for catalog discovery; "
            "use these tools only for signed receipts and deterministic impact."
        ),
    )
    read_only = ToolAnnotations(
        read_only_hint=True,
        destructive_hint=False,
        idempotent_hint=True,
        open_world_hint=False,
    )

    @server.tool(annotations=read_only)
    def verify_decision_receipt(receipt_id: str) -> dict[str, object]:
        """Verify a stored signed decision receipt without returning its raw body."""

        return service.verify_decision_receipt(receipt_id)

    @server.tool(annotations=read_only)
    def get_decision_influence(receipt_id: str) -> dict[str, object]:
        """Get the evidence that influenced one decision and its completeness state."""

        return service.get_decision_influence(receipt_id)

    @server.tool(annotations=read_only)
    def get_decision_publication(receipt_id: str) -> dict[str, object]:
        """Get sealed durable DataHub-publication evidence for one decision receipt."""

        return service.get_decision_publication(receipt_id)

    @server.tool(annotations=read_only)
    def classify_decision_impact(
        receipt_id: str,
        event_id: str,
        entity_urn: str,
        aspect_name: str,
        kind: str,
        occurred_at: str,
        schema_field_urn: str | None = None,
        before_digest: str | None = None,
        after_digest: str | None = None,
    ) -> dict[str, object]:
        """Classify whether one verified decision is affected by one metadata change."""

        change = _change(
            event_id=event_id,
            entity_urn=entity_urn,
            aspect_name=aspect_name,
            kind=kind,
            occurred_at=occurred_at,
            schema_field_urn=schema_field_urn,
            before_digest=before_digest,
            after_digest=after_digest,
        )
        return service.classify_decision_impact(receipt_id, change)

    @server.tool(annotations=read_only)
    def list_affected_decisions(
        event_id: str,
        entity_urn: str,
        aspect_name: str,
        kind: str,
        occurred_at: str,
        schema_field_urn: str | None = None,
        before_digest: str | None = None,
        after_digest: str | None = None,
        limit: int = 100,
    ) -> dict[str, object]:
        """List stale, at-risk, or unknown decisions in the configured receipt index."""

        change = _change(
            event_id=event_id,
            entity_urn=entity_urn,
            aspect_name=aspect_name,
            kind=kind,
            occurred_at=occurred_at,
            schema_field_urn=schema_field_urn,
            before_digest=before_digest,
            after_digest=after_digest,
        )
        return service.list_affected_decisions(change, limit=limit)

    @server.tool(annotations=read_only)
    def get_invalidation_campaign(campaign_id: str) -> dict[str, object]:
        """Get one persisted campaign produced by the running DataHub Action."""

        return service.get_invalidation_campaign(campaign_id)

    @server.tool(annotations=read_only)
    def list_decision_findings(
        receipt_id: str,
        limit: int = 100,
    ) -> dict[str, object]:
        """List metadata-change findings actually persisted for one decision."""

        return service.list_decision_findings(receipt_id, limit=limit)

    try:
        from starlette.requests import Request
        from starlette.responses import JSONResponse
    except ImportError:  # pragma: no cover - MCP installs the HTTP dependency
        return server

    def unauthorized(request: Request) -> Any | None:
        if http_bearer_token is None:
            return None
        authorization = request.headers.get("authorization")
        expected = f"Bearer {http_bearer_token}"
        if authorization is not None and hmac.compare_digest(
            authorization.encode(), expected.encode()
        ):
            return None
        return _console_error("UNAUTHENTICATED", "Service authentication failed.", status_code=401)

    async def health(request: Request) -> Any:
        if (rejected := unauthorized(request)) is not None:
            return rejected
        return JSONResponse(
            {
                "status": "ok",
                "service": "glassbox-forensics",
                "contract_version": "glassbox.console-api.v1",
            }
        )

    async def console_overview(request: Request) -> Any:
        if (rejected := unauthorized(request)) is not None:
            return rejected
        return JSONResponse(service.get_console_overview())

    async def console_receipts(request: Request) -> Any:
        if (rejected := unauthorized(request)) is not None:
            return rejected
        try:
            return JSONResponse(
                service.list_decisions(
                    query=request.query_params.get("query"),
                    limit=_query_int(request, "limit", 100),
                    offset=_query_int(request, "offset", 0),
                )
            )
        except ForensicsInputError as exc:
            return _console_error("INVALID_ARGUMENT", str(exc), status_code=400)

    async def console_receipt_findings(request: Request) -> Any:
        if (rejected := unauthorized(request)) is not None:
            return rejected
        try:
            return JSONResponse(
                service.list_decision_findings(
                    request.path_params["receipt_id"],
                    limit=_query_int(request, "limit", 100),
                )
            )
        except ForensicsInputError as exc:
            return _console_error("INVALID_ARGUMENT", str(exc), status_code=400)
        except ForensicsNotFoundError as exc:
            return _console_error("NOT_FOUND", str(exc), status_code=404)

    async def console_receipt(request: Request) -> Any:
        if (rejected := unauthorized(request)) is not None:
            return rejected
        try:
            receipt_id = request.path_params["receipt_id"]
            return JSONResponse(
                {
                    "contract_version": "glassbox.console-api.v1",
                    "verification": service.verify_decision_receipt(receipt_id),
                    "influence": service.get_decision_influence(receipt_id),
                    "publication": service.get_decision_publication(receipt_id),
                }
            )
        except ForensicsInputError as exc:
            return _console_error("INVALID_ARGUMENT", str(exc), status_code=400)
        except ForensicsNotFoundError as exc:
            return _console_error("NOT_FOUND", str(exc), status_code=404)

    async def console_campaigns(request: Request) -> Any:
        if (rejected := unauthorized(request)) is not None:
            return rejected
        try:
            return JSONResponse(
                service.list_invalidation_campaigns(
                    limit=_query_int(request, "limit", 100),
                    offset=_query_int(request, "offset", 0),
                )
            )
        except ForensicsInputError as exc:
            return _console_error("INVALID_ARGUMENT", str(exc), status_code=400)

    async def console_campaign(request: Request) -> Any:
        if (rejected := unauthorized(request)) is not None:
            return rejected
        try:
            return JSONResponse(
                service.get_invalidation_campaign(request.path_params["campaign_id"])
            )
        except ForensicsInputError as exc:
            return _console_error("INVALID_ARGUMENT", str(exc), status_code=400)
        except ForensicsNotFoundError as exc:
            return _console_error("NOT_FOUND", str(exc), status_code=404)

    server.custom_route("/health", methods=["GET"])(health)
    server.custom_route("/api/v1/overview", methods=["GET"])(console_overview)
    server.custom_route("/api/v1/receipts", methods=["GET"])(console_receipts)
    server.custom_route(
        "/api/v1/receipts/{receipt_id:path}/findings",
        methods=["GET"],
    )(console_receipt_findings)
    server.custom_route("/api/v1/receipts/{receipt_id:path}", methods=["GET"])(console_receipt)
    server.custom_route("/api/v1/campaigns", methods=["GET"])(console_campaigns)
    server.custom_route("/api/v1/campaigns/{campaign_id:path}", methods=["GET"])(console_campaign)
    return server


def main() -> None:
    """Run the local read-only server over stdio."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--receipt-store",
        type=Path,
        default=None,
        help="append-only verified receipt JSONL path (or GLASSBOX_RECEIPT_STORE_PATH)",
    )
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="development-only: do not require an Ed25519 receipt signature",
    )
    parser.add_argument(
        "--signer-trust-policy",
        type=Path,
        default=None,
        help=("trusted-signer policy path (or GLASSBOX_SIGNER_TRUST_POLICY_PATH)"),
    )
    parser.add_argument(
        "--allow-untrusted-signers",
        action="store_true",
        help="development-only: accept self-contained signatures without an operator trust anchor",
    )
    parser.add_argument(
        "--state-postgres-dsn-env",
        default=None,
        help="environment-variable name containing the Action PostgreSQL DSN",
    )
    parser.add_argument(
        "--state-postgres-schema",
        default="glassbox",
        help="existing Action PostgreSQL schema (default: glassbox)",
    )
    parser.add_argument(
        "--postgres-connect-timeout-seconds",
        type=float,
        default=10.0,
        help="bounded PostgreSQL connection timeout",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
        help="serve MCP over stdio or the loopback HTTP operator surface",
    )
    parser.add_argument(
        "--http-host",
        default="127.0.0.1",
        help="loopback host for streamable HTTP (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--http-port",
        type=int,
        default=8788,
        help="port for streamable HTTP and the console API (default: 8788)",
    )
    parser.add_argument(
        "--http-bearer-token-env",
        default="GLASSBOX_FORENSICS_API_TOKEN",
        help="environment variable containing the private console API bearer token",
    )
    args = parser.parse_args()
    configured = args.receipt_store or _path_from_environment()
    if configured is not None and args.state_postgres_dsn_env is not None:
        parser.error("configure either a receipt store or PostgreSQL live state, not both")
    require_signature = not args.allow_unsigned
    trust_policy_path = args.signer_trust_policy or _trust_path_from_environment()
    if trust_policy_path is None and not args.allow_untrusted_signers:
        parser.error(
            "--signer-trust-policy or GLASSBOX_SIGNER_TRUST_POLICY_PATH is required; "
            "use --allow-untrusted-signers only for development"
        )
    if args.allow_unsigned and trust_policy_path is not None:
        parser.error("--allow-unsigned cannot be combined with a signer trust policy")
    signer_trust_policy = (
        load_signer_trust_policy(trust_policy_path) if trust_policy_path is not None else None
    )
    if args.state_postgres_dsn_env is not None:
        dsn = os.getenv(args.state_postgres_dsn_env)
        if dsn is None or not dsn:
            parser.error("configured PostgreSQL DSN environment variable is unset")
        from glassbox_invalidation.postgres_store import PostgresInvalidationStore

        postgres_store = PostgresInvalidationStore(
            dsn,
            schema=args.state_postgres_schema,
            require_signature=require_signature,
            signer_trust_policy=signer_trust_policy,
            connect_timeout_seconds=args.postgres_connect_timeout_seconds,
            initialize_schema=False,
        )
        service = ForensicsService(
            postgres_store,
            artifacts=postgres_store,
            findings=TransactionalCampaignReader(postgres_store),
            publications=TransactionalReceiptPublicationReader(
                postgres_store,
                durability_authority="POSTGRESQL",
            ),
            require_signature=require_signature,
            signer_trust_policy=signer_trust_policy,
        )
    else:
        if configured is None:
            parser.error(
                "--receipt-store, GLASSBOX_RECEIPT_STORE_PATH, or "
                "--state-postgres-dsn-env is required"
            )
        jsonl_store = VerifiedReceiptStore(
            configured,
            require_signature=require_signature,
            signer_trust_policy=signer_trust_policy,
        )
        service = ForensicsService(
            jsonl_store,
            artifacts=jsonl_store,
            require_signature=require_signature,
            signer_trust_policy=signer_trust_policy,
        )
    http_bearer_token = os.getenv(args.http_bearer_token_env) or None
    server = (
        build_server(service, http_bearer_token=http_bearer_token)
        if http_bearer_token is not None
        else build_server(service)
    )
    if args.transport == "stdio":
        server.run()
    else:
        if args.http_host not in {"127.0.0.1", "localhost", "::1"} and http_bearer_token is None:
            parser.error("a non-loopback console API bind requires bearer authentication")
        if not 1 <= args.http_port <= 65535:
            parser.error("http-port must be between 1 and 65535")
        server.run(
            transport="streamable-http",
            host=args.http_host,
            port=args.http_port,
            json_response=True,
            stateless_http=True,
        )


def _path_from_environment() -> Path | None:
    value = os.environ.get("GLASSBOX_RECEIPT_STORE_PATH")
    return Path(value) if value else None


def _trust_path_from_environment() -> Path | None:
    value = os.environ.get("GLASSBOX_SIGNER_TRUST_POLICY_PATH")
    return Path(value) if value else None


def _query_int(request: Any, name: str, default: int) -> int:
    raw = request.query_params.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ForensicsInputError(f"{name} must be an integer") from exc


def _console_error(code: str, message: str, *, status_code: int) -> Any:
    from starlette.responses import JSONResponse

    return JSONResponse(
        {
            "contract_version": "glassbox.console-api.v1",
            "error": {"code": code, "message": message},
            "raw_content_returned": False,
        },
        status_code=status_code,
    )


def _change(
    *,
    event_id: str,
    entity_urn: str,
    aspect_name: str,
    kind: str,
    occurred_at: str,
    schema_field_urn: str | None,
    before_digest: str | None,
    after_digest: str | None,
) -> NormalizedChange:
    try:
        selected_kind = ChangeKind(kind)
    except ValueError as exc:
        allowed = ", ".join(item.value for item in ChangeKind)
        raise ValueError(f"kind must be one of: {allowed}") from exc
    return NormalizedChange(
        event_id=event_id,
        entity_urn=entity_urn,
        aspect_name=aspect_name,
        kind=selected_kind,
        occurred_at=occurred_at,
        schema_field_urn=schema_field_urn,
        before_digest=before_digest,
        after_digest=after_digest,
    )


if __name__ == "__main__":
    main()
