"""Thin MCP transport for the protocol-neutral GlassBox forensics service."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
from typing import Any

from glassbox_dbom import load_signer_trust_policy
from glassbox_forensics.live_state import TransactionalCampaignReader
from glassbox_forensics.service import ForensicsService
from glassbox_invalidation import VerifiedReceiptStore
from glassbox_policy import ChangeKind, NormalizedChange


class MCPDependencyError(RuntimeError):
    """Raised when the optional MCP transport dependency is unavailable."""


def build_server(service: ForensicsService) -> Any:
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
    build_server(service).run()


def _path_from_environment() -> Path | None:
    value = os.environ.get("GLASSBOX_RECEIPT_STORE_PATH")
    return Path(value) if value else None


def _trust_path_from_environment() -> Path | None:
    value = os.environ.get("GLASSBOX_SIGNER_TRUST_POLICY_PATH")
    return Path(value) if value else None


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
