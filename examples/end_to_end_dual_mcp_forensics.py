"""Live proof: official DataHub MCP plus GlassBox MCP over one Action campaign."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import shutil
import sys
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import psycopg
from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from examples.end_to_end_invalidation import (
    CHANGE_TIME_MS,
    FIELD_PATH,
    FIELD_URN,
    _emit_schema,
    _mcl,
    _schema,
)
from examples.end_to_end_receipt import (
    build_signed_receipt,
    demo_signer_trust_policy,
    demo_signing_key,
)
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from psycopg import sql

from glassbox_compiler import LiveReceiptPipeline, VerifiedURNResolver
from glassbox_datahub import DataHubInvalidationBackend, DataHubReceiptBackend, ReceiptEmitter
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_forensics import (
    DualMCPExpectation,
    MCPToolContract,
    compose_dual_mcp_evidence,
)
from glassbox_invalidation import TransactionalInvalidationAction
from glassbox_invalidation.datahub_action import (
    GlassBoxInvalidationAction,
    GlassBoxInvalidationActionConfig,
)
from glassbox_invalidation.postgres_store import PostgresInvalidationStore
from glassbox_policy import FieldCoverage, FieldLineageProof

OFFICIAL_DATAHUB_MCP_PACKAGE = "mcp-server-datahub"
OFFICIAL_DATAHUB_MCP_VERSION = "0.6.0"
PROOF_DATE = "2026-08-07"
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
EXPECTED_NATIVE_TYPE = "DECIMAL(18,2)"
_BEFORE_TIME_MS = CHANGE_TIME_MS - 7_200_000
_UNRELATED_TIME_MS = CHANGE_TIME_MS - 3_600_000


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-dual-mcp-forensics")
    parser.add_argument("--server", default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    parser.add_argument("--state-postgres-dsn-env", default="GLASSBOX_STATE_POSTGRES_DSN")
    parser.add_argument("--uvx", type=Path, default=None)
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    return parser


def _tool_contracts(tools: Sequence[Any]) -> tuple[MCPToolContract, ...]:
    contracts = []
    for tool in tools:
        annotations = tool.annotations
        contracts.append(
            MCPToolContract(
                name=tool.name,
                read_only=(annotations.read_only_hint if annotations is not None else None),
                destructive=(annotations.destructive_hint if annotations is not None else None),
                idempotent=(annotations.idempotent_hint if annotations is not None else None),
                open_world=(annotations.open_world_hint if annotations is not None else None),
            )
        )
    return tuple(contracts)


def _structured(result: Any, *, tool_name: str) -> Mapping[str, Any]:
    if result.is_error:
        raise RuntimeError(f"MCP tool {tool_name!r} returned a protocol error")
    value = result.structured_content
    if not isinstance(value, Mapping):
        raise RuntimeError(f"MCP tool {tool_name!r} returned no structured content")
    return value


async def _query_both_servers(
    *,
    server: str,
    token: str | None,
    dsn_environment_name: str,
    dsn: str,
    schema: str,
    trust_policy_path: Path,
    uvx: Path,
    expectation: DualMCPExpectation,
) -> tuple[dict[str, object], dict[str, str]]:
    datahub_environment = os.environ.copy()
    datahub_environment.update(
        {
            "DATAHUB_GMS_URL": server,
            "TOOLS_IS_MUTATION_ENABLED": "false",
            "TOOLS_IS_USER_ENABLED": "false",
            "DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED": "true",
        }
    )
    if token is None:
        datahub_environment.pop("DATAHUB_GMS_TOKEN", None)
    else:
        datahub_environment["DATAHUB_GMS_TOKEN"] = token
    glassbox_environment = os.environ.copy()
    glassbox_environment[dsn_environment_name] = dsn

    datahub_parameters = StdioServerParameters(
        command=str(uvx),
        args=[
            "--from",
            f"{OFFICIAL_DATAHUB_MCP_PACKAGE}=={OFFICIAL_DATAHUB_MCP_VERSION}",
            OFFICIAL_DATAHUB_MCP_PACKAGE,
            "--transport",
            "stdio",
        ],
        env=datahub_environment,
    )
    glassbox_parameters = StdioServerParameters(
        command=sys.executable,
        args=[
            "-m",
            "glassbox_forensics.server",
            "--state-postgres-dsn-env",
            dsn_environment_name,
            "--state-postgres-schema",
            schema,
            "--signer-trust-policy",
            str(trust_policy_path),
        ],
        env=glassbox_environment,
    )

    with Path(os.devnull).open("w", encoding="utf-8") as error_log:
        async with stdio_client(datahub_parameters, errlog=error_log) as (
            datahub_read,
            datahub_write,
        ):
            async with ClientSession(datahub_read, datahub_write) as datahub_session:
                datahub_initialize = await datahub_session.initialize()
                datahub_discovery = await datahub_session.list_tools()
                datahub_entities_result = await datahub_session.call_tool(
                    "get_entities",
                    {"urns": [expectation.dataset_urn, expectation.incident_urn]},
                )
                async with stdio_client(glassbox_parameters, errlog=error_log) as (
                    glassbox_read,
                    glassbox_write,
                ):
                    async with ClientSession(
                        glassbox_read,
                        glassbox_write,
                    ) as glassbox_session:
                        glassbox_initialize = await glassbox_session.initialize()
                        glassbox_discovery = await glassbox_session.list_tools()
                        receipt = await glassbox_session.call_tool(
                            "verify_decision_receipt",
                            {"receipt_id": expectation.receipt_id},
                        )
                        influence = await glassbox_session.call_tool(
                            "get_decision_influence",
                            {"receipt_id": expectation.receipt_id},
                        )
                        campaign = await glassbox_session.call_tool(
                            "get_invalidation_campaign",
                            {"campaign_id": expectation.campaign_id},
                        )
                        findings = await glassbox_session.call_tool(
                            "list_decision_findings",
                            {"receipt_id": expectation.receipt_id},
                        )
                        report = compose_dual_mcp_evidence(
                            expectation=expectation,
                            datahub_tools=_tool_contracts(datahub_discovery.tools),
                            glassbox_tools=_tool_contracts(glassbox_discovery.tools),
                            datahub_entities=_structured(
                                datahub_entities_result,
                                tool_name="get_entities",
                            ),
                            receipt_verification=_structured(
                                receipt,
                                tool_name="verify_decision_receipt",
                            ),
                            influence=_structured(
                                influence,
                                tool_name="get_decision_influence",
                            ),
                            campaign=_structured(
                                campaign,
                                tool_name="get_invalidation_campaign",
                            ),
                            findings=_structured(
                                findings,
                                tool_name="list_decision_findings",
                            ),
                        )
                        if (
                            datahub_initialize.protocol_version
                            != glassbox_initialize.protocol_version
                        ):
                            raise RuntimeError(
                                "the two MCP servers negotiated different protocol versions"
                            )
                        server_info = {
                            "datahub_mcp_name": datahub_initialize.server_info.name,
                            "datahub_mcp_reported_server_version": (
                                datahub_initialize.server_info.version
                            ),
                            "glassbox_mcp_name": glassbox_initialize.server_info.name,
                            "glassbox_mcp_reported_server_version": (
                                glassbox_initialize.server_info.version
                            ),
                            "negotiated_mcp_protocol_version": (
                                datahub_initialize.protocol_version
                            ),
                        }
                        return report, server_info


def _drop_schema(dsn: str, schema: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
        )


def _datahub_version(graph: DataHubGraph) -> tuple[str, str]:
    config = graph.get_config()
    versions = config.get("versions")
    if not isinstance(versions, Mapping):
        raise RuntimeError("DataHub Core did not return version metadata")
    datahub = versions.get("acryldata/datahub")
    if not isinstance(datahub, Mapping):
        raise RuntimeError("DataHub Core version metadata omitted acryldata/datahub")
    version = datahub.get("version")
    commit = datahub.get("commit")
    if not isinstance(version, str) or not isinstance(commit, str):
        raise RuntimeError("DataHub Core version metadata is incomplete")
    return version, commit


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    dsn = os.getenv(args.state_postgres_dsn_env)
    if dsn is None or not dsn:
        raise ValueError("configured PostgreSQL DSN environment variable is unset")
    uvx_value = args.uvx or (Path(found) if (found := shutil.which("uvx")) else None)
    if uvx_value is None or not uvx_value.is_file():
        raise ValueError("uvx is required to launch the pinned official DataHub MCP server")

    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=args.token))
    graph.test_connection()
    core_version, core_commit = _datahub_version(graph)
    schema = f"gbx_dual_mcp_{uuid.uuid4().hex}"
    try:
        before = _schema(native_type="VARCHAR", numeric=False, time_ms=_BEFORE_TIME_MS)
        after_unrelated = _schema(
            native_type="VARCHAR",
            numeric=False,
            time_ms=_UNRELATED_TIME_MS,
            include_unrelated=True,
        )
        after = _schema(
            native_type=EXPECTED_NATIVE_TYPE,
            numeric=True,
            time_ms=CHANGE_TIME_MS,
            include_unrelated=True,
        )
        _emit_schema(graph, before)
        _emit_schema(graph, after_unrelated)

        receipt_backend = DataHubReceiptBackend(server=server, token=args.token)
        receipt_backend.test_connection()
        signing_key = demo_signing_key()
        trust_policy = demo_signer_trust_policy(signing_key)
        receipt = build_signed_receipt(
            urn_resolver=VerifiedURNResolver(receipt_backend),
            schema_field_urn=FIELD_URN,
            signing_key=signing_key,
        )
        store = PostgresInvalidationStore(
            dsn,
            schema=schema,
            signer_trust_policy=trust_policy,
        )
        lineage = FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.dual-mcp-live-proof.v1",
            wildcard_query=False,
        )
        publication = LiveReceiptPipeline(
            store,
            ReceiptEmitter(receipt_backend, signer_trust_policy=trust_policy),
        ).publish_compiled(receipt, field_lineage=lineage)
        if not publication.valid:
            raise RuntimeError("live receipt registration and DataHub publication failed")

        with TemporaryDirectory(prefix="glassbox-dual-mcp-") as temporary:
            policy_path = Path(temporary) / "trusted-signers.json"
            policy_path.write_text(
                json.dumps(trust_policy.to_dict(), sort_keys=True),
                encoding="utf-8",
            )
            policy_path.chmod(0o600)
            invalidation_backend = DataHubInvalidationBackend.from_graph(graph)
            invalidation_backend.test_connection()
            action = TransactionalInvalidationAction(
                invalidation_backend,
                store,
                worker_id="dual-mcp-live-action",
            )
            plugin = GlassBoxInvalidationAction(
                GlassBoxInvalidationActionConfig(
                    state_postgres_dsn_env=args.state_postgres_dsn_env,
                    state_postgres_schema=schema,
                    signer_trust_policy_path=policy_path,
                    worker_id="dual-mcp-live-action",
                ),
                action,
                store,
            )
            _emit_schema(graph, after)
            envelope = _mcl(
                after_unrelated,
                after,
                event_time_ms=CHANGE_TIME_MS,
            )
            if not plugin.act(envelope) or len(plugin.last_reports) != 1:
                raise RuntimeError("DataHub Action did not complete exactly one material change")
            first = plugin.last_reports[0]
            if not plugin.act(envelope) or len(plugin.last_reports) != 1:
                raise RuntimeError("DataHub Action redelivery did not return one campaign")
            redelivery = plugin.last_reports[0]
            if not (
                first.valid
                and first.emissions == 2
                and redelivery.valid
                and redelivery.emissions == 0
                and redelivery.reused_completion
                and first.campaign.campaign_id == redelivery.campaign.campaign_id
            ):
                raise RuntimeError("DataHub Action campaign did not seal idempotently")

            expectation = DualMCPExpectation(
                dataset_urn=DATASET_URN,
                field_path=FIELD_PATH,
                native_type=EXPECTED_NATIVE_TYPE,
                receipt_id=str(receipt["receipt_id"]),
                document_urn=publication.datahub.document_urn,
                campaign_id=first.campaign.campaign_id,
                incident_urn=first.campaign.incident_urn,
            )
            composed, server_info = asyncio.run(
                _query_both_servers(
                    server=server,
                    token=args.token,
                    dsn_environment_name=args.state_postgres_dsn_env,
                    dsn=dsn,
                    schema=schema,
                    trust_policy_path=policy_path,
                    uvx=uvx_value,
                    expectation=expectation,
                )
            )

        integrity = store.verify_integrity()
        with psycopg.connect(dsn) as connection:
            version_row = connection.execute("SHOW server_version").fetchone()
        if version_row is None:
            raise RuntimeError("PostgreSQL did not return its server version")
        composed["runtime"] = {
            "proof_date": PROOF_DATE,
            "datahub_core_version": core_version,
            "datahub_core_commit": core_commit,
            "datahub_sdk_version": receipt_backend.sdk_version,
            "official_datahub_mcp_package": OFFICIAL_DATAHUB_MCP_PACKAGE,
            "official_datahub_mcp_package_version": OFFICIAL_DATAHUB_MCP_VERSION,
            **server_info,
            "postgresql_server_version": version_row[0],
            "postgresql_schema_version": 3,
        }
        composed["action"] = {
            "real_datahub_writeback": True,
            "official_actions_envelope": True,
            "campaign_status": "COMPLETED",
            "first_delivery_emissions": first.emissions,
            "redelivery_emissions": redelivery.emissions,
            "reused_completion": redelivery.reused_completion,
            "target_summary_verified": first.write_evidence.target_summary_verified
            if first.write_evidence is not None
            else False,
        }
        composed["state"] = {
            "engine": "PostgreSQL",
            "receipts": integrity.receipts,
            "campaigns": integrity.campaigns,
            "audit_records": integrity.audit_records,
            "dsn_persisted_or_reported": False,
            "receipt_body_returned": False,
        }
        datahub_projection = composed.get("datahub_mcp")
        if not isinstance(datahub_projection, Mapping):  # pragma: no cover - fixed shape
            raise RuntimeError("dual-MCP report has no DataHub projection")
        composed["scope"] = {
            "live_datahub_core": "PROVEN",
            "live_postgresql": "PROVEN",
            "official_datahub_mcp_stdio": "PROVEN",
            "glassbox_mcp_stdio": "PROVEN",
            "exact_incident_body_via_official_datahub_mcp": datahub_projection[
                "exact_incident_entity_projection"
            ],
            "kafka_delivery_in_this_run": "NOT_EXERCISED",
            "remote_mcp_authentication": "NOT_EXERCISED",
            "organizational_retention_completeness": "CONFIGURATION_DEPENDENT",
        }
        print(json.dumps(composed, indent=2, sort_keys=True))
        return 0
    finally:
        _drop_schema(dsn, schema)


if __name__ == "__main__":
    raise SystemExit(main())
