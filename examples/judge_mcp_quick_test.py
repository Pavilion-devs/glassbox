"""Run a fresh signed decision through the real read-only GlassBox MCP surface.

This is a local protocol proof for evaluators. It executes the deterministic pricing
agent, creates an ephemeral Ed25519 authority, persists the receipt and one impact
campaign, then uses the official MCP client to discover and call every GlassBox tool.
It never contacts a remote service and never returns raw prompts, outputs, or values.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

from examples.end_to_end_receipt import (
    build_signed_receipt,
    demo_signer_trust_policy,
    demo_signing_key,
)
from mcp.client import Client

from glassbox_forensics import ForensicsService
from glassbox_forensics.live_state import (
    TransactionalCampaignReader,
    TransactionalReceiptPublicationReader,
)
from glassbox_forensics.server import build_server
from glassbox_invalidation import SQLiteInvalidationStore
from glassbox_policy import ChangeKind, NormalizedChange, create_campaign

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},average_order_value)"
EXPECTED_TOOLS = (
    "verify_decision_receipt",
    "get_decision_influence",
    "get_decision_publication",
    "classify_decision_impact",
    "list_affected_decisions",
    "get_invalidation_campaign",
    "list_decision_findings",
)


def _structured(result: Any, tool_name: str) -> Mapping[str, Any]:
    if result.is_error:
        raise RuntimeError(f"MCP tool {tool_name!r} returned a protocol error")
    content = result.structured_content
    if not isinstance(content, Mapping):
        raise RuntimeError(f"MCP tool {tool_name!r} returned no structured content")
    return content


def _raw_content_returned(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("raw_content_returned") is True:
            return True
        return any(_raw_content_returned(item) for item in value.values())
    if isinstance(value, list | tuple):
        return any(_raw_content_returned(item) for item in value)
    return False


async def run_judge_mcp_quick_test(state_dir: Path) -> dict[str, Any]:
    """Execute the fresh local proof and return its bounded result."""

    signing_key = demo_signing_key()
    trust_policy = demo_signer_trust_policy(signing_key)
    receipt = build_signed_receipt(schema_field_urn=FIELD, signing_key=signing_key)

    store = SQLiteInvalidationStore(
        state_dir / "judge-mcp.sqlite3",
        signer_trust_policy=trust_policy,
    )
    inserted = store.register(receipt)
    change = NormalizedChange(
        event_id="judge-schema-change-001",
        entity_urn=DATASET,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-11T00:00:00Z",
        schema_field_urn=FIELD,
    )
    campaign = create_campaign(change, store.all_profiles())
    store.stage_campaign(campaign)

    service = ForensicsService(
        store,
        artifacts=store,
        findings=TransactionalCampaignReader(store),
        publications=TransactionalReceiptPublicationReader(store),
        signer_trust_policy=trust_policy,
    )
    server = build_server(service)
    responses: dict[str, Mapping[str, Any]] = {}

    async with Client(server) as client:
        discovered = await client.list_tools()
        tool_names = tuple(tool.name for tool in discovered.tools)
        annotations_are_read_only = all(
            tool.annotations is not None
            and tool.annotations.read_only_hint is True
            and tool.annotations.destructive_hint is False
            and tool.annotations.idempotent_hint is True
            and tool.annotations.open_world_hint is False
            for tool in discovered.tools
        )
        if tool_names != EXPECTED_TOOLS:
            raise RuntimeError("the MCP tool contract does not match the expected closed surface")
        if not annotations_are_read_only:
            raise RuntimeError("the MCP tool contract is not uniformly read-only")

        receipt_id = str(receipt["receipt_id"])
        change_arguments = {
            "event_id": change.event_id,
            "entity_urn": change.entity_urn,
            "aspect_name": change.aspect_name,
            "kind": change.kind.value,
            "occurred_at": change.occurred_at,
            "schema_field_urn": change.schema_field_urn,
        }
        calls = (
            ("verify_decision_receipt", {"receipt_id": receipt_id}),
            ("get_decision_influence", {"receipt_id": receipt_id}),
            ("get_decision_publication", {"receipt_id": receipt_id}),
            ("classify_decision_impact", {"receipt_id": receipt_id, **change_arguments}),
            ("list_affected_decisions", change_arguments),
            ("get_invalidation_campaign", {"campaign_id": campaign.campaign_id}),
            ("list_decision_findings", {"receipt_id": receipt_id}),
        )
        for tool_name, arguments in calls:
            responses[tool_name] = _structured(
                await client.call_tool(tool_name, arguments),
                tool_name,
            )

    verification = responses["verify_decision_receipt"]
    influence = responses["get_decision_influence"]
    publication = responses["get_decision_publication"]
    impact = responses["classify_decision_impact"]
    reverse = responses["list_affected_decisions"]
    persisted = responses["get_invalidation_campaign"]
    findings = responses["list_decision_findings"]
    valid = all(
        (
            inserted,
            verification.get("verification_state") == "VERIFIED_NOW",
            verification.get("valid") is True,
            influence.get("raw_content_returned") is False,
            publication.get("availability") == "AVAILABLE",
            impact.get("assessment", {}).get("state") == "STALE",
            reverse.get("scan_complete") is True,
            reverse.get("review_required_total") == 1,
            persisted.get("availability") == "AVAILABLE",
            findings.get("findings_total") == 1,
            not _raw_content_returned(responses),
        )
    )
    return {
        "valid": valid,
        "proof": "fresh local MCP protocol run",
        "agent_run_executed": True,
        "external_datahub_contacted": False,
        "receipt_id": receipt["receipt_id"],
        "campaign_id": campaign.campaign_id,
        "mcp": {
            "tools_discovered": len(EXPECTED_TOOLS),
            "tools_called": len(responses),
            "read_only_contract": True,
        },
        "verification_state": verification.get("verification_state"),
        "dependency": FIELD,
        "impact_state": impact.get("assessment", {}).get("state"),
        "affected_decisions": reverse.get("review_required_total"),
        "campaign_state": persisted.get("campaign", {})
        .get("processing", {})
        .get("workflow_status"),
        "publication_state": publication.get("durability", {}).get("workflow_status"),
        "raw_content_returned": False,
    }


def main() -> int:
    with TemporaryDirectory(prefix="glassbox-judge-mcp-") as directory:
        report = asyncio.run(run_judge_mcp_quick_test(Path(directory)))
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
