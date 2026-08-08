"""Official MCP SDK protocol tests for the read-only forensics adapter."""

from __future__ import annotations

import asyncio
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp.client import Client

from glassbox_dbom import SigningKey, seal_receipt
from glassbox_forensics import ForensicsService
from glassbox_forensics.live_state import TransactionalCampaignReader
from glassbox_forensics.server import build_server
from glassbox_invalidation import SQLiteInvalidationStore, VerifiedReceiptStore
from glassbox_policy import (
    ChangeKind,
    InvalidationWriteEvidence,
    NormalizedChange,
    create_campaign,
)
from tests.helpers import receipt_payload

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},revenue)"


def test_official_client_discovers_only_read_only_tools_and_calls_every_contract(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        payload = receipt_payload()
        payload["evidence"][0]["schema_field_urn"] = FIELD
        receipt = seal_receipt(
            payload,
            signing_keys=[SigningKey("mcp-test-key", Ed25519PrivateKey.generate())],
        )
        store = SQLiteInvalidationStore(tmp_path / "live-state.sqlite3")
        store.register(receipt)
        normalized_change = NormalizedChange(
            event_id="mcl-schema-001",
            entity_urn=DATASET,
            aspect_name="schemaMetadata",
            kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
            occurred_at="2026-08-07T00:00:00Z",
            schema_field_urn=FIELD,
        )
        campaign = create_campaign(normalized_change, store.all_profiles())
        store.stage_campaign(campaign)
        store.claim(
            campaign.campaign_id,
            worker_id="datahub-action",
            now_ms=1,
            lease_duration_ms=10_000,
        )
        store.complete(
            campaign,
            InvalidationWriteEvidence(
                incident_aspects=("incidentInfo", "incidentKey"),
                target_summary_verified=True,
                quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
            ),
            worker_id="datahub-action",
        )
        server = build_server(
            ForensicsService(
                store,
                artifacts=store,
                findings=TransactionalCampaignReader(store),
            )
        )

        async with Client(server) as client:
            discovered = await client.list_tools()
            assert [tool.name for tool in discovered.tools] == [
                "verify_decision_receipt",
                "get_decision_influence",
                "classify_decision_impact",
                "list_affected_decisions",
                "get_invalidation_campaign",
                "list_decision_findings",
            ]
            assert all(tool.annotations is not None for tool in discovered.tools)
            assert all(tool.annotations.read_only_hint is True for tool in discovered.tools)
            assert all(tool.annotations.destructive_hint is False for tool in discovered.tools)
            assert all(tool.annotations.idempotent_hint is True for tool in discovered.tools)
            assert all(tool.annotations.open_world_hint is False for tool in discovered.tools)

            verified = await client.call_tool(
                "verify_decision_receipt", {"receipt_id": receipt["receipt_id"]}
            )
            influence = await client.call_tool(
                "get_decision_influence", {"receipt_id": receipt["receipt_id"]}
            )
            change = {
                "event_id": "mcl-schema-001",
                "entity_urn": DATASET,
                "aspect_name": "schemaMetadata",
                "kind": "SCHEMA_FIELD_TYPE_CHANGED",
                "occurred_at": "2026-08-07T00:00:00Z",
                "schema_field_urn": FIELD,
            }
            impact = await client.call_tool(
                "classify_decision_impact",
                {"receipt_id": receipt["receipt_id"], **change},
            )
            reverse = await client.call_tool("list_affected_decisions", change)
            persisted = await client.call_tool(
                "get_invalidation_campaign", {"campaign_id": campaign.campaign_id}
            )
            findings = await client.call_tool(
                "list_decision_findings", {"receipt_id": receipt["receipt_id"]}
            )

            assert verified.is_error is False
            assert verified.structured_content["verification_state"] == "VERIFIED_NOW"
            assert influence.structured_content["raw_content_returned"] is False
            assert impact.structured_content["assessment"]["state"] == "STALE"
            assert reverse.structured_content["review_required_total"] == 1
            assert reverse.structured_content["scan_complete"] is True
            assert persisted.structured_content["availability"] == "AVAILABLE"
            assert (
                persisted.structured_content["campaign"]["processing"]["datahub_writeback_state"]
                == "VERIFIED"
            )
            assert findings.structured_content["findings_total"] == 1
            assert findings.structured_content["findings"][0]["assessment"]["state"] == "STALE"

    asyncio.run(scenario())


def test_mcp_validation_and_domain_errors_are_protocol_errors_without_raw_values(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        store = VerifiedReceiptStore(tmp_path / "receipts.jsonl", sync=False)
        server = build_server(ForensicsService(store, artifacts=store))
        async with Client(server) as client:
            missing = await client.call_tool(
                "verify_decision_receipt",
                {"receipt_id": "gbx:receipt:sha256:" + "a" * 64},
            )
            malformed = await client.call_tool(
                "verify_decision_receipt", {"receipt_id": "../../secret-receipt.json"}
            )
            invalid_kind = await client.call_tool(
                "list_affected_decisions",
                {
                    "event_id": "mcl-schema-001",
                    "entity_urn": DATASET,
                    "aspect_name": "schemaMetadata",
                    "kind": "MODEL_DECIDES",
                    "occurred_at": "2026-08-07T00:00:00Z",
                },
            )

            assert missing.is_error is True
            assert "configured evidence scope" in missing.content[0].text
            assert malformed.is_error is True
            assert "content address" in malformed.content[0].text
            assert "secret-receipt" not in malformed.content[0].text
            assert invalid_kind.is_error is True
            assert "kind must be one of" in invalid_kind.content[0].text

    asyncio.run(scenario())
