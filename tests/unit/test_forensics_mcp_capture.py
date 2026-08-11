"""Closed-surface tests for the filmed live MCP investigation helper."""

from __future__ import annotations

from scripts.forensics_mcp_capture import QUESTION, _latest_flagship_campaign, render
from scripts.remote_forensics_mcp_capture import REMOTE_COMMAND
from scripts.remote_forensics_mcp_capture import main as remote_main


def _campaign() -> dict[str, object]:
    return {
        "campaign_id": "gbx:invalidation:sha256:" + "a" * 64,
        "change": {
            "entity_urn": ("urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"),
            "kind": "SCHEMA_FIELD_TYPE_CHANGED",
            "schema_field_urn": "urn:li:schemaField:(commerce.orders,average_order_value)",
        },
        "processing": {
            "workflow_status": "COMPLETED",
            "datahub_writeback_state": "VERIFIED",
        },
    }


def test_campaign_discovery_selects_only_completed_verified_flagship() -> None:
    selected = _latest_flagship_campaign({"campaigns": [_campaign()]})
    assert selected["campaign_id"] == "gbx:invalidation:sha256:" + "a" * 64


def test_render_is_raw_free_and_names_the_real_mcp_question() -> None:
    output = render(
        {
            "protocol": "2025-11-25",
            "tool_count": 7,
            "change_kind": "SCHEMA_FIELD_TYPE_CHANGED",
            "affected_count": 2,
            "receipts": ["gbx:receipt:sha256:" + "b" * 64],
            "states": ["STALE"],
            "reasons": ["EXACT_FIELD_DEPENDENCY"],
            "verification": "VERIFIED_NOW",
            "dependency_state": "OBSERVED",
            "campaign_id": "gbx:invalidation:sha256:" + "a" * 64,
            "workflow": "COMPLETED",
            "writeback": "VERIFIED",
        }
    )
    assert QUESTION in output
    assert "AUTHENTICATED · READ ONLY" in output
    assert "Raw content   NOT RETURNED" in output


def test_remote_wrapper_has_no_mutation_or_secret_arguments() -> None:
    assert remote_main(["--campaign-id", "anything"]) == 2
    assert "forensics_mcp_capture.py" in REMOTE_COMMAND
    assert "GLASSBOX_FORENSICS_API_TOKEN" not in REMOTE_COMMAND
    assert "guarded_schema_change" not in REMOTE_COMMAND
