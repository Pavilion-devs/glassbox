"""Run the fixed, read-only Devpost investigation through the live MCP server."""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Mapping, Sequence
from typing import Any

import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

FORENSICS_ORIGIN = "http://forensics:8788"
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD_PATH = "average_order_value"
QUESTION = "Which agent decisions were affected by this change, and why?"


class ForensicsCaptureError(RuntimeError):
    """Bounded, raw-free capture failure."""


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ForensicsCaptureError(f"{label} was not returned as structured evidence")
    return value


def _sequence(value: object, label: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise ForensicsCaptureError(f"{label} was not returned as structured evidence")
    return value


def _structured(result: Any, tool_name: str) -> Mapping[str, Any]:
    if result.is_error:
        raise ForensicsCaptureError(f"the {tool_name} MCP call failed")
    return _mapping(result.structured_content, tool_name)


def _latest_flagship_campaign(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    campaigns = _sequence(payload.get("campaigns"), "campaign discovery")
    matches = []
    for value in campaigns:
        campaign = _mapping(value, "campaign")
        change = _mapping(campaign.get("change"), "campaign change")
        processing = _mapping(campaign.get("processing"), "campaign processing")
        if (
            change.get("entity_urn") == DATASET_URN
            and change.get("kind") == "SCHEMA_FIELD_TYPE_CHANGED"
            and FIELD_PATH in str(change.get("schema_field_urn", ""))
            and processing.get("workflow_status") == "COMPLETED"
            and processing.get("datahub_writeback_state") == "VERIFIED"
        ):
            matches.append(campaign)
    if not matches:
        raise ForensicsCaptureError("the completed flagship campaign is unavailable")
    return matches[0]


async def investigate() -> dict[str, object]:
    token = os.getenv("GLASSBOX_FORENSICS_API_TOKEN", "")
    if not token:
        raise ForensicsCaptureError("the private MCP credential is unavailable")
    headers = {"Authorization": f"Bearer {token}"}
    async with httpx2.AsyncClient(headers=headers, timeout=30.0) as http:
        discovery_response = await http.get(
            f"{FORENSICS_ORIGIN}/api/v1/campaigns",
            params={"limit": 100},
        )
        if discovery_response.status_code != 200:
            raise ForensicsCaptureError("campaign discovery was rejected")
        discovered = _latest_flagship_campaign(
            _mapping(discovery_response.json(), "campaign discovery")
        )
        campaign_id = str(discovered.get("campaign_id", ""))

        async with streamable_http_client(
            f"{FORENSICS_ORIGIN}/mcp",
            http_client=http,
        ) as (read, write):
            async with ClientSession(read, write) as session:
                initialized = await session.initialize()
                tools = await session.list_tools()
                if not tools.tools:
                    raise ForensicsCaptureError("the MCP tool contract is empty")
                if any(
                    tool.annotations is None
                    or tool.annotations.read_only_hint is not True
                    or tool.annotations.destructive_hint is not False
                    for tool in tools.tools
                ):
                    raise ForensicsCaptureError("the MCP tool contract is not read-only")

                persisted = _structured(
                    await session.call_tool(
                        "get_invalidation_campaign",
                        {"campaign_id": campaign_id},
                    ),
                    "get_invalidation_campaign",
                )
                campaign = _mapping(persisted.get("campaign"), "persisted campaign")
                change = _mapping(campaign.get("change"), "persisted change")
                processing = _mapping(campaign.get("processing"), "campaign processing")
                affected = _structured(
                    await session.call_tool("list_affected_decisions", dict(change)),
                    "list_affected_decisions",
                )
                assessments = _sequence(affected.get("assessments"), "impact assessments")
                if affected.get("scan_complete") is not True or not assessments:
                    raise ForensicsCaptureError("the MCP impact scan was incomplete")

                primary = _mapping(assessments[0], "primary assessment")
                receipt_id = str(primary.get("receipt_id", ""))
                verification = _structured(
                    await session.call_tool(
                        "verify_decision_receipt",
                        {"receipt_id": receipt_id},
                    ),
                    "verify_decision_receipt",
                )
                influence = _structured(
                    await session.call_tool(
                        "get_decision_influence",
                        {"receipt_id": receipt_id},
                    ),
                    "get_decision_influence",
                )
                findings = _structured(
                    await session.call_tool(
                        "list_decision_findings",
                        {"receipt_id": receipt_id},
                    ),
                    "list_decision_findings",
                )
                if verification.get("verification_state") != "VERIFIED_NOW":
                    raise ForensicsCaptureError("the affected receipt did not verify now")
                dependencies = _sequence(influence.get("dependencies"), "decision influence")
                if not any(
                    _mapping(item, "dependency").get("datahub_urn") == DATASET_URN
                    for item in dependencies
                ):
                    raise ForensicsCaptureError("the DataHub dependency was not returned")
                persisted_findings = _sequence(findings.get("findings"), "persisted findings")
                if not any(
                    _mapping(item, "finding").get("campaign_id") == campaign_id
                    for item in persisted_findings
                ):
                    raise ForensicsCaptureError("the persisted finding did not match the campaign")
                if (
                    processing.get("workflow_status") != "COMPLETED"
                    or processing.get("datahub_writeback_state") != "VERIFIED"
                ):
                    raise ForensicsCaptureError("campaign writeback was not verified")

                assessment_rows = [_mapping(item, "assessment") for item in assessments]
                return {
                    "protocol": initialized.protocol_version,
                    "tool_count": len(tools.tools),
                    "campaign_id": campaign_id,
                    "change_kind": change.get("kind"),
                    "affected_count": affected.get("review_required_total"),
                    "scan_complete": affected.get("scan_complete"),
                    "receipts": [str(item.get("receipt_id", "")) for item in assessment_rows],
                    "states": sorted({str(item.get("state", "")) for item in assessment_rows}),
                    "reasons": sorted(
                        {str(item.get("reason_code", "")) for item in assessment_rows}
                    ),
                    "primary_receipt": receipt_id,
                    "verification": verification.get("verification_state"),
                    "dependency_state": _mapping(dependencies[0], "dependency").get("state"),
                    "workflow": processing.get("workflow_status"),
                    "writeback": processing.get("datahub_writeback_state"),
                    "raw_content_returned": any(
                        "raw_content_returned" in value
                        and value.get("raw_content_returned") is not False
                        for value in (persisted, affected, verification, influence, findings)
                    ),
                }


def render(report: Mapping[str, object]) -> str:
    receipts = report["receipts"]
    states = report["states"]
    reasons = report["reasons"]
    if (
        not isinstance(receipts, list)
        or not all(isinstance(item, str) for item in receipts)
        or not isinstance(states, list)
        or not all(isinstance(item, str) for item in states)
        or not isinstance(reasons, list)
        or not all(isinstance(item, str) for item in reasons)
    ):
        raise ForensicsCaptureError("receipt evidence is invalid")
    lines: list[tuple[str, str]] = [
        ("GlassBox", "live MCP forensic investigation"),
        ("Question", QUESTION),
        ("MCP", f"{report['protocol']} · AUTHENTICATED · READ ONLY"),
        ("Tools", f"{report['tool_count']} discovered · 0 mutation tools"),
        ("Change", str(report["change_kind"])),
        ("Dataset", "postgres · commerce.orders · PROD"),
        ("Field", FIELD_PATH),
        (
            "Affected",
            f"{report['affected_count']} decisions · complete index scan",
        ),
    ]
    for index, receipt_id in enumerate(receipts, start=1):
        lines.append((f"Receipt {index}", str(receipt_id)))
    lines.extend(
        (
            ("State", ", ".join(states)),
            ("Why", ", ".join(reasons)),
            ("Evidence", f"{report['verification']} · dependency {report['dependency_state']}"),
            ("Campaign", str(report["campaign_id"])),
            ("Writeback", f"{report['workflow']} · DataHub {report['writeback']}"),
            ("Raw content", "NOT RETURNED"),
        )
    )
    return "\n".join(f"{label:<13} {value}" for label, value in lines)


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        print("This fixed filming helper accepts no arguments.", file=sys.stderr)
        return 2
    try:
        report = asyncio.run(investigate())
        if report["raw_content_returned"] is True:
            raise ForensicsCaptureError("an MCP response crossed the raw-content boundary")
    except Exception as exc:
        safe = exc if isinstance(exc, ForensicsCaptureError) else type(exc).__name__
        print(f"GlassBox MCP investigation failed: {safe}", file=sys.stderr)
        return 1
    print(render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
