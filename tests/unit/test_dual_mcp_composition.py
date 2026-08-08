"""Cross-plane proof composition tests for official DataHub and GlassBox MCP."""

from __future__ import annotations

import copy
from typing import Any

import pytest

from glassbox_forensics import (
    DualMCPExpectation,
    DualMCPProofError,
    MCPToolContract,
    compose_dual_mcp_evidence,
)
from glassbox_forensics.dual_mcp import (
    DATAHUB_REQUIRED_READ_TOOLS,
    GLASSBOX_READ_TOOLS,
)

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},average_order_value)"
RECEIPT_ID = "gbx:receipt:sha256:" + "a" * 64
DOCUMENT = "urn:li:document:glassbox.receipt." + "a" * 64
CAMPAIGN = "gbx:invalidation:sha256:" + "b" * 64
INCIDENT = "urn:li:incident:glassbox.invalidation." + "b" * 64
SECRET = "never-return-hostile-catalog-content"


def _expectation() -> DualMCPExpectation:
    return DualMCPExpectation(
        dataset_urn=DATASET,
        field_path="average_order_value",
        native_type="DECIMAL(18,2)",
        receipt_id=RECEIPT_ID,
        document_urn=DOCUMENT,
        campaign_id=CAMPAIGN,
        incident_urn=INCIDENT,
    )


def _datahub_tools() -> list[MCPToolContract]:
    return [
        MCPToolContract(name, True, None, None, None)
        for name in sorted(DATAHUB_REQUIRED_READ_TOOLS | {"get_dataset_queries"})
    ]


def _glassbox_tools() -> list[MCPToolContract]:
    return [MCPToolContract(name, True, False, True, False) for name in sorted(GLASSBOX_READ_TOOLS)]


def _inputs() -> dict[str, Any]:
    return {
        "expectation": _expectation(),
        "datahub_tools": _datahub_tools(),
        "glassbox_tools": _glassbox_tools(),
        "datahub_entities": {
            "result": [
                {
                    "urn": DATASET,
                    "description": SECRET,
                    "schemaMetadata": {
                        "fields": [
                            {
                                "fieldPath": "average_order_value",
                                "nativeDataType": "DECIMAL(18,2)",
                                "description": SECRET,
                            }
                        ]
                    },
                    "health": [
                        {
                            "type": "INCIDENTS",
                            "status": "FAIL",
                            "message": SECRET,
                            "causes": ["ACTIVE_INCIDENTS"],
                        }
                    ],
                    "relatedDocuments": {"documents": [{"urn": DOCUMENT, "title": SECRET}]},
                },
                {"urn": INCIDENT, "error": SECRET},
            ]
        },
        "receipt_verification": {
            "receipt_id": RECEIPT_ID,
            "verification_state": "VERIFIED_NOW",
            "valid": True,
        },
        "influence": {
            "receipt_id": RECEIPT_ID,
            "document_urn": DOCUMENT,
            "dependencies": [
                {
                    "datahub_urn": DATASET,
                    "schema_field_urn": FIELD,
                    "state": "OBSERVED",
                    "private_value": SECRET,
                }
            ],
            "raw_content_returned": False,
        },
        "campaign": {
            "availability": "AVAILABLE",
            "campaign": {
                "campaign_id": CAMPAIGN,
                "incident_urn": INCIDENT,
                "change": {"entity_urn": DATASET},
                "processing": {
                    "workflow_status": "COMPLETED",
                    "datahub_writeback_state": "VERIFIED",
                },
            },
            "raw_content_returned": False,
        },
        "findings": {
            "receipt_id": RECEIPT_ID,
            "availability": "AVAILABLE",
            "scan_complete": True,
            "findings": [
                {
                    "campaign_id": CAMPAIGN,
                    "assessment": {
                        "receipt_id": RECEIPT_ID,
                        "state": "STALE",
                        "quarantine_required": True,
                    },
                }
            ],
            "raw_content_returned": False,
        },
    }


def test_composition_cross_binds_both_read_only_planes_without_raw_content() -> None:
    report = compose_dual_mcp_evidence(**_inputs())

    assert report["valid"] is True
    assert report["datahub_mcp"]["catalog_entity_read"] == "PROVEN"
    assert report["datahub_mcp"]["exact_incident_entity_projection"] == "UNAVAILABLE"
    assert report["glassbox_mcp"]["campaign_workflow"] == "COMPLETED"
    assert report["glassbox_mcp"]["finding_state"] == "STALE"
    assert report["cross_plane_binding"]["campaign_to_incident"] == "EXACT"
    assert report["raw_content_returned"] is False
    assert SECRET not in repr(report)


@pytest.mark.parametrize(
    "mutate,match",
    [
        (
            lambda values: values["datahub_tools"].append(
                MCPToolContract("update_description", True, None, None, None)
            ),
            "mutation tools",
        ),
        (
            lambda values: values["datahub_tools"].append(
                MCPToolContract("mystery_tool", None, None, None, None)
            ),
            "without read-only authority",
        ),
        (
            lambda values: values["glassbox_tools"].__setitem__(
                0,
                MCPToolContract(
                    values["glassbox_tools"][0].name,
                    True,
                    False,
                    False,
                    False,
                ),
            ),
            "annotations",
        ),
    ],
)
def test_composition_refuses_ambiguous_or_mutating_tool_authority(
    mutate: Any,
    match: str,
) -> None:
    values = _inputs()
    mutate(values)

    with pytest.raises(DualMCPProofError, match=match):
        compose_dual_mcp_evidence(**values)


def test_composition_requires_every_official_catalog_read_tool() -> None:
    values = _inputs()
    values["datahub_tools"] = [tool for tool in values["datahub_tools"] if tool.name != "search"]

    with pytest.raises(DualMCPProofError, match="missing required read tools"):
        compose_dual_mcp_evidence(**values)


def test_composition_requires_exact_glassbox_tool_surface() -> None:
    values = _inputs()
    values["glassbox_tools"].pop()

    with pytest.raises(DualMCPProofError, match="tool surface"):
        compose_dual_mcp_evidence(**values)


@pytest.mark.parametrize("server", ["datahub", "glassbox"])
def test_composition_rejects_duplicate_tool_names(server: str) -> None:
    values = _inputs()
    key = f"{server}_tools"
    values[key].append(values[key][0])

    with pytest.raises(DualMCPProofError, match="duplicate tool names"):
        compose_dual_mcp_evidence(**values)


@pytest.mark.parametrize(
    "path,value,match",
    [
        (
            ("datahub_entities", "result", 0, "schemaMetadata", "fields", 0, "nativeDataType"),
            "VARCHAR",
            "native type",
        ),
        (("datahub_entities", "result"), {}, "result is not an array"),
        (("datahub_entities", "result", 0, "error"), SECRET, "expected dataset"),
        (("datahub_entities", "result", 0, "schemaMetadata"), None, "schemaMetadata"),
        (
            ("datahub_entities", "result", 0, "schemaMetadata", "fields"),
            {},
            "schema fields",
        ),
        (
            ("datahub_entities", "result", 0, "schemaMetadata", "fields"),
            [],
            "exactly one expected field",
        ),
        (
            ("datahub_entities", "result", 0, "health"),
            [],
            "active-incident health",
        ),
        (("datahub_entities", "result", 0, "health"), {}, "health is unavailable"),
        (
            ("datahub_entities", "result", 0, "health", 0, "causes"),
            ["ACTIVE_INCIDENTS", 7],
            "active-incident health",
        ),
        (
            ("datahub_entities", "result", 0, "relatedDocuments", "documents"),
            [],
            "receipt Document",
        ),
        (("datahub_entities", "result", 1, "urn"), "urn:li:incident:other", "expected incident"),
        (("receipt_verification", "valid"), False, "freshly verify"),
        (("influence", "raw_content_returned"), True, "bind the receipt Document"),
        (("influence", "dependencies"), {}, "exact observed field influence"),
        (("campaign", "availability"), "NOT_CONFIGURED", "campaign is unavailable"),
        (("campaign", "campaign", "campaign_id"), "gbx:other", "expected incident"),
        (("campaign", "campaign", "change", "entity_urn"), "urn:li:other", "different"),
        (
            ("campaign", "campaign", "processing", "datahub_writeback_state"),
            "PENDING",
            "not completed and verified",
        ),
        (("findings", "raw_content_returned"), True, "incomplete or not raw-free"),
        (("findings", "findings"), {}, "findings are not an array"),
        (("findings", "findings"), [], "exactly one expected finding"),
        (
            ("findings", "findings", 0, "assessment", "state"),
            "AT_RISK",
            "stale quarantine",
        ),
    ],
)
def test_composition_fails_closed_on_cross_plane_drift(
    path: tuple[object, ...],
    value: object,
    match: str,
) -> None:
    values = copy.deepcopy(_inputs())
    target: Any = values
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(DualMCPProofError, match=match):
        compose_dual_mcp_evidence(**values)


def test_composition_accepts_future_exact_incident_projection_without_echoing_it() -> None:
    values = _inputs()
    values["datahub_entities"]["result"][1] = {
        "urn": INCIDENT,
        "description": SECRET,
    }

    report = compose_dual_mcp_evidence(**values)

    assert report["datahub_mcp"]["exact_incident_entity_projection"] == "AVAILABLE"
    assert SECRET not in repr(report)
