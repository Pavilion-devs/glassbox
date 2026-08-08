"""Deterministic composition of DataHub catalog and GlassBox decision evidence."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

DUAL_MCP_CONTRACT_VERSION = "glassbox.dual-mcp-forensics.v1"

DATAHUB_REQUIRED_READ_TOOLS = frozenset(
    {
        "get_entities",
        "get_lineage",
        "get_lineage_paths_between",
        "list_schema_fields",
        "search",
    }
)
DATAHUB_KNOWN_MUTATION_TOOLS = frozenset(
    {
        "accept_or_reject_proposals",
        "add_owners",
        "add_related_terms",
        "add_structured_properties",
        "add_tags",
        "add_terms",
        "create_glossary_term",
        "create_glossary_term_version",
        "propose_create_glossary_term",
        "propose_lifecycle_stage",
        "remove_domains",
        "remove_owners",
        "remove_structured_properties",
        "remove_tags",
        "remove_terms",
        "save_document",
        "set_domains",
        "set_lifecycle_stage",
        "update_description",
    }
)
GLASSBOX_READ_TOOLS = frozenset(
    {
        "classify_decision_impact",
        "get_decision_influence",
        "get_invalidation_campaign",
        "list_affected_decisions",
        "list_decision_findings",
        "verify_decision_receipt",
    }
)


class DualMCPProofError(ValueError):
    """Raised when the two evidence planes cannot be bound without guessing."""


@dataclass(frozen=True)
class MCPToolContract:
    """Safe projection of one discovered MCP tool and its authority hints."""

    name: str
    read_only: bool | None
    destructive: bool | None
    idempotent: bool | None
    open_world: bool | None


@dataclass(frozen=True)
class DualMCPExpectation:
    """Exact identities and field state the two servers must independently bind."""

    dataset_urn: str
    field_path: str
    native_type: str
    receipt_id: str
    document_urn: str
    campaign_id: str
    incident_urn: str


def compose_dual_mcp_evidence(
    *,
    expectation: DualMCPExpectation,
    datahub_tools: Sequence[MCPToolContract],
    glassbox_tools: Sequence[MCPToolContract],
    datahub_entities: Mapping[str, Any],
    receipt_verification: Mapping[str, Any],
    influence: Mapping[str, Any],
    campaign: Mapping[str, Any],
    findings: Mapping[str, Any],
) -> dict[str, object]:
    """Cross-bind both MCP planes and return only a bounded proof projection."""

    datahub_tool_names = _verify_datahub_tools(datahub_tools)
    glassbox_tool_names = _verify_glassbox_tools(glassbox_tools)
    catalog = _catalog_evidence(datahub_entities, expectation)
    decision = _decision_evidence(
        receipt_verification=receipt_verification,
        influence=influence,
        campaign=campaign,
        findings=findings,
        expectation=expectation,
    )
    return {
        "contract": DUAL_MCP_CONTRACT_VERSION,
        "valid": True,
        "datahub_mcp": {
            "tool_count": len(datahub_tool_names),
            "required_read_tools_present": sorted(DATAHUB_REQUIRED_READ_TOOLS),
            "non_read_only_tools": [],
            "known_mutation_tools_exposed": [],
            **catalog,
        },
        "glassbox_mcp": {
            "tool_count": len(glassbox_tool_names),
            "read_tools": sorted(GLASSBOX_READ_TOOLS),
            "mutation_tools": 0,
            **decision,
        },
        "cross_plane_binding": {
            "dataset_urn": expectation.dataset_urn,
            "receipt_id": expectation.receipt_id,
            "document_urn": expectation.document_urn,
            "campaign_id": expectation.campaign_id,
            "incident_urn": expectation.incident_urn,
            "catalog_to_receipt": "EXACT",
            "receipt_to_campaign": "EXACT",
            "campaign_to_incident": "EXACT",
        },
        "raw_content_returned": False,
    }


def _verify_datahub_tools(tools: Sequence[MCPToolContract]) -> frozenset[str]:
    names = _unique_tool_names(tools, server="DataHub")
    missing = DATAHUB_REQUIRED_READ_TOOLS - names
    if missing:
        raise DualMCPProofError(
            "DataHub MCP is missing required read tools: " + ", ".join(sorted(missing))
        )
    exposed_mutations = names & DATAHUB_KNOWN_MUTATION_TOOLS
    if exposed_mutations:
        raise DualMCPProofError(
            "DataHub MCP exposed mutation tools: " + ", ".join(sorted(exposed_mutations))
        )
    non_read_only = sorted(tool.name for tool in tools if tool.read_only is not True)
    if non_read_only:
        raise DualMCPProofError(
            "DataHub MCP exposed tools without read-only authority: " + ", ".join(non_read_only)
        )
    return names


def _verify_glassbox_tools(tools: Sequence[MCPToolContract]) -> frozenset[str]:
    names = _unique_tool_names(tools, server="GlassBox")
    if names != GLASSBOX_READ_TOOLS:
        raise DualMCPProofError("GlassBox MCP tool surface does not match the read-only contract")
    unsafe = [
        tool.name
        for tool in tools
        if not (
            tool.read_only is True
            and tool.destructive is False
            and tool.idempotent is True
            and tool.open_world is False
        )
    ]
    if unsafe:
        raise DualMCPProofError(
            "GlassBox MCP tool annotations are not closed-world read-only: "
            + ", ".join(sorted(unsafe))
        )
    return names


def _unique_tool_names(
    tools: Sequence[MCPToolContract],
    *,
    server: str,
) -> frozenset[str]:
    names = [tool.name for tool in tools]
    if any(not name for name in names) or len(names) != len(set(names)):
        raise DualMCPProofError(f"{server} MCP returned empty or duplicate tool names")
    return frozenset(names)


def _catalog_evidence(
    response: Mapping[str, Any],
    expectation: DualMCPExpectation,
) -> dict[str, object]:
    raw_result = response.get("result")
    if not isinstance(raw_result, list):
        raise DualMCPProofError("DataHub get_entities result is not an array")
    entities = [item for item in raw_result if isinstance(item, Mapping)]
    dataset = _one_urn(entities, expectation.dataset_urn, label="dataset")
    if "error" in dataset:
        raise DualMCPProofError("DataHub MCP could not project the expected dataset")

    schema = _mapping(dataset, "schemaMetadata", label="DataHub dataset")
    fields = schema.get("fields")
    if not isinstance(fields, list):
        raise DualMCPProofError("DataHub dataset schema fields are unavailable")
    matching_fields = [
        item
        for item in fields
        if isinstance(item, Mapping) and item.get("fieldPath") == expectation.field_path
    ]
    if len(matching_fields) != 1:
        raise DualMCPProofError("DataHub dataset did not contain exactly one expected field")
    native_type = matching_fields[0].get("nativeDataType")
    if native_type != expectation.native_type:
        raise DualMCPProofError("DataHub field native type did not match the Action change")

    health = dataset.get("health")
    if not isinstance(health, list):
        raise DualMCPProofError("DataHub dataset health is unavailable")
    incident_health = [
        item
        for item in health
        if isinstance(item, Mapping)
        and item.get("type") == "INCIDENTS"
        and item.get("status") == "FAIL"
        and "ACTIVE_INCIDENTS" in _string_list(item.get("causes"))
    ]
    if not incident_health:
        raise DualMCPProofError("DataHub MCP did not observe failed active-incident health")

    related = _mapping(dataset, "relatedDocuments", label="DataHub dataset")
    documents = related.get("documents")
    if not isinstance(documents, list) or not any(
        isinstance(item, Mapping) and item.get("urn") == expectation.document_urn
        for item in documents
    ):
        raise DualMCPProofError("DataHub MCP did not relate the receipt Document to the dataset")

    incident = _one_urn(entities, expectation.incident_urn, label="incident")
    incident_projection = "UNAVAILABLE" if "error" in incident else "AVAILABLE"
    return {
        "catalog_entity_read": "PROVEN",
        "dataset_urn": expectation.dataset_urn,
        "field_path": expectation.field_path,
        "native_type": expectation.native_type,
        "incident_health": "FAIL",
        "active_incident_signal": True,
        "receipt_document_related": True,
        "exact_incident_entity_projection": incident_projection,
    }


def _decision_evidence(
    *,
    receipt_verification: Mapping[str, Any],
    influence: Mapping[str, Any],
    campaign: Mapping[str, Any],
    findings: Mapping[str, Any],
    expectation: DualMCPExpectation,
) -> dict[str, object]:
    if not (
        receipt_verification.get("receipt_id") == expectation.receipt_id
        and receipt_verification.get("verification_state") == "VERIFIED_NOW"
        and receipt_verification.get("valid") is True
    ):
        raise DualMCPProofError("GlassBox MCP did not freshly verify the expected receipt")
    if not (
        influence.get("receipt_id") == expectation.receipt_id
        and influence.get("document_urn") == expectation.document_urn
        and influence.get("raw_content_returned") is False
    ):
        raise DualMCPProofError("GlassBox influence projection did not bind the receipt Document")
    dependencies = influence.get("dependencies")
    if not isinstance(dependencies, list) or not any(
        isinstance(item, Mapping)
        and item.get("datahub_urn") == expectation.dataset_urn
        and item.get("schema_field_urn")
        == f"urn:li:schemaField:({expectation.dataset_urn},{expectation.field_path})"
        and item.get("state") == "OBSERVED"
        for item in dependencies
    ):
        raise DualMCPProofError("GlassBox MCP did not return the exact observed field influence")

    if not (
        campaign.get("availability") == "AVAILABLE"
        and campaign.get("raw_content_returned") is False
    ):
        raise DualMCPProofError("GlassBox MCP campaign is unavailable or not raw-free")
    persisted = _mapping(campaign, "campaign", label="GlassBox campaign")
    if not (
        persisted.get("campaign_id") == expectation.campaign_id
        and persisted.get("incident_urn") == expectation.incident_urn
    ):
        raise DualMCPProofError("GlassBox campaign did not bind the expected incident")
    change = _mapping(persisted, "change", label="GlassBox campaign")
    if change.get("entity_urn") != expectation.dataset_urn:
        raise DualMCPProofError("GlassBox campaign changed a different DataHub entity")
    processing = _mapping(persisted, "processing", label="GlassBox campaign")
    if not (
        processing.get("workflow_status") == "COMPLETED"
        and processing.get("datahub_writeback_state") == "VERIFIED"
    ):
        raise DualMCPProofError("GlassBox Action campaign is not completed and verified")

    if not (
        findings.get("receipt_id") == expectation.receipt_id
        and findings.get("availability") == "AVAILABLE"
        and findings.get("scan_complete") is True
        and findings.get("raw_content_returned") is False
    ):
        raise DualMCPProofError("GlassBox MCP findings are incomplete or not raw-free")
    raw_findings = findings.get("findings")
    if not isinstance(raw_findings, list):
        raise DualMCPProofError("GlassBox MCP findings are not an array")
    matching = [
        item
        for item in raw_findings
        if isinstance(item, Mapping) and item.get("campaign_id") == expectation.campaign_id
    ]
    if len(matching) != 1:
        raise DualMCPProofError("GlassBox MCP did not return exactly one expected finding")
    assessment = _mapping(matching[0], "assessment", label="GlassBox finding")
    if not (
        assessment.get("receipt_id") == expectation.receipt_id
        and assessment.get("state") == "STALE"
        and assessment.get("quarantine_required") is True
    ):
        raise DualMCPProofError("GlassBox MCP finding did not prove stale quarantine state")
    return {
        "receipt_verification": "VERIFIED_NOW",
        "observed_field_influence": True,
        "campaign_workflow": "COMPLETED",
        "datahub_writeback": "VERIFIED",
        "finding_state": "STALE",
        "quarantine_required": True,
        "scan_complete": True,
    }


def _one_urn(
    values: Sequence[Mapping[str, Any]],
    urn: str,
    *,
    label: str,
) -> Mapping[str, Any]:
    matches = [item for item in values if item.get("urn") == urn]
    if len(matches) != 1:
        raise DualMCPProofError(f"DataHub MCP did not return exactly one expected {label}")
    return matches[0]


def _mapping(value: Mapping[str, Any], key: str, *, label: str) -> Mapping[str, Any]:
    child = value.get(key)
    if not isinstance(child, Mapping):
        raise DualMCPProofError(f"{label} field {key!r} is unavailable")
    return child


def _string_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return ()
    return tuple(value)


__all__ = [
    "DATAHUB_KNOWN_MUTATION_TOOLS",
    "DATAHUB_REQUIRED_READ_TOOLS",
    "DUAL_MCP_CONTRACT_VERSION",
    "GLASSBOX_READ_TOOLS",
    "DualMCPExpectation",
    "DualMCPProofError",
    "MCPToolContract",
    "compose_dual_mcp_evidence",
]
