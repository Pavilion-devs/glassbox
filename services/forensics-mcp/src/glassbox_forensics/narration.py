"""Machine-auditable natural-language narration over dual-MCP evidence."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Any

from glassbox_forensics.dual_mcp import DUAL_MCP_CONTRACT_VERSION

NARRATION_BRIEF_CONTRACT_VERSION = "glassbox.agent-narration-brief.v1"
NARRATION_RESPONSE_CONTRACT_VERSION = "glassbox.agent-narration.v1"
NARRATION_EVALUATION_CONTRACT_VERSION = "glassbox.agent-narration-evaluation.v1"

_FACT_ORDER = (
    "identity.dataset",
    "identity.receipt",
    "identity.document",
    "identity.campaign",
    "identity.incident",
    "catalog.field.path",
    "catalog.field.native_type",
    "catalog.incident.health",
    "catalog.incident.entity_projection",
    "decision.receipt.verification",
    "decision.field.influence",
    "decision.finding.state",
    "decision.quarantine.required",
    "decision.campaign.workflow",
    "decision.datahub_writeback",
    "decision.scan.complete",
    "scope.organizational_retention",
    "authority.mutation_tools",
)
_FINDING_FACTS = (
    "identity.receipt",
    "catalog.field.path",
    "decision.receipt.verification",
    "decision.field.influence",
    "decision.finding.state",
    "decision.campaign.workflow",
    "decision.datahub_writeback",
)
_CITATION = re.compile(r"\[fact:([a-z0-9_.-]+)\]")


class NarrationContractError(ValueError):
    """Raised when trusted dual-MCP evidence cannot form a narration brief."""


def build_narration_brief(evidence: Mapping[str, Any]) -> dict[str, object]:
    """Validate a live dual-MCP report and project a bounded agent fact set."""

    if evidence.get("contract") != DUAL_MCP_CONTRACT_VERSION:
        raise NarrationContractError("dual-MCP evidence contract is unsupported")
    if evidence.get("valid") is not True or evidence.get("raw_content_returned") is not False:
        raise NarrationContractError("dual-MCP evidence is invalid or not raw-free")

    binding = _mapping(evidence, "cross_plane_binding", label="dual-MCP evidence")
    datahub = _mapping(evidence, "datahub_mcp", label="dual-MCP evidence")
    glassbox = _mapping(evidence, "glassbox_mcp", label="dual-MCP evidence")
    scope = _mapping(evidence, "scope", label="dual-MCP evidence")

    for key in ("catalog_to_receipt", "receipt_to_campaign", "campaign_to_incident"):
        if binding.get(key) != "EXACT":
            raise NarrationContractError("dual-MCP cross-plane identity is not exact")

    dataset_urn = _required_string(binding, "dataset_urn", label="cross-plane binding")
    if datahub.get("dataset_urn") != dataset_urn:
        raise NarrationContractError("DataHub dataset does not match the cross-plane binding")
    if not (
        datahub.get("catalog_entity_read") == "PROVEN"
        and datahub.get("incident_health") == "FAIL"
        and datahub.get("active_incident_signal") is True
    ):
        raise NarrationContractError("DataHub catalog or incident-health proof is incomplete")

    incident_projection = datahub.get("exact_incident_entity_projection")
    if incident_projection not in {"AVAILABLE", "UNAVAILABLE"}:
        raise NarrationContractError("exact Incident projection has an unknown state")
    if scope.get("exact_incident_body_via_official_datahub_mcp") != incident_projection:
        raise NarrationContractError("Incident projection state differs across evidence sections")

    organizational_scope = scope.get("organizational_retention_completeness")
    if organizational_scope not in {"PROVEN", "CONFIGURATION_DEPENDENT", "NOT_PROVEN"}:
        raise NarrationContractError("organizational retention completeness has an unknown state")
    if not (
        glassbox.get("receipt_verification") == "VERIFIED_NOW"
        and glassbox.get("observed_field_influence") is True
        and glassbox.get("finding_state") == "STALE"
        and glassbox.get("quarantine_required") is True
        and glassbox.get("campaign_workflow") == "COMPLETED"
        and glassbox.get("datahub_writeback") == "VERIFIED"
        and glassbox.get("scan_complete") is True
    ):
        raise NarrationContractError("GlassBox decision evidence is incomplete")
    if not (
        glassbox.get("mutation_tools") == 0
        and datahub.get("known_mutation_tools_exposed") == []
        and datahub.get("non_read_only_tools") == []
    ):
        raise NarrationContractError("the measured MCP surface is not read-only")

    fact_values: dict[str, object] = {
        "identity.dataset": dataset_urn,
        "identity.receipt": _required_string(binding, "receipt_id", label="cross-plane binding"),
        "identity.document": _required_string(binding, "document_urn", label="cross-plane binding"),
        "identity.campaign": _required_string(binding, "campaign_id", label="cross-plane binding"),
        "identity.incident": _required_string(binding, "incident_urn", label="cross-plane binding"),
        "catalog.field.path": _required_string(datahub, "field_path", label="DataHub evidence"),
        "catalog.field.native_type": _required_string(
            datahub, "native_type", label="DataHub evidence"
        ),
        "catalog.incident.health": "FAIL",
        "catalog.incident.entity_projection": incident_projection,
        "decision.receipt.verification": "VERIFIED_NOW",
        "decision.field.influence": "OBSERVED",
        "decision.finding.state": "STALE",
        "decision.quarantine.required": True,
        "decision.campaign.workflow": "COMPLETED",
        "decision.datahub_writeback": "VERIFIED",
        "decision.scan.complete": True,
        "scope.organizational_retention": organizational_scope,
        "authority.mutation_tools": "NONE",
    }
    facts = [
        {"id": fact_id, "value": fact_values[fact_id], "source": _fact_source(fact_id)}
        for fact_id in _FACT_ORDER
    ]
    required_limits = []
    if incident_projection != "AVAILABLE":
        required_limits.append("catalog.incident.entity_projection")
    if organizational_scope != "PROVEN":
        required_limits.append("scope.organizational_retention")
    required_limits.append("authority.mutation_tools")
    return {
        "contract": NARRATION_BRIEF_CONTRACT_VERSION,
        "facts": facts,
        "required_claim_ids": list(_FACT_ORDER),
        "required_finding_citations": list(_FINDING_FACTS),
        "required_limit_ids": required_limits,
        "free_prose_semantics": "MODEL_REVIEW_REQUIRED",
        "raw_content_returned": False,
    }


def evaluate_agent_narration(
    brief: Mapping[str, Any],
    response: Mapping[str, Any],
) -> dict[str, object]:
    """Deterministically validate a structured agent narration without echoing prose."""

    expected = _brief_fact_values(brief)
    required_claims = _string_sequence(brief.get("required_claim_ids"))
    required_finding = _string_sequence(brief.get("required_finding_citations"))
    required_limits = _string_sequence(brief.get("required_limit_ids"))
    reason_codes: set[str] = set()

    if response.get("contract") != NARRATION_RESPONSE_CONTRACT_VERSION:
        reason_codes.add("RESPONSE_CONTRACT_INVALID")
    if response.get("raw_content_returned") is not False:
        reason_codes.add("RAW_CONTENT_BOUNDARY_INVALID")
    if response.get("mutation_authority") != "NONE":
        reason_codes.add("MUTATION_AUTHORITY_INFLATED")

    finding = response.get("finding")
    citations: set[str] = set()
    if not isinstance(finding, str) or not finding.strip() or len(finding) > 1_200:
        reason_codes.add("FINDING_SHAPE_INVALID")
    else:
        citations = set(_CITATION.findall(finding))
        if not set(required_finding).issubset(citations):
            reason_codes.add("FINDING_CITATIONS_INCOMPLETE")
        if not citations.issubset(expected):
            reason_codes.add("FINDING_CITATION_UNSUPPORTED")

    claims = response.get("claims")
    observed_claims: dict[str, object] = {}
    if not isinstance(claims, list):
        reason_codes.add("CLAIM_LEDGER_INVALID")
    else:
        for claim in claims:
            if not isinstance(claim, Mapping):
                reason_codes.add("CLAIM_LEDGER_INVALID")
                continue
            fact_id = claim.get("fact_id")
            if not isinstance(fact_id, str) or not fact_id or fact_id in observed_claims:
                reason_codes.add("CLAIM_LEDGER_INVALID")
                continue
            observed_claims[fact_id] = claim.get("value")
        if set(observed_claims) != set(required_claims):
            reason_codes.add("CLAIM_SET_INCOMPLETE_OR_UNSUPPORTED")
        if any(
            fact_id not in expected or value != expected.get(fact_id)
            for fact_id, value in observed_claims.items()
        ):
            reason_codes.add("CLAIM_VALUE_MISMATCH")

    limits = _string_sequence(response.get("limitations"))
    if set(limits) != set(required_limits) or len(limits) != len(set(limits)):
        reason_codes.add("LIMITATIONS_INCOMPLETE_OR_UNSUPPORTED")

    incident_preserved = observed_claims.get("catalog.incident.entity_projection") == expected.get(
        "catalog.incident.entity_projection"
    )
    scope_preserved = observed_claims.get("scope.organizational_retention") == expected.get(
        "scope.organizational_retention"
    )
    authority_preserved = (
        observed_claims.get("authority.mutation_tools") == "NONE"
        and response.get("mutation_authority") == "NONE"
    )
    return {
        "contract": NARRATION_EVALUATION_CONTRACT_VERSION,
        "valid": not reason_codes,
        "reason_codes": sorted(reason_codes),
        "checked_claims": len(observed_claims),
        "required_claims": len(required_claims),
        "finding_citations_complete": "FINDING_CITATIONS_INCOMPLETE" not in reason_codes,
        "limitations_complete": "LIMITATIONS_INCOMPLETE_OR_UNSUPPORTED" not in reason_codes,
        "incident_projection_preserved": incident_preserved,
        "organizational_scope_preserved": scope_preserved,
        "mutation_authority_preserved": authority_preserved,
        "response_sha256": _response_digest(response),
        "free_prose_semantics": "NOT_DETERMINISTICALLY_PROVEN",
        "raw_content_returned": False,
    }


def _brief_fact_values(brief: Mapping[str, Any]) -> dict[str, object]:
    if brief.get("contract") != NARRATION_BRIEF_CONTRACT_VERSION:
        raise NarrationContractError("narration brief contract is unsupported")
    if brief.get("raw_content_returned") is not False:
        raise NarrationContractError("narration brief is not raw-free")
    facts = brief.get("facts")
    if not isinstance(facts, list):
        raise NarrationContractError("narration brief facts are unavailable")
    projected: dict[str, object] = {}
    for fact in facts:
        if not isinstance(fact, Mapping):
            raise NarrationContractError("narration brief fact is malformed")
        fact_id = fact.get("id")
        if not isinstance(fact_id, str) or fact_id not in _FACT_ORDER or fact_id in projected:
            raise NarrationContractError("narration brief fact identity is invalid")
        projected[fact_id] = fact.get("value")
    if tuple(projected) != _FACT_ORDER:
        raise NarrationContractError("narration brief fact set is incomplete or reordered")
    return projected


def _mapping(value: Mapping[str, Any], key: str, *, label: str) -> Mapping[str, Any]:
    child = value.get(key)
    if not isinstance(child, Mapping):
        raise NarrationContractError(f"{label} field {key!r} is unavailable")
    return child


def _required_string(value: Mapping[str, Any], key: str, *, label: str) -> str:
    child = value.get(key)
    if not isinstance(child, str) or not child:
        raise NarrationContractError(f"{label} field {key!r} is unavailable")
    return child


def _string_sequence(value: object) -> tuple[str, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return ()
    if not all(isinstance(item, str) for item in value):
        return ()
    return tuple(value)


def _fact_source(fact_id: str) -> str:
    if fact_id.startswith("identity."):
        return "CROSS_PLANE_BINDING"
    if fact_id.startswith("catalog."):
        return "DATAHUB_MCP"
    if fact_id.startswith("decision."):
        return "GLASSBOX_MCP"
    if fact_id.startswith("scope."):
        return "LIVE_PROOF_SCOPE"
    return "MCP_TOOL_AUTHORITY"


def _response_digest(response: Mapping[str, Any]) -> str:
    try:
        canonical = json.dumps(
            response,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError):
        canonical = b"UNSERIALIZABLE_RESPONSE"
    return hashlib.sha256(canonical).hexdigest()


__all__ = [
    "NARRATION_BRIEF_CONTRACT_VERSION",
    "NARRATION_EVALUATION_CONTRACT_VERSION",
    "NARRATION_RESPONSE_CONTRACT_VERSION",
    "NarrationContractError",
    "build_narration_brief",
    "evaluate_agent_narration",
]
