"""Adversarial tests for machine-auditable dual-MCP agent narration."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest

from glassbox_forensics import (
    NARRATION_BRIEF_CONTRACT_VERSION,
    NARRATION_EVALUATION_CONTRACT_VERSION,
    NARRATION_RESPONSE_CONTRACT_VERSION,
    NarrationContractError,
    build_narration_brief,
    evaluate_agent_narration,
)
from glassbox_forensics.narration_cli import main as narration_cli_main

_ROOT = Path(__file__).resolve().parents[2]
_LIVE_PROOF = _ROOT / "docs" / "compatibility" / "datahub-1.6.0-dual-mcp-forensics.live.json"
_SECRET = "hostile-agent-prose-must-not-cross-the-evaluation-boundary"


def _evidence() -> dict[str, Any]:
    value = json.loads(_LIVE_PROOF.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _brief() -> dict[str, Any]:
    return build_narration_brief(_evidence())


def _response(brief: dict[str, Any]) -> dict[str, Any]:
    facts = {item["id"]: item["value"] for item in brief["facts"]}
    citations = " ".join(f"[fact:{fact_id}]" for fact_id in brief["required_finding_citations"])
    return {
        "contract": NARRATION_RESPONSE_CONTRACT_VERSION,
        "finding": f"The verified receipt is stale after its observed field changed. {citations}",
        "claims": [
            {"fact_id": fact_id, "value": facts[fact_id]} for fact_id in brief["required_claim_ids"]
        ],
        "limitations": list(brief["required_limit_ids"]),
        "mutation_authority": "NONE",
        "raw_content_returned": False,
    }


def test_live_dual_mcp_evidence_builds_a_bounded_valid_narration_contract() -> None:
    brief = _brief()
    response = _response(brief)
    response["private_reasoning"] = _SECRET

    evaluation = evaluate_agent_narration(brief, response)

    assert brief["contract"] == NARRATION_BRIEF_CONTRACT_VERSION
    assert brief["raw_content_returned"] is False
    assert brief["free_prose_semantics"] == "MODEL_REVIEW_REQUIRED"
    assert evaluation["contract"] == NARRATION_EVALUATION_CONTRACT_VERSION
    assert evaluation["valid"] is True
    assert evaluation["reason_codes"] == []
    assert evaluation["checked_claims"] == evaluation["required_claims"] == 18
    assert evaluation["incident_projection_preserved"] is True
    assert evaluation["organizational_scope_preserved"] is True
    assert evaluation["mutation_authority_preserved"] is True
    assert evaluation["free_prose_semantics"] == "NOT_DETERMINISTICALLY_PROVEN"
    assert evaluation["raw_content_returned"] is False
    assert _SECRET not in repr(evaluation)


def test_brief_only_requires_limits_that_remain_unproven() -> None:
    evidence = _evidence()
    evidence["datahub_mcp"]["exact_incident_entity_projection"] = "AVAILABLE"
    evidence["scope"]["exact_incident_body_via_official_datahub_mcp"] = "AVAILABLE"
    evidence["scope"]["organizational_retention_completeness"] = "PROVEN"

    brief = build_narration_brief(evidence)

    assert brief["required_limit_ids"] == ["authority.mutation_tools"]


@pytest.mark.parametrize(
    ("mutate", "reason_code"),
    [
        (
            lambda response: response.__setitem__("contract", "agent-prose.v0"),
            "RESPONSE_CONTRACT_INVALID",
        ),
        (
            lambda response: response.__setitem__("raw_content_returned", True),
            "RAW_CONTENT_BOUNDARY_INVALID",
        ),
        (
            lambda response: response.__setitem__("mutation_authority", "QUARANTINE"),
            "MUTATION_AUTHORITY_INFLATED",
        ),
        (
            lambda response: response.__setitem__("finding", ""),
            "FINDING_SHAPE_INVALID",
        ),
        (
            lambda response: response.__setitem__("finding", "x" * 1_201),
            "FINDING_SHAPE_INVALID",
        ),
        (
            lambda response: response.__setitem__(
                "finding",
                response["finding"].replace("[fact:decision.datahub_writeback]", ""),
            ),
            "FINDING_CITATIONS_INCOMPLETE",
        ),
        (
            lambda response: response.__setitem__(
                "finding", response["finding"] + " [fact:incident.root_cause]"
            ),
            "FINDING_CITATION_UNSUPPORTED",
        ),
        (
            lambda response: response.__setitem__("claims", {}),
            "CLAIM_LEDGER_INVALID",
        ),
        (
            lambda response: response["claims"].append("not-a-claim"),
            "CLAIM_LEDGER_INVALID",
        ),
        (
            lambda response: response["claims"].append({"fact_id": 7, "value": "invented"}),
            "CLAIM_LEDGER_INVALID",
        ),
        (
            lambda response: response["claims"].append(response["claims"][0]),
            "CLAIM_LEDGER_INVALID",
        ),
        (
            lambda response: response["claims"].pop(),
            "CLAIM_SET_INCOMPLETE_OR_UNSUPPORTED",
        ),
        (
            lambda response: response["claims"][8].__setitem__("value", "AVAILABLE"),
            "CLAIM_VALUE_MISMATCH",
        ),
        (
            lambda response: response["limitations"].pop(),
            "LIMITATIONS_INCOMPLETE_OR_UNSUPPORTED",
        ),
        (
            lambda response: response.__setitem__("limitations", "none"),
            "LIMITATIONS_INCOMPLETE_OR_UNSUPPORTED",
        ),
        (
            lambda response: response.__setitem__("limitations", [7]),
            "LIMITATIONS_INCOMPLETE_OR_UNSUPPORTED",
        ),
    ],
)
def test_agent_response_fails_closed_on_claim_or_boundary_drift(
    mutate: Any,
    reason_code: str,
) -> None:
    brief = _brief()
    response = _response(brief)
    mutate(response)

    evaluation = evaluate_agent_narration(brief, response)

    assert evaluation["valid"] is False
    assert reason_code in evaluation["reason_codes"]
    assert evaluation["raw_content_returned"] is False


@pytest.mark.parametrize(
    ("path", "value", "match"),
    [
        (("contract",), "glassbox.dual-mcp.v0", "contract"),
        (("valid",), False, "invalid or not raw-free"),
        (("raw_content_returned",), True, "invalid or not raw-free"),
        (("cross_plane_binding",), None, "cross_plane_binding"),
        (("cross_plane_binding", "catalog_to_receipt"), "PARTIAL", "not exact"),
        (("datahub_mcp", "dataset_urn"), "urn:li:dataset:other", "does not match"),
        (("datahub_mcp", "catalog_entity_read"), "UNPROVEN", "proof is incomplete"),
        (("datahub_mcp", "exact_incident_entity_projection"), "PARTIAL", "unknown state"),
        (
            ("scope", "exact_incident_body_via_official_datahub_mcp"),
            "AVAILABLE",
            "differs",
        ),
        (("scope", "organizational_retention_completeness"), "GLOBAL", "unknown state"),
        (("glassbox_mcp", "finding_state"), "AT_RISK", "decision evidence is incomplete"),
        (("glassbox_mcp", "mutation_tools"), 1, "not read-only"),
        (("cross_plane_binding", "receipt_id"), "", "receipt_id"),
        (("datahub_mcp", "field_path"), None, "field_path"),
    ],
)
def test_narration_brief_refuses_unproven_or_malformed_source_evidence(
    path: tuple[object, ...],
    value: object,
    match: str,
) -> None:
    evidence = copy.deepcopy(_evidence())
    target: Any = evidence
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value

    with pytest.raises(NarrationContractError, match=match):
        build_narration_brief(evidence)


@pytest.mark.parametrize(
    ("mutate", "match"),
    [
        (lambda brief: brief.__setitem__("contract", "brief.v0"), "contract"),
        (lambda brief: brief.__setitem__("raw_content_returned", True), "not raw-free"),
        (lambda brief: brief.__setitem__("facts", {}), "facts are unavailable"),
        (lambda brief: brief["facts"].__setitem__(0, "bad"), "fact is malformed"),
        (
            lambda brief: brief["facts"][0].__setitem__("id", "unsupported.fact"),
            "identity is invalid",
        ),
        (lambda brief: brief["facts"].pop(), "incomplete or reordered"),
        (
            lambda brief: brief["facts"].__setitem__(1, copy.deepcopy(brief["facts"][0])),
            "identity is invalid",
        ),
    ],
)
def test_evaluator_rejects_a_tampered_narration_brief(mutate: Any, match: str) -> None:
    brief = copy.deepcopy(_brief())
    mutate(brief)

    with pytest.raises(NarrationContractError, match=match):
        evaluate_agent_narration(brief, _response(_brief()))


def test_evaluation_hashes_but_never_echoes_unserializable_agent_material() -> None:
    brief = _brief()
    response = _response(brief)
    response["opaque_agent_state"] = {_SECRET}

    evaluation = evaluate_agent_narration(brief, response)

    assert evaluation["valid"] is True
    assert len(evaluation["response_sha256"]) == 64
    assert _SECRET not in repr(evaluation)


def test_cli_builds_brief_and_accepts_a_valid_agent_response(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert narration_cli_main(["brief", str(_LIVE_PROOF), "--pretty"]) == 0
    brief = json.loads(capsys.readouterr().out)
    response_path = tmp_path / "response.json"
    response_path.write_text(json.dumps(_response(brief)), encoding="utf-8")

    assert narration_cli_main(["evaluate", str(_LIVE_PROOF), str(response_path)]) == 0
    evaluation = json.loads(capsys.readouterr().out)

    assert evaluation["valid"] is True
    assert evaluation["reason_codes"] == []


def test_cli_rejects_evidence_drift_and_malformed_agent_input_without_echoing_it(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    brief = _brief()
    response = _response(brief)
    response["claims"][8]["value"] = "AVAILABLE"
    response_path = tmp_path / "response.json"
    response_path.write_text(json.dumps(response), encoding="utf-8")

    assert narration_cli_main(["evaluate", str(_LIVE_PROOF), str(response_path)]) == 1
    assert "CLAIM_VALUE_MISMATCH" in json.loads(capsys.readouterr().out)["reason_codes"]

    response_path.write_text("{" + _SECRET, encoding="utf-8")
    assert narration_cli_main(["evaluate", str(_LIVE_PROOF), str(response_path)]) == 2
    invalid_output = capsys.readouterr().out
    assert json.loads(invalid_output)["reason_codes"] == ["INPUT_INVALID"]
    assert _SECRET not in invalid_output
