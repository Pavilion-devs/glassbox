"""Synthetic, non-sensitive DBOM fixtures."""

from __future__ import annotations

import copy
import hashlib
from typing import Any


def sha256(value: str) -> dict[str, str]:
    return {"algorithm": "sha256", "value": hashlib.sha256(value.encode()).hexdigest()}


def receipt_payload() -> dict[str, Any]:
    """Return a new valid, unsealed read-only receipt payload."""

    dataset_urn = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
    return {
        "spec_version": "0.1.0",
        "run": {
            "run_id": "run-pricing-001",
            "status": "SUCCEEDED",
            "started_at": "2026-08-06T00:00:00Z",
            "ended_at": "2026-08-06T00:00:02Z",
            "trace_id": "0123456789abcdef0123456789abcdef",
            "parent_run_id": None,
            "environment": "DEV",
        },
        "agent": {
            "id": "glassbox.pricing-agent",
            "version": "0.1.0",
            "datahub_urn": "urn:li:aiAgent:glassbox.pricing-agent",
            "source_digest": sha256("pricing-agent-source-v0.1.0"),
        },
        "workflow": {"id": "pricing-recommendation", "version": "0.1.0"},
        "models": [
            {
                "id": "deterministic-demo-model",
                "version": "1",
                "datahub_urn": None,
                "source_digest": sha256("deterministic-demo-model-v1"),
            }
        ],
        "skills": [
            {
                "id": "pricing-analysis",
                "version": "0.1.0",
                "datahub_urn": "urn:li:agentSkill:glassbox.pricing-analysis",
                "source_digest": sha256("pricing-analysis-skill-v0.1.0"),
            }
        ],
        "tools": [
            {
                "id": "glassbox.orders.lookup",
                "version": "0.1.0",
                "datahub_urn": "urn:li:api:glassbox.orders.lookup",
                "source_digest": sha256("orders-lookup-tool-v0.1.0"),
                "schema_digest": sha256("orders-lookup-schema-v0.1.0"),
            }
        ],
        "evidence": [
            {
                "evidence_id": "evidence-orders-001",
                "entity_type": "dataset",
                "datahub_urn": dataset_urn,
                "schema_field_urn": None,
                "state": "OBSERVED",
                "role": "INPUT",
                "source_span_id": "0123456789abcdef",
                "representation_digest": sha256("synthetic-order-aggregate"),
                "observed_at": "2026-08-06T00:00:01Z",
                "redaction": {
                    "status": "DIGEST_ONLY",
                    "policy_id": "glassbox.default-deny-v1",
                    "reason": "Raw rows are not receipt material.",
                },
                "provenance": {
                    "capture_method": "OTEL_SPAN",
                    "rule_id": None,
                    "confidence": None,
                },
            }
        ],
        "queries": [
            {
                "query_id": "query-orders-001",
                "language": "SQL",
                "statement_digest": sha256("select synthetic aggregate"),
                "redacted": True,
            }
        ],
        "actions": [
            {
                "action_id": "action-read-orders-001",
                "tool_id": "glassbox.orders.lookup",
                "effect": "READ_ONLY",
                "status": "SUCCEEDED",
                "idempotency_key": "run-pricing-001:orders-lookup",
                "input_digest": sha256("synthetic-query-input"),
                "output_digest": sha256("synthetic-order-aggregate"),
                "approval_id": None,
            }
        ],
        "approvals": [],
        "evaluations": [
            {
                "evaluation_id": "evaluation-completeness-001",
                "method": "DETERMINISTIC",
                "version": "0.1.0",
                "result": "PASS",
                "score": 1.0,
            }
        ],
        "output": {
            "kind": "recommendation",
            "mime_type": "application/json",
            "digest": sha256("synthetic-pricing-recommendation"),
            "redacted": True,
            "redaction_reason": "Receipt stores an output digest by default.",
        },
        "replay": {
            "eligibility": "ELIGIBLE",
            "reason": "All recorded actions are read-only.",
            "prior_receipt_digest": None,
        },
        "extensions": {},
    }


def copied_payload() -> dict[str, Any]:
    return copy.deepcopy(receipt_payload())
