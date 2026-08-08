"""Live proof: publish both replay receipts and directly verify supersession in DataHub."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections.abc import Mapping, Sequence
from typing import Any

from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from examples.replay_read_only import build_replay_artifacts

from glassbox_datahub import (
    DataHubReceiptBackend,
    DataHubSupersessionBackend,
    ReceiptEmitter,
    SupersessionEmitter,
)
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_dbom.canonical import canonicalize
from glassbox_policy import SemanticPolicyRegistry, pricing_recommendation_policy_v1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-replay-supersession")
    parser.add_argument("--server", default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    parser.add_argument(
        "--pricing-semantic-policy",
        action="store_true",
        help="Use the trusted pricing v1 rule pack to prove non-exact equivalence.",
    )
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    return parser


def _entity_digest(graph: DataHubGraph, urn: str) -> str:
    entity = graph.get_entity_raw(urn)
    if not isinstance(entity, Mapping) or not entity.get("aspects"):
        raise RuntimeError(f"DataHub direct read returned no aspects for {urn}")
    return hashlib.sha256(canonicalize(entity)).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    semantic_policy = pricing_recommendation_policy_v1()
    artifacts = (
        build_replay_artifacts(
            source_output_override={
                "customer_id": "semantic-private-customer",
                "recommended_price": 100.0,
                "currency": "USD",
            },
            replay_output_override={
                "customer_id": "semantic-private-customer",
                "recommended_price": 100.4,
                "currency": "USD",
            },
            output_kind=semantic_policy.output_kind,
            semantic_policy_id=semantic_policy.policy_id,
            semantic_registry=SemanticPolicyRegistry.trust((semantic_policy,)),
        )
        if args.pricing_semantic_policy
        else build_replay_artifacts()
    )
    if not artifacts.valid:
        raise RuntimeError("offline replay artifacts did not verify before DataHub writes")

    receipt_backend = DataHubReceiptBackend(server=server, token=args.token)
    receipt_backend.test_connection()
    source_emission = ReceiptEmitter(receipt_backend).emit_verified(artifacts.source_receipt)
    replay_emission = ReceiptEmitter(receipt_backend).emit_verified(artifacts.replay_receipt)
    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=args.token))
    before = {
        source_emission.document_urn: _entity_digest(graph, source_emission.document_urn),
        replay_emission.document_urn: _entity_digest(graph, replay_emission.document_urn),
    }

    supersession_backend = DataHubSupersessionBackend(server=server, token=args.token)
    supersession_backend.test_connection()
    supersession_emission = SupersessionEmitter(supersession_backend).emit_verified(
        artifacts.supersession
    )
    after = {urn: _entity_digest(graph, urn) for urn in before}
    receipt_documents_unchanged = before == after
    report: dict[str, Any] = {
        "contract": "glassbox.datahub-semantic-policy.v1",
        "valid": (
            artifacts.valid
            and source_emission.valid
            and replay_emission.valid
            and supersession_emission.valid
            and receipt_documents_unchanged
            and (
                not args.pricing_semantic_policy
                or (
                    artifacts.diff.semantic.policy_id == semantic_policy.policy_id
                    and artifacts.diff.semantic.result == "EQUIVALENT"
                    and artifacts.diff.semantic.exact_match is False
                    and artifacts.diff.semantic.matched_change_count
                    == len(artifacts.diff.structural_changes)
                    == 1
                    and supersession_emission.verified_property_count == 19
                )
            )
        ),
        "compatibility": {
            "server": server,
            "datahub_core_target": "1.6.0",
            "sdk_version": receipt_backend.sdk_version,
        },
        "artifacts": artifacts.summary(),
        "source_receipt": source_emission.to_dict(),
        "replay_receipt": replay_emission.to_dict(),
        "supersession": supersession_emission.to_dict(),
        "semantic_policy": {
            "selected": args.pricing_semantic_policy,
            "policy_id": artifacts.diff.semantic.policy_id,
            "rule_id": artifacts.diff.semantic.rule_id,
            "rule_version": artifacts.diff.semantic.rule_version,
            "result": artifacts.diff.semantic.result,
            "exact_match": artifacts.diff.semantic.exact_match,
            "structural_change_count": artifacts.diff.semantic.structural_change_count,
            "matched_change_count": artifacts.diff.semantic.matched_change_count,
            "reason_codes": list(artifacts.diff.semantic.reason_codes),
            "rule_evaluations": [item.to_dict() for item in artifacts.diff.semantic.evaluations],
            "raw_content_returned": False,
        },
        "history_preservation": {
            "local_source_mutations": artifacts.execution.source_history_mutations,
            "receipt_documents_unchanged_after_supersession": receipt_documents_unchanged,
            "direct_entity_digests_before": before,
            "direct_entity_digests_after": after,
        },
        "privacy": {
            "raw_source_output_returned": False,
            "raw_replay_output_returned": False,
            "raw_customer_identity_returned": False,
        },
        "raw_content_returned": False,
    }
    serialized = json.dumps(report, indent=2, sort_keys=True)
    if "semantic-private-customer" in serialized or '"recommended_price"' in serialized:
        raise RuntimeError("semantic policy proof crossed the raw-output boundary")
    print(serialized)
    return 0 if report["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
