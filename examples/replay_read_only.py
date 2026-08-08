"""Offline closed-loop proof: execute, receipt, diff, and supersession artifacts."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox.redaction import digest_value
from glassbox_dbom import SigningKey, seal_receipt, verify_receipt
from glassbox_policy import SemanticPolicyRegistry
from glassbox_replay import (
    ModelDeterminism,
    ModelReplayConfig,
    ReadOnlyCapability,
    ReadOnlyReplayExecution,
    ReadOnlyReplayExecutor,
    ReplayActionInput,
    ReplayDiff,
    ReplayExecutionInputs,
    ReplayMode,
    ReplayPlan,
    ReplaySupplement,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
    SupersessionRecord,
    build_replay_bundle,
    build_replay_diff,
    build_replay_receipt,
    create_supersession_record,
    plan_replay,
)

FIXTURE = Path(__file__).parents[1] / "tests" / "fixtures" / "dbom" / "valid-read-only.json"
EVALUATED_AT = "2026-08-06T12:30:00Z"
STARTED_AT = "2026-08-06T12:31:00Z"
ENDED_AT = "2026-08-06T12:31:01Z"
CREATED_AT = "2026-08-06T12:32:00Z"


@dataclass(frozen=True)
class ReplayProofArtifacts:
    """Verified artifacts returned for the live DataHub transport proof."""

    source_receipt: dict[str, Any]
    replay_receipt: dict[str, Any]
    plan: ReplayPlan
    execution: ReadOnlyReplayExecution
    diff: ReplayDiff
    supersession: SupersessionRecord
    source_unchanged: bool

    @property
    def valid(self) -> bool:
        return (
            self.plan.valid
            and self.execution.valid
            and verify_receipt(self.replay_receipt, require_signature=True).valid
            and self.diff.valid
            and self.supersession.valid
            and self.source_unchanged
        )

    def summary(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "decision": self.plan.decision.value,
            "source_receipt_id": self.source_receipt["receipt_id"],
            "replay_receipt_id": self.replay_receipt["receipt_id"],
            "execution_id": self.execution.execution_id,
            "diff_id": self.diff.diff_id,
            "semantic_policy_id": self.diff.semantic.policy_id,
            "semantic_rule_id": self.diff.semantic.rule_id,
            "semantic_rule_version": self.diff.semantic.rule_version,
            "semantic_result": self.diff.semantic.result,
            "semantic_exact_match": self.diff.semantic.exact_match,
            "structural_change_count": len(self.diff.structural_changes),
            "supersession_id": self.supersession.supersession_id,
            "source_history_mutations": self.execution.source_history_mutations,
            "raw_values_retained": False,
        }


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _value(value: dict[str, str] | None) -> str | None:
    return value["value"] if value is not None else None


def _inventory(receipt: dict[str, Any]) -> ResourceInventory:
    agent = receipt["agent"]
    workflow = receipt["workflow"]
    model = receipt["models"][0]
    skill = receipt["skills"][0]
    tool = receipt["tools"][0]
    return ResourceInventory(
        (
            ResourceAvailability(
                ResourceKind.AGENT,
                agent["id"],
                agent["version"],
                source_digest=_value(agent["source_digest"]),
            ),
            ResourceAvailability(ResourceKind.WORKFLOW, workflow["id"], workflow["version"]),
            ResourceAvailability(
                ResourceKind.MODEL,
                model["id"],
                model["version"],
                source_digest=_value(model["source_digest"]),
            ),
            ResourceAvailability(
                ResourceKind.SKILL,
                skill["id"],
                skill["version"],
                source_digest=_value(skill["source_digest"]),
            ),
            ResourceAvailability(
                ResourceKind.TOOL,
                tool["id"],
                tool["version"],
                source_digest=_value(tool["source_digest"]),
                schema_digest=_value(tool["schema_digest"]),
            ),
        )
    )


def build_replay_artifacts(
    *,
    source_output_override: dict[str, Any] | None = None,
    replay_output_override: dict[str, Any] | None = None,
    output_kind: str | None = None,
    semantic_policy_id: str | None = None,
    semantic_registry: SemanticPolicyRegistry | None = None,
) -> ReplayProofArtifacts:
    action_input = {"customer_id": "synthetic-customer"}
    replay_input = {"request_id": "synthetic-replay"}
    source_action_output = {"aggregate": 40}
    source_output = (
        source_output_override if source_output_override is not None else {"recommended_price": 40}
    )
    replay_output = (
        replay_output_override if replay_output_override is not None else {"recommended_price": 42}
    )

    source_payload = json.loads(FIXTURE.read_bytes())
    source_payload.pop("receipt_id")
    source_payload.pop("integrity")
    if output_kind is not None:
        source_payload["output"]["kind"] = output_kind
    source_payload["actions"][0]["input_digest"] = {
        "algorithm": "sha256",
        "value": digest_value(action_input),
    }
    source_payload["actions"][0]["output_digest"] = {
        "algorithm": "sha256",
        "value": digest_value(source_action_output),
    }
    source_payload["output"]["digest"] = {
        "algorithm": "sha256",
        "value": digest_value(source_output),
    }
    source_receipt = seal_receipt(
        source_payload,
        signing_keys=(SigningKey("ephemeral-source", Ed25519PrivateKey.generate()),),
    )
    source_snapshot = copy.deepcopy(source_receipt)
    model = source_receipt["models"][0]
    tool = source_receipt["tools"][0]
    bundle = build_replay_bundle(
        source_receipt,
        mode=ReplayMode.PINNED,
        supplement=ReplaySupplement(
            input_digest=digest_value(replay_input),
            input_reference="artifact://example/replay-input",
            feature_flags_digest=_sha("example-feature-flags"),
            model_configs=(
                ModelReplayConfig(
                    model["id"],
                    "example-provider",
                    _sha("temperature=0"),
                    ModelDeterminism.DETERMINISTIC,
                    "example-artifact-store",
                ),
            ),
        ),
        signing_keys=(SigningKey("ephemeral-bundle", Ed25519PrivateKey.generate()),),
    )
    inventory = _inventory(source_receipt)
    plan = plan_replay(
        bundle,
        source_receipt=source_receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    capability = ReadOnlyCapability(
        tool["id"],
        tool["version"],
        _value(tool["source_digest"]) or "",
        _value(tool["schema_digest"]) or "",
        "offline-example-capability",
        lambda _value: {"aggregate": 42},
    )
    inputs = ReplayExecutionInputs(
        replay_input,
        (ReplayActionInput(source_receipt["actions"][0]["action_id"], action_input),),
    )
    execution = ReadOnlyReplayExecutor((capability,)).execute(
        bundle,
        plan,
        source_receipt=source_receipt,
        inventory=inventory,
        inputs=inputs,
        output_projector=lambda _input, _outputs: copy.deepcopy(replay_output),
        run_id="offline-replay-run-001",
        trace_id="abcdef0123456789abcdef0123456789",
        started_at=STARTED_AT,
        ended_at=ENDED_AT,
    )
    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source_receipt,
        inputs=inputs,
        signing_keys=(SigningKey("ephemeral-replay", Ed25519PrivateKey.generate()),),
    )
    diff = build_replay_diff(
        source_receipt,
        replay_receipt,
        source_output=source_output,
        replay_output=execution.output,
        semantic_policy_id=semantic_policy_id,
        semantic_registry=semantic_registry,
    )
    supersession = create_supersession_record(
        source_receipt,
        replay_receipt,
        execution=execution,
        plan=plan,
        diff=diff,
        created_at=CREATED_AT,
    )
    if replay_output != execution.output:
        raise RuntimeError("offline example projector did not produce the expected output")
    return ReplayProofArtifacts(
        source_receipt=source_receipt,
        replay_receipt=replay_receipt,
        plan=plan,
        execution=execution,
        diff=diff,
        supersession=supersession,
        source_unchanged=source_receipt == source_snapshot,
    )


def main() -> int:
    artifacts = build_replay_artifacts()
    result = artifacts.summary()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
