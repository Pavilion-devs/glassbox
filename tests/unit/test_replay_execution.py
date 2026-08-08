"""Capability-scoped execution, replay receipt, and privacy-safe diff tests."""

from __future__ import annotations

import copy
import hashlib
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox.redaction import digest_value
from glassbox_dbom import SigningKey, seal_receipt, verify_receipt
from glassbox_replay import (
    ActionInputReplacement,
    ContextReplacement,
    ModelDeterminism,
    ModelReplayConfig,
    ReadOnlyCapability,
    ReadOnlyReplayExecutor,
    ReplayActionInput,
    ReplayContextObservation,
    ReplayExecutionError,
    ReplayExecutionInputs,
    ReplayMode,
    ReplaySupplement,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
    build_replay_bundle,
    build_replay_diff,
    build_replay_receipt,
    plan_replay,
)
from tests.helpers import receipt_payload

EVALUATED_AT = "2026-08-06T12:30:00Z"
STARTED_AT = "2026-08-06T12:31:00Z"
ENDED_AT = "2026-08-06T12:31:01Z"
TRACE_ID = "abcdef0123456789abcdef0123456789"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _value(value: dict[str, str] | None) -> str | None:
    return value["value"] if value is not None else None


def _source(
    *,
    action_input: object,
    source_output: object,
    action_output: object | None = None,
) -> dict[str, Any]:
    payload = receipt_payload()
    payload["actions"][0]["input_digest"] = {
        "algorithm": "sha256",
        "value": digest_value(action_input),
    }
    payload["actions"][0]["output_digest"] = {
        "algorithm": "sha256",
        "value": digest_value(action_output if action_output is not None else source_output),
    }
    payload["output"]["digest"] = {
        "algorithm": "sha256",
        "value": digest_value(source_output),
    }
    return seal_receipt(
        payload,
        signing_keys=(SigningKey("execution-source", Ed25519PrivateKey.generate()),),
    )


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


def _bundle(
    receipt: dict[str, Any],
    *,
    replay_input: object,
    mode: ReplayMode = ReplayMode.PINNED,
    replacements: tuple[ContextReplacement, ...] = (),
    replacement_action_input: object | None = None,
) -> dict[str, Any]:
    model = receipt["models"][0]
    input_replacements: tuple[ActionInputReplacement, ...] = ()
    if replacement_action_input is not None:
        input_replacements = (
            ActionInputReplacement(
                receipt["actions"][0]["action_id"],
                digest_value(replacement_action_input),
                tuple(item.evidence_id for item in replacements),
                replacements[0].verification_authority or "",
            ),
        )
    return build_replay_bundle(
        receipt,
        mode=mode,
        supplement=ReplaySupplement(
            input_digest=digest_value(replay_input),
            input_reference="artifact://verified/replay-input",
            feature_flags_digest=_sha("feature-flags"),
            model_configs=(
                ModelReplayConfig(
                    model["id"],
                    "synthetic-provider",
                    _sha("temperature=0"),
                    ModelDeterminism.DETERMINISTIC,
                    "verified-artifact-store",
                ),
            ),
        ),
        context_replacements=replacements,
        action_input_replacements=input_replacements,
        signing_keys=(SigningKey("execution-bundle", Ed25519PrivateKey.generate()),),
    )


def _capability(receipt: dict[str, Any], handler: Any) -> ReadOnlyCapability:
    tool = receipt["tools"][0]
    return ReadOnlyCapability(
        tool["id"],
        tool["version"],
        _value(tool["source_digest"]) or "",
        _value(tool["schema_digest"]) or "",
        "local-read-only-test-capability",
        handler,
    )


def _execute(
    receipt: dict[str, Any],
    bundle: dict[str, Any],
    *,
    replay_input: object,
    action_input: object,
    handler: Any,
    projector: Any,
    observations: tuple[ReplayContextObservation, ...] = (),
) -> tuple[Any, Any, ReplayExecutionInputs]:
    inventory = _inventory(receipt)
    plan = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    inputs = ReplayExecutionInputs(
        replay_input,
        (ReplayActionInput(receipt["actions"][0]["action_id"], action_input),),
        observations,
    )
    execution = ReadOnlyReplayExecutor((_capability(receipt, handler),)).execute(
        bundle,
        plan,
        source_receipt=receipt,
        inventory=inventory,
        inputs=inputs,
        output_projector=projector,
        run_id="replay-run-001",
        trace_id=TRACE_ID,
        started_at=STARTED_AT,
        ended_at=ENDED_AT,
    )
    return plan, execution, inputs


def test_read_only_execution_emits_new_signed_receipt_without_raw_values() -> None:
    action_input = {"customer_id": "secret-customer-77"}
    replay_input = {"request": "secret-replay-request"}
    source_output = {"price": 40, "explanation": "old-private-explanation"}
    replay_output = {"price": 42, "explanation": "new-private-explanation"}
    source = _source(action_input=action_input, source_output=source_output)
    source_before = copy.deepcopy(source)
    bundle = _bundle(source, replay_input=replay_input)

    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda value: {"aggregate": 42, "customer_seen": bool(value)},
        projector=lambda _input, _outputs: replay_output,
    )

    assert execution.valid and execution.status == "SUCCEEDED"
    assert execution.source_history_mutations == 0
    assert source == source_before
    projection = json.dumps(execution.to_dict())
    for secret in (
        "secret-customer-77",
        "secret-replay-request",
        "new-private-explanation",
    ):
        assert secret not in projection

    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("replay-receipt", Ed25519PrivateKey.generate()),),
    )
    assert verify_receipt(replay_receipt, require_signature=True).valid
    assert replay_receipt["receipt_id"] != source["receipt_id"]
    assert replay_receipt["run"]["parent_run_id"] == source["run"]["run_id"]
    assert replay_receipt["replay"]["prior_receipt_digest"] == source["integrity"]["payload_digest"]
    assert replay_receipt["extensions"]["glassbox.replay.execution_id"] == execution.execution_id
    assert replay_receipt["output"]["digest"]["value"] == digest_value(replay_output)
    assert source == source_before


def test_diff_is_deterministic_content_addressed_and_never_retains_values() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source_output = {
        "price": 40,
        "explanation": "source-sensitive-text",
        "nested": {"removed": True},
    }
    replay_output = {
        "price": 42,
        "explanation": "replay-sensitive-text",
        "nested": {"added": [1, 2]},
    }
    source = _source(action_input=action_input, source_output=source_output)
    bundle = _bundle(source, replay_input=replay_input)
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=lambda _input, _outputs: replay_output,
    )
    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("diff-receipt", Ed25519PrivateKey.generate()),),
    )

    first = build_replay_diff(
        source,
        replay_receipt,
        source_output=source_output,
        replay_output=execution.output,
    )
    second = build_replay_diff(
        source,
        replay_receipt,
        source_output=source_output,
        replay_output=execution.output,
    )
    assert first == second and first.valid
    assert first.semantic.result == "CHANGED"
    assert {item.path for item in first.structural_changes} == {
        "/explanation",
        "/nested/added",
        "/nested/removed",
        "/price",
    }
    serialized = json.dumps(first.to_dict())
    assert "source-sensitive-text" not in serialized
    assert "replay-sensitive-text" not in serialized
    assert first.to_dict()["raw_values_retained"] is False


def test_exactly_equivalent_output_has_no_structural_changes() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    output = {"price": 42, "items": [1, 2]}
    source = _source(action_input=action_input, source_output=output)
    bundle = _bundle(source, replay_input=replay_input)
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=lambda _input, _outputs: output,
    )
    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("equivalent-receipt", Ed25519PrivateKey.generate()),),
    )
    diff = build_replay_diff(
        source,
        replay_receipt,
        source_output=output,
        replay_output=execution.output,
    )
    assert diff.semantic.result == "EQUIVALENT"
    assert diff.semantic.score == 1.0
    assert diff.structural_changes == ()


def test_corrected_context_requires_runtime_observation_and_updates_new_receipt_only() -> None:
    source_action_input = {"query": "stale-orders"}
    action_input = {"query": "corrected-orders"}
    replay_input = {"customer": 77}
    source_output = {"price": 40}
    replacement_digest = _sha("corrected-context")
    source = _source(action_input=source_action_input, source_output=source_output)
    source_before = copy.deepcopy(source)
    evidence_id = source["evidence"][0]["evidence_id"]
    replacement = ContextReplacement(
        evidence_id,
        replacement_digest,
        "datahub-direct-read:production",
    )
    bundle = _bundle(
        source,
        replay_input=replay_input,
        mode=ReplayMode.CORRECTED,
        replacements=(replacement,),
        replacement_action_input=action_input,
    )
    observation = ReplayContextObservation(
        evidence_id,
        replacement_digest,
        "datahub-direct-read:production",
        "fedcba9876543210",
        STARTED_AT,
    )
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=lambda _input, _outputs: {"price": 42},
        observations=(observation,),
    )
    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("corrected-receipt", Ed25519PrivateKey.generate()),),
    )
    evidence = replay_receipt["evidence"][0]
    assert evidence["state"] == "OBSERVED"
    assert evidence["representation_digest"]["value"] == replacement_digest
    assert evidence["source_span_id"] == observation.source_span_id
    assert evidence["observed_at"] == observation.observed_at
    assert replay_receipt["actions"][0]["input_digest"]["value"] == digest_value(action_input)
    assert (
        bundle["recipe"]["actions"][0]["original_input_digest"]
        == source["actions"][0]["input_digest"]
    )
    assert source == source_before

    with pytest.raises(ReplayExecutionError, match="exactly match context replacements"):
        _execute(
            source,
            bundle,
            replay_input=replay_input,
            action_input=action_input,
            handler=lambda _value: {"aggregate": 42},
            projector=lambda _input, _outputs: {"price": 42},
        )


def test_handler_and_projector_failures_are_bounded_and_receipted() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source = _source(action_input=action_input, source_output={"price": 40})
    bundle = _bundle(source, replay_input=replay_input)

    def fail_handler(_value: object) -> object:
        raise RuntimeError("raw backend secret must never escape")

    plan, failed, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=fail_handler,
        projector=lambda _input, _outputs: {"unreachable": True},
    )
    assert failed.valid and failed.status == "FAILED"
    assert failed.failure_type == "RuntimeError"
    assert failed.actions[0].status == "FAILED"
    assert "raw backend secret" not in json.dumps(failed.to_dict())
    receipt = build_replay_receipt(
        failed,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("failure-receipt", Ed25519PrivateKey.generate()),),
    )
    assert verify_receipt(receipt, require_signature=True).valid
    assert receipt["run"]["status"] == "FAILED"
    assert receipt["replay"]["eligibility"] == "UNREPLAYABLE"

    def fail_projector(_input: object, _outputs: Any) -> object:
        raise ValueError("private projection value")

    _, projection_failed, _ = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=fail_projector,
    )
    assert projection_failed.status == "FAILED"
    assert projection_failed.failure_type == "ValueError"
    assert projection_failed.actions[0].status == "SUCCEEDED"


def test_execution_refuses_stale_plan_inputs_capabilities_and_source_mutation() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source = _source(action_input=action_input, source_output={"price": 40})
    bundle = _bundle(source, replay_input=replay_input)
    inventory = _inventory(source)
    plan = plan_replay(
        bundle,
        source_receipt=source,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    executor = ReadOnlyReplayExecutor((_capability(source, lambda _value: {"aggregate": 42}),))
    valid_inputs = ReplayExecutionInputs(
        replay_input,
        (ReplayActionInput(source["actions"][0]["action_id"], action_input),),
    )
    arguments = {
        "source_receipt": source,
        "inventory": inventory,
        "output_projector": lambda _input, _outputs: {"price": 42},
        "run_id": "replay-run-refusal",
        "trace_id": TRACE_ID,
        "started_at": STARTED_AT,
        "ended_at": ENDED_AT,
    }
    with pytest.raises(ReplayExecutionError, match="content address"):
        executor.execute(
            bundle,
            replace(plan, plan_id="gbx:replay-plan:sha256:" + "0" * 64),
            inputs=valid_inputs,
            **arguments,
        )
    with pytest.raises(ReplayExecutionError, match="resolved replay input"):
        executor.execute(
            bundle,
            plan,
            inputs=ReplayExecutionInputs(
                {"wrong": True},
                valid_inputs.action_inputs,
            ),
            **arguments,
        )
    with pytest.raises(ReplayExecutionError, match="action input digest mismatch"):
        executor.execute(
            bundle,
            plan,
            inputs=ReplayExecutionInputs(
                replay_input,
                (ReplayActionInput(source["actions"][0]["action_id"], {"wrong": True}),),
            ),
            **arguments,
        )

    mismatched = replace(_capability(source, lambda _value: {}), version="different")
    with pytest.raises(ReplayExecutionError, match="exact read-only capability unavailable"):
        ReadOnlyReplayExecutor((mismatched,)).execute(
            bundle,
            plan,
            inputs=valid_inputs,
            **arguments,
        )

    source_to_mutate = copy.deepcopy(source)

    def mutating_handler(_value: object) -> object:
        source_to_mutate["run"]["status"] = "FAILED"
        return {"aggregate": 42}

    mutating_arguments = {**arguments, "source_receipt": source_to_mutate}
    with pytest.raises(ReplayExecutionError, match="source receipt mutated"):
        ReadOnlyReplayExecutor((_capability(source, mutating_handler),)).execute(
            bundle,
            plan,
            inputs=valid_inputs,
            **mutating_arguments,
        )


def test_diff_refuses_uncommitted_outputs_and_broken_history_link() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source_output = {"price": 40}
    replay_output = {"price": 42}
    source = _source(action_input=action_input, source_output=source_output)
    bundle = _bundle(source, replay_input=replay_input)
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=lambda _input, _outputs: replay_output,
    )
    receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("linked-receipt", Ed25519PrivateKey.generate()),),
    )
    with pytest.raises(ReplayExecutionError, match="source output"):
        build_replay_diff(
            source,
            receipt,
            source_output={"price": 999},
            replay_output=replay_output,
        )
    with pytest.raises(ReplayExecutionError, match="replay output"):
        build_replay_diff(
            source,
            receipt,
            source_output=source_output,
            replay_output={"price": 999},
        )

    broken_payload = copy.deepcopy(receipt)
    broken_payload.pop("receipt_id")
    broken_payload.pop("integrity")
    broken_payload["replay"]["prior_receipt_digest"]["value"] = _sha("other-source")
    broken = seal_receipt(
        broken_payload,
        signing_keys=(SigningKey("broken-link", Ed25519PrivateKey.generate()),),
    )
    with pytest.raises(ReplayExecutionError, match="not linked"):
        build_replay_diff(
            source,
            broken,
            source_output=source_output,
            replay_output=replay_output,
        )


def test_execution_input_contracts_reject_ambiguous_material() -> None:
    digest = _sha("digest")
    with pytest.raises(ReplayExecutionError, match="unique"):
        ReplayExecutionInputs(
            {},
            (ReplayActionInput("action", {}), ReplayActionInput("action", {})),
        )
    with pytest.raises(ReplayExecutionError, match="lowercase SHA-256"):
        ReadOnlyCapability("tool", "1", "bad", digest, "authority", lambda value: value)
    with pytest.raises(ReplayExecutionError, match="must be callable"):
        ReadOnlyCapability("tool", "1", digest, digest, "authority", None)  # type: ignore[arg-type]
    with pytest.raises(ReplayExecutionError, match="16 lowercase"):
        ReplayContextObservation(
            "evidence",
            digest,
            "authority",
            "bad-span",
            STARTED_AT,
        )
    with pytest.raises(ReplayExecutionError, match="runtime-observed"):
        ReplayContextObservation(
            "evidence",
            digest,
            "authority",
            "0123456789abcdef",
            STARTED_AT,
            "CONFIGURATION",
        )


def test_executor_rejects_invalid_metadata_non_allow_policy_and_fresh_policy_drift() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source = _source(action_input=action_input, source_output={"price": 40})
    bundle = _bundle(source, replay_input=replay_input)
    inventory = _inventory(source)
    plan = plan_replay(
        bundle,
        source_receipt=source,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    inputs = ReplayExecutionInputs(
        replay_input,
        (ReplayActionInput(source["actions"][0]["action_id"], action_input),),
    )
    executor = ReadOnlyReplayExecutor((_capability(source, lambda _value: {"aggregate": 42}),))
    base = {
        "source_receipt": source,
        "inventory": inventory,
        "inputs": inputs,
        "output_projector": lambda _input, _outputs: {"price": 42},
        "run_id": "metadata-refusal",
        "trace_id": TRACE_ID,
        "started_at": STARTED_AT,
        "ended_at": ENDED_AT,
    }
    with pytest.raises(ReplayExecutionError, match="trace_id"):
        executor.execute(bundle, plan, **{**base, "trace_id": "bad"})
    with pytest.raises(ReplayExecutionError, match="must not precede"):
        executor.execute(
            bundle,
            plan,
            **{**base, "started_at": ENDED_AT, "ended_at": STARTED_AT},
        )

    dry_bundle = _bundle(source, replay_input=replay_input, mode=ReplayMode.DRY)
    dry_plan = plan_replay(
        dry_bundle,
        source_receipt=source,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    with pytest.raises(ReplayExecutionError, match="requires an ALLOW plan"):
        executor.execute(dry_bundle, dry_plan, **base)

    drifted_resources = list(inventory.resources)
    drifted_resources[-1] = replace(drifted_resources[-1], version="drifted")
    with pytest.raises(ReplayExecutionError, match="fresh policy evaluation"):
        executor.execute(
            bundle,
            plan,
            **{**base, "inventory": ResourceInventory(tuple(drifted_resources))},
        )

    tampered_bundle = copy.deepcopy(bundle)
    tampered_bundle["original_output"]["digest"]["value"] = _sha("tampered")
    with pytest.raises(ReplayExecutionError, match="bundle verification failed"):
        executor.execute(tampered_bundle, plan, **base)

    with pytest.raises(ReplayExecutionError, match="exactly match replay actions"):
        executor.execute(
            bundle,
            plan,
            **{**base, "inputs": ReplayExecutionInputs(replay_input)},
        )


def test_replay_receipt_builder_rechecks_execution_context_and_signing_bindings() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source = _source(action_input=action_input, source_output={"price": 40})
    bundle = _bundle(source, replay_input=replay_input)
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=lambda _input, _outputs: {"price": 42},
    )
    with pytest.raises(ReplayExecutionError, match="execution content address"):
        build_replay_receipt(
            replace(execution, execution_id="gbx:replay-execution:sha256:" + "0" * 64),
            bundle,
            plan,
            source_receipt=source,
            inputs=inputs,
            signing_keys=(SigningKey("receipt", Ed25519PrivateKey.generate()),),
        )
    with pytest.raises(ReplayExecutionError, match="supplied replay plan"):
        build_replay_receipt(
            execution,
            bundle,
            replace(plan, plan_id="gbx:replay-plan:sha256:" + "0" * 64),
            source_receipt=source,
            inputs=inputs,
            signing_keys=(SigningKey("receipt", Ed25519PrivateKey.generate()),),
        )
    with pytest.raises(ReplayExecutionError, match="at least one signing key"):
        build_replay_receipt(
            execution,
            bundle,
            plan,
            source_receipt=source,
            inputs=inputs,
            signing_keys=(),
        )


def test_diff_covers_type_array_and_json_pointer_changes_and_invalid_receipts() -> None:
    action_input = {"query": "orders"}
    replay_input = {"customer": 77}
    source_output = {"kind": 1, "items": [1, 2], "a/b~c": None}
    replay_output = {"kind": {"nested": True}, "items": [1], "a/b~c": True}
    source = _source(action_input=action_input, source_output=source_output)
    bundle = _bundle(source, replay_input=replay_input)
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=lambda _value: {"aggregate": 42},
        projector=lambda _input, _outputs: replay_output,
    )
    receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("shape-receipt", Ed25519PrivateKey.generate()),),
    )
    diff = build_replay_diff(
        source,
        receipt,
        source_output=source_output,
        replay_output=replay_output,
    )
    by_path = {item.path: item for item in diff.structural_changes}
    assert by_path["/kind"].kind == "TYPE_CHANGED"
    assert by_path["/items/1"].kind == "REMOVED"
    assert by_path["/a~1b~0c"].before_type == "null"
    assert by_path["/a~1b~0c"].after_type == "boolean"

    with pytest.raises(ReplayExecutionError, match="two distinct"):
        build_replay_diff(
            source,
            source,
            source_output=source_output,
            replay_output=source_output,
        )
    tampered = copy.deepcopy(receipt)
    tampered["output"]["kind"] = "tampered"
    with pytest.raises(ReplayExecutionError, match="replay receipt verification"):
        build_replay_diff(
            source,
            tampered,
            source_output=source_output,
            replay_output=replay_output,
        )
