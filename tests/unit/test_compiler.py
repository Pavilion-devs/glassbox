"""Deterministic provenance compiler tests."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from examples.deterministic_pricing_agent import ORDERS_URN, build_pricing_agent

from glassbox import (
    ActionEffect,
    ActionStatus,
    EvidenceRole,
    EvidenceState,
    GlassBox,
    InMemorySink,
)
from glassbox_compiler import (
    CompilationError,
    CompilationProfile,
    ComponentDeclaration,
    Environment,
    ToolDeclaration,
    compile_events,
)
from glassbox_dbom import SigningKey, verify_receipt

_DIGEST = "a" * 64


def _profile(*, signing: bool = False) -> CompilationProfile:
    signing_keys = (
        (SigningKey("glassbox-test-key", Ed25519PrivateKey.generate()),) if signing else ()
    )
    return CompilationProfile(
        environment=Environment.DEV,
        output_kind="pricing-recommendation",
        output_mime_type="application/json",
        agent=ComponentDeclaration(
            id="glassbox.demo.pricing-agent",
            version="0.1.0",
            datahub_urn="urn:li:document:glassbox.demo.agent.pricing-agent",
            source_digest=_DIGEST,
        ),
        models=(ComponentDeclaration(id="glassbox.demo.model", version="1"),),
        skills=(ComponentDeclaration(id="glassbox.demo.pricing-analysis", version="0.1.0"),),
        tools=(
            ToolDeclaration(
                id="glassbox.demo.pricing-policy",
                version="0.1.0",
                datahub_urn="urn:li:document:glassbox.demo.tool.pricing-policy",
                source_digest="b" * 64,
                schema_digest="c" * 64,
            ),
        ),
        signing_keys=signing_keys,
    )


def _pricing_events() -> tuple[object, ...]:
    sink = InMemorySink()
    agent = build_pricing_agent(GlassBox(sink))
    agent("synthetic-customer-17")
    return sink.events


def test_compiles_real_runtime_events_into_a_signed_valid_dbom() -> None:
    events = _pricing_events()
    receipt = compile_events(events, profile=_profile(signing=True))

    report = verify_receipt(receipt, require_signature=True)
    assert report.valid
    assert receipt["run"]["status"] == "SUCCEEDED"
    assert receipt["agent"]["datahub_urn"] == ("urn:li:document:glassbox.demo.agent.pricing-agent")
    assert receipt["evidence"][0]["datahub_urn"] == ORDERS_URN
    assert receipt["evidence"][0]["state"] == "OBSERVED"
    assert receipt["actions"][0]["status"] == "SUCCEEDED"
    assert receipt["replay"]["eligibility"] == "ELIGIBLE"
    assert receipt["integrity"]["signatures"][0]["key_id"] == "glassbox-test-key"
    assert "synthetic-customer-17" not in json.dumps(receipt)


def test_same_events_and_profile_compile_to_same_content_address() -> None:
    events = _pricing_events()
    profile = _profile()

    first = compile_events(events, profile=profile)
    second = compile_events(tuple(reversed(events)), profile=profile)

    assert first == second
    assert first["receipt_id"] == second["receipt_id"]


def test_declared_evidence_remains_distinct_and_is_not_upgraded_to_observed() -> None:
    sink = InMemorySink()
    runtime = GlassBox(sink)
    with runtime.run(
        agent_id="glassbox.demo.pricing-agent",
        agent_version="0.1.0",
        workflow_id="glassbox.demo.recommend-price",
        workflow_version="0.1.0",
    ) as handle:
        runtime.observe_evidence(
            entity_type="policy",
            state=EvidenceState.DECLARED,
            role=EvidenceRole.POLICY,
            datahub_urn="urn:li:glossaryTerm:PricingPolicy",
            capture_method="OWNER_DECLARATION",
        )
        handle.record_output({"decision": "hold"})

    receipt = compile_events(sink.events, profile=_profile())
    evidence = receipt["evidence"][0]
    assert evidence["state"] == "DECLARED"
    assert evidence["representation_digest"] is None
    assert evidence["redaction"]["status"] == "NOT_CAPTURED"
    assert evidence["provenance"]["capture_method"] == "OWNER_DECLARATION"


def test_unfinished_action_is_preserved_as_uncertain_and_unreplayable() -> None:
    sink = InMemorySink()
    runtime = GlassBox(sink)
    with runtime.run(
        agent_id="glassbox.demo.pricing-agent",
        agent_version="0.1.0",
        workflow_id="glassbox.demo.recommend-price",
        workflow_version="0.1.0",
    ) as handle:
        runtime.begin_action(
            tool_id="glassbox.demo.pricing-policy",
            input_value={"order_count": 12},
            effect=ActionEffect.READ_ONLY,
        )
        handle.record_output({"decision": "uncertain"})

    receipt = compile_events(sink.events, profile=_profile())
    assert receipt["actions"][0]["status"] == "ATTEMPTED"
    assert receipt["actions"][0]["output_digest"] is None
    assert receipt["replay"]["eligibility"] == "UNREPLAYABLE"
    assert receipt["extensions"]["glassbox.compiler.partial_action_count"] == 1


@pytest.mark.parametrize(
    ("effect", "status", "expected"),
    [
        (ActionEffect.REVERSIBLE, ActionStatus.SUCCEEDED, "REQUIRES_APPROVAL"),
        (ActionEffect.IRREVERSIBLE, ActionStatus.SUCCEEDED, "UNREPLAYABLE"),
        (ActionEffect.UNKNOWN_EFFECT, ActionStatus.SUCCEEDED, "NOT_EVALUATED"),
        (ActionEffect.READ_ONLY, ActionStatus.FAILED, "UNREPLAYABLE"),
    ],
)
def test_replay_classification_is_fail_safe(
    effect: ActionEffect, status: ActionStatus, expected: str
) -> None:
    sink = InMemorySink()
    runtime = GlassBox(sink)
    with runtime.run(
        agent_id="glassbox.demo.pricing-agent",
        agent_version="0.1.0",
        workflow_id="glassbox.demo.recommend-price",
        workflow_version="0.1.0",
    ) as handle:
        runtime.record_action(
            tool_id="glassbox.demo.pricing-policy",
            input_value={"order_count": 12},
            output_value={"price": 88} if status is ActionStatus.SUCCEEDED else None,
            effect=effect,
            status=status,
            error_type="SyntheticFailure" if status is ActionStatus.FAILED else None,
            idempotency_key="synthetic-idempotency-key",
            approval_id="synthetic-approval" if effect is ActionEffect.IRREVERSIBLE else None,
        )
        handle.record_output({"decision": "hold"})

    receipt = compile_events(sink.events, profile=_profile())
    assert receipt["replay"]["eligibility"] == expected
    if effect is ActionEffect.IRREVERSIBLE:
        assert receipt["extensions"]["glassbox.compiler.unresolved_approval_ids"] == [
            "synthetic-approval"
        ]


def test_terminal_only_framework_action_compiles_without_an_attempt_event() -> None:
    sink = InMemorySink()
    runtime = GlassBox(sink)
    with runtime.run(
        agent_id="glassbox.demo.pricing-agent",
        agent_version="0.1.0",
        workflow_id="glassbox.demo.recommend-price",
        workflow_version="0.1.0",
    ) as handle:
        runtime.record_action(
            tool_id="glassbox.demo.pricing-policy",
            input_value={"order_count": 12},
            output_value={"price": 88},
            effect=ActionEffect.READ_ONLY,
            status=ActionStatus.SUCCEEDED,
        )
        handle.record_output({"decision": "hold"})

    receipt = compile_events(sink.events, profile=_profile())
    assert len(receipt["actions"]) == 1
    assert receipt["actions"][0]["status"] == "SUCCEEDED"


def test_missing_output_commitment_is_rejected_instead_of_fabricated() -> None:
    sink = InMemorySink()
    runtime = GlassBox(sink)
    with runtime.run(
        agent_id="glassbox.demo.pricing-agent",
        workflow_id="glassbox.demo.recommend-price",
    ):
        pass

    with pytest.raises(CompilationError, match=r"output\.digest"):
        compile_events(sink.events, profile=_profile())


def test_duplicate_terminal_event_is_rejected() -> None:
    events = list(_pricing_events())
    terminal = events[-1]
    events.append(replace(terminal, sequence=terminal.sequence + 1))

    with pytest.raises(CompilationError, match=r"exactly one glassbox\.run\.finished"):
        compile_events(events, profile=_profile())


def test_action_identity_cannot_change_between_attempt_and_finish() -> None:
    events = list(_pricing_events())
    terminal_index = next(
        index
        for index, event in enumerate(events)
        if event.kind.value == "glassbox.action.finished"
    )
    terminal = events[terminal_index]
    attributes = {**terminal.attributes, "tool.id": "glassbox.demo.changed-tool"}
    events[terminal_index] = replace(terminal, attributes=attributes)

    with pytest.raises(CompilationError, match=r"changed identity fields: tool\.id"):
        compile_events(events, profile=_profile())


def test_profile_declarations_reject_bad_or_conflicting_identity() -> None:
    with pytest.raises(ValueError, match="lowercase SHA-256"):
        ComponentDeclaration(id="agent", source_digest="not-a-digest")
    with pytest.raises(ValueError, match="unique ids"):
        CompilationProfile(
            environment=Environment.DEV,
            output_kind="result",
            output_mime_type="application/json",
            models=(ComponentDeclaration(id="duplicate"), ComponentDeclaration(id="duplicate")),
        )

    conflict = replace(_profile(), agent=ComponentDeclaration(id="different-agent"))
    with pytest.raises(CompilationError, match="does not match runtime id"):
        compile_events(_pricing_events(), profile=conflict)


def test_malformed_runtime_digest_and_capture_method_are_rejected() -> None:
    events = list(_pricing_events())
    finish = events[-1]
    events[-1] = replace(finish, attributes={**finish.attributes, "output.digest": "BAD"})
    with pytest.raises(CompilationError, match="lowercase SHA-256"):
        compile_events(events, profile=_profile())

    events = list(_pricing_events())
    evidence_index = next(
        index
        for index, event in enumerate(events)
        if event.kind.value == "glassbox.evidence.observed"
    )
    evidence = events[evidence_index]
    events[evidence_index] = replace(
        evidence,
        attributes={**evidence.attributes, "evidence.capture_method": "MAGIC"},
    )
    with pytest.raises(CompilationError, match="unsupported evidence capture method"):
        compile_events(events, profile=_profile())
