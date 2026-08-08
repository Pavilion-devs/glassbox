"""History-preserving supersession artifact and DataHub projection tests."""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_datahub import (
    SupersessionEmissionError,
    SupersessionEmitter,
    SupersessionReadback,
    supersession_document_urn,
    supersession_properties,
)
from glassbox_dbom import SigningKey, seal_receipt
from glassbox_replay import (
    ReplayExecutionError,
    build_replay_diff,
    build_replay_receipt,
    create_supersession_record,
)
from tests.unit.test_replay_execution import _bundle, _execute, _source

CREATED_AT = "2026-08-06T12:32:00Z"


class FakeSupersessionBackend:
    def __init__(
        self,
        *,
        change_second_urn: bool = False,
        wrong_urn: bool = False,
        mismatched_property: bool = False,
        aspects: tuple[str, ...] = ("documentInfo", "status"),
    ) -> None:
        self.change_second_urn = change_second_urn
        self.wrong_urn = wrong_urn
        self.mismatched_property = mismatched_property
        self.aspects = aspects
        self.records: list[Any] = []

    def upsert_supersession(self, record: Any) -> str:
        self.records.append(record)
        urn = supersession_document_urn(record.supersession_id)
        if self.wrong_urn:
            return urn + ".wrong"
        if self.change_second_urn and len(self.records) == 2:
            return urn + ".second"
        return urn

    def direct_read_supersession(self, urn: str) -> SupersessionReadback:
        del urn
        properties = supersession_properties(self.records[-1])
        if self.mismatched_property:
            properties["glassbox.replay_diff_id"] = "tampered"
        return SupersessionReadback(properties=properties, aspect_names=self.aspects)


def _successful_artifacts(
    *,
    query: str = "orders",
    source_price: int = 40,
    replay_price: int = 42,
) -> tuple[dict[str, Any], dict[str, Any], Any, Any, Any]:
    action_input = {"query": query}
    replay_input = {"customer": 77}
    source_output = {"price": source_price, "private": "old-value"}
    replay_output = {"price": replay_price, "private": "new-value"}
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
        signing_keys=(SigningKey("supersession-receipt", Ed25519PrivateKey.generate()),),
    )
    diff = build_replay_diff(
        source,
        replay_receipt,
        source_output=source_output,
        replay_output=execution.output,
    )
    return source, replay_receipt, plan, execution, diff


def test_supersession_chain_is_content_addressed_idempotent_and_directly_verified() -> None:
    source, replay_receipt, plan, execution, diff = _successful_artifacts()
    first = create_supersession_record(
        source,
        replay_receipt,
        execution=execution,
        plan=plan,
        diff=diff,
        created_at=CREATED_AT,
    )
    second = create_supersession_record(
        source,
        replay_receipt,
        execution=execution,
        plan=plan,
        diff=diff,
        created_at=CREATED_AT,
    )

    assert first == second and first.valid
    assert first.source_receipt_id == source["receipt_id"]
    assert first.replay_receipt_id == replay_receipt["receipt_id"]
    assert first.relation == "SUPERSEDES"
    assert first.structural_change_count == len(diff.structural_changes)
    projection = json.dumps(first.to_dict())
    assert "old-value" not in projection and "new-value" not in projection

    backend = FakeSupersessionBackend()
    report = SupersessionEmitter(backend).emit_verified(first)
    assert report.valid
    assert report.emissions == 2
    assert len(backend.records) == 2
    assert report.document_urn == supersession_document_urn(first.supersession_id)
    assert report.verified_property_count == 19
    assert report.to_dict()["valid"] is True


def test_supersession_emitter_fails_closed_on_transport_or_readback_drift() -> None:
    source, replay_receipt, plan, execution, diff = _successful_artifacts()
    record = create_supersession_record(
        source,
        replay_receipt,
        execution=execution,
        plan=plan,
        diff=diff,
        created_at=CREATED_AT,
    )
    with pytest.raises(SupersessionEmissionError, match="content address"):
        SupersessionEmitter(FakeSupersessionBackend()).emit_verified(
            replace(record, supersession_id="gbx:replay-supersession:sha256:" + "0" * 64)
        )
    with pytest.raises(SupersessionEmissionError, match="not idempotent"):
        SupersessionEmitter(FakeSupersessionBackend(change_second_urn=True)).emit_verified(record)
    with pytest.raises(SupersessionEmissionError, match="unexpected URN"):
        SupersessionEmitter(FakeSupersessionBackend(wrong_urn=True)).emit_verified(record)
    with pytest.raises(SupersessionEmissionError, match="readback mismatch"):
        SupersessionEmitter(FakeSupersessionBackend(mismatched_property=True)).emit_verified(record)
    with pytest.raises(SupersessionEmissionError, match="no aspects"):
        SupersessionEmitter(FakeSupersessionBackend(aspects=())).emit_verified(record)


def test_supersession_creation_rejects_failed_or_cross_bound_artifacts() -> None:
    source, replay_receipt, plan, execution, diff = _successful_artifacts()
    with pytest.raises(ReplayExecutionError, match="successful execution"):
        create_supersession_record(
            source,
            replay_receipt,
            execution=replace(execution, status="FAILED", failure_type="SyntheticFailure"),
            plan=plan,
            diff=diff,
            created_at=CREATED_AT,
        )
    with pytest.raises(ReplayExecutionError, match="diff content address"):
        create_supersession_record(
            source,
            replay_receipt,
            execution=execution,
            plan=plan,
            diff=replace(diff, diff_id="gbx:replay-diff:sha256:" + "0" * 64),
            created_at=CREATED_AT,
        )
    with pytest.raises(ReplayExecutionError, match="plan binding"):
        create_supersession_record(
            source,
            replay_receipt,
            execution=execution,
            plan=replace(plan, plan_id="gbx:replay-plan:sha256:" + "0" * 64),
            diff=diff,
            created_at=CREATED_AT,
        )

    altered_payload = copy.deepcopy(replay_receipt)
    altered_payload.pop("receipt_id")
    altered_payload.pop("integrity")
    altered_payload["extensions"]["glassbox.replay.execution_id"] = "wrong"
    altered = seal_receipt(
        altered_payload,
        signing_keys=(SigningKey("altered-replay", Ed25519PrivateKey.generate()),),
    )
    altered_diff = build_replay_diff(
        source,
        altered,
        source_output={"price": 40, "private": "old-value"},
        replay_output=execution.output,
    )
    with pytest.raises(ReplayExecutionError, match="extensions"):
        create_supersession_record(
            source,
            altered,
            execution=execution,
            plan=plan,
            diff=altered_diff,
            created_at=CREATED_AT,
        )

    other_source, other_replay, other_plan, other_execution, other_diff = _successful_artifacts(
        query="different-query", source_price=10, replay_price=11
    )
    del other_replay, other_diff
    with pytest.raises(ReplayExecutionError, match="source receipt binding"):
        create_supersession_record(
            source,
            replay_receipt,
            execution=other_execution,
            plan=other_plan,
            diff=diff,
            created_at=CREATED_AT,
        )

    _, alternate_replay, _, _, alternate_diff = _successful_artifacts(replay_price=43)
    with pytest.raises(ReplayExecutionError, match="not the diff replay output"):
        create_supersession_record(
            source,
            alternate_replay,
            execution=execution,
            plan=plan,
            diff=alternate_diff,
            created_at=CREATED_AT,
        )

    with pytest.raises(ReplayExecutionError, match="ISO 8601"):
        create_supersession_record(
            source,
            replay_receipt,
            execution=execution,
            plan=plan,
            diff=diff,
            created_at="not-a-time",
        )
    with pytest.raises(ReplayExecutionError, match="timezone"):
        create_supersession_record(
            source,
            replay_receipt,
            execution=execution,
            plan=plan,
            diff=diff,
            created_at="2026-08-06T12:32:00",
        )
    tampered_source = copy.deepcopy(source)
    tampered_source["output"]["kind"] = "tampered"
    with pytest.raises(ReplayExecutionError, match="source receipt verification"):
        create_supersession_record(
            tampered_source,
            replay_receipt,
            execution=execution,
            plan=plan,
            diff=diff,
            created_at=CREATED_AT,
        )
    assert other_source["receipt_id"] != source["receipt_id"]


@pytest.mark.parametrize(
    "value",
    [
        "wrong-type",
        "gbx:replay-supersession:sha256:abc",
        "gbx:replay-supersession:sha256:" + "G" * 64,
    ],
)
def test_supersession_document_urn_rejects_malformed_ids(value: str) -> None:
    with pytest.raises(SupersessionEmissionError):
        supersession_document_urn(value)


def test_supersession_projection_contains_only_ids_counts_and_document_urns() -> None:
    source, replay_receipt, plan, execution, diff = _successful_artifacts()
    record = create_supersession_record(
        source,
        replay_receipt,
        execution=execution,
        plan=plan,
        diff=diff,
        created_at=CREATED_AT,
    )
    properties = supersession_properties(record)
    assert properties["glassbox.source_receipt_urn"].startswith("urn:li:document:glassbox.receipt.")
    assert properties["glassbox.replay_receipt_urn"].startswith("urn:li:document:glassbox.receipt.")
    assert properties["glassbox.replay_semantic_policy_id"] == diff.semantic.policy_id
    assert properties["glassbox.replay_semantic_rule_id"] == diff.semantic.rule_id
    assert properties["glassbox.replay_semantic_exact_match"] == "false"
    assert set(properties.values()).isdisjoint({"old-value", "new-value"})
    assert all(isinstance(value, str) for value in properties.values())
