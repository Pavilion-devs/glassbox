"""OpenTelemetry semantic mapping contract tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from glassbox import (
    ActionEffect,
    EvidenceRole,
    EvidenceState,
    GlassBox,
    InMemorySink,
    OpenTelemetryMappingError,
    OpenTelemetrySpanSink,
    OTelSpanRecord,
    OTelSpanStatus,
)
from tests.unit.test_runtime import DeterministicIds


class IncrementingClock:
    def __init__(self) -> None:
        self._value = datetime(2026, 8, 6, tzinfo=UTC)

    def __call__(self) -> datetime:
        current = self._value
        self._value += timedelta(milliseconds=1)
        return current


def _mapped_runtime() -> tuple[GlassBox, list[OTelSpanRecord]]:
    spans: list[OTelSpanRecord] = []
    sink = OpenTelemetrySpanSink(spans.append)
    runtime = GlassBox(sink, id_generator=DeterministicIds(), clock=IncrementingClock())
    return runtime, spans


def test_run_evidence_and_action_follow_genai_semantic_conventions() -> None:
    runtime, spans = _mapped_runtime()

    with runtime.run(
        agent_id="pricing-agent",
        agent_version="2.1.0",
        workflow_id="recommend-price",
        workflow_version="4",
    ) as run:
        runtime.observe_evidence(
            entity_type="dataset",
            datahub_urn="urn:li:dataset:(urn:li:dataPlatform:test,orders,PROD)",
            schema_field_urn=(
                "urn:li:schemaField:(urn:li:dataset:(urn:li:dataPlatform:test,orders,PROD),revenue)"
            ),
            state=EvidenceState.OBSERVED,
            role=EvidenceRole.INPUT,
            representation={"revenue": 42, "secret": "must-never-leak"},
        )
        result = runtime.call_tool(
            "orders.lookup",
            lambda: {"price": 42, "token": "tool-secret"},
            effect=ActionEffect.READ_ONLY,
        )
        run.record_output(result)

    assert [span.name for span in spans] == [
        "execute_tool orders.lookup",
        "invoke_agent pricing-agent",
    ]
    tool_span, run_span = spans
    assert tool_span.attributes["gen_ai.operation.name"] == "execute_tool"
    assert tool_span.attributes["gen_ai.tool.name"] == "orders.lookup"
    assert "gen_ai.tool.call.arguments" not in tool_span.attributes
    assert "gen_ai.tool.call.result" not in tool_span.attributes
    assert tool_span.status is OTelSpanStatus.UNSET
    assert run_span.attributes["gen_ai.operation.name"] == "invoke_agent"
    assert run_span.attributes["gen_ai.agent.name"] == "pricing-agent"
    assert run_span.attributes["gen_ai.workflow.name"] == "recommend-price"
    assert run_span.attributes["glassbox.run.status"] == "SUCCEEDED"
    assert len(run_span.events) == 1
    assert run_span.events[0].attributes["glassbox.evidence.state"] == "OBSERVED"
    assert "glassbox.datahub.schema_field_urn" in run_span.events[0].attributes
    encoded = json.dumps([span.__dict__ for span in spans], default=str)
    assert "must-never-leak" not in encoded
    assert "tool-secret" not in encoded


def test_failed_tool_and_run_set_error_status_without_exception_message() -> None:
    runtime, spans = _mapped_runtime()

    with pytest.raises(RuntimeError, match="private failure"):
        with runtime.run(agent_id="agent", workflow_id="workflow"):
            runtime.call_tool(
                "dangerous.lookup",
                lambda: (_ for _ in ()).throw(RuntimeError("private failure")),
                effect=ActionEffect.READ_ONLY,
            )

    assert spans[0].status is OTelSpanStatus.ERROR
    assert spans[0].attributes["error.type"] == "RuntimeError"
    assert spans[1].status is OTelSpanStatus.ERROR
    assert spans[1].attributes["error.type"] == "RuntimeError"
    assert "private failure" not in json.dumps([span.__dict__ for span in spans], default=str)


def test_policy_block_becomes_an_instant_error_span() -> None:
    runtime, spans = _mapped_runtime()

    with runtime.run(agent_id="agent", workflow_id="workflow"):
        with pytest.raises(Exception, match="approval_id"):
            runtime.call_tool(
                "payments.charge",
                lambda: None,
                effect=ActionEffect.IRREVERSIBLE,
                idempotency_key="charge-1",
            )

    blocked = spans[0]
    assert blocked.name == "execute_tool payments.charge"
    assert blocked.start_time == blocked.end_time
    assert blocked.status is OTelSpanStatus.ERROR
    assert blocked.attributes["glassbox.action.status"] == "BLOCKED"


def test_orphan_evidence_is_rejected_instead_of_inventing_a_span() -> None:
    source = InMemorySink()
    runtime = GlassBox(source, id_generator=DeterministicIds(), clock=IncrementingClock())
    with runtime.run(agent_id="agent", workflow_id="workflow"):
        runtime.observe_evidence(
            entity_type="dataset",
            state=EvidenceState.UNKNOWN,
            role=EvidenceRole.REFERENCE,
        )

    mapper = OpenTelemetrySpanSink(lambda span: None)
    with pytest.raises(OpenTelemetryMappingError, match="not active"):
        mapper.emit(source.events[1])
