"""Runtime correlation, privacy, and safety tests."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest

from glassbox import (
    ActionEffect,
    ActionStatus,
    CallbackActionAdapter,
    DuplicateActionError,
    EventKind,
    EvidenceRole,
    EvidenceState,
    EvidenceValidationError,
    GlassBox,
    InMemorySink,
    MCPToolMiddleware,
    NoActiveRunError,
    PolicyViolationError,
    RedactionPolicy,
    RunStatus,
    TelemetryExportError,
    UnknownActionError,
)
from glassbox.models import RuntimeEvent
from glassbox.redaction import digest_value


class DeterministicIds:
    def __init__(self) -> None:
        self._spans: Iterator[int] = iter(range(1, 100))
        self._runs: Iterator[int] = iter(range(1, 100))

    def trace_id(self) -> str:
        return "a" * 32

    def span_id(self) -> str:
        return f"{next(self._spans):016x}"

    def run_id(self) -> str:
        return f"run-{next(self._runs)}"


class FailingSink:
    def emit(self, event: RuntimeEvent) -> None:
        del event
        raise OSError("synthetic sink failure with secret=never-record-this")


class InvalidTraceIds(DeterministicIds):
    def trace_id(self) -> str:
        return "invalid"


def runtime(*, sink: InMemorySink | None = None) -> tuple[GlassBox, InMemorySink]:
    active_sink = sink or InMemorySink()
    recorder = GlassBox(
        active_sink,
        id_generator=DeterministicIds(),
        clock=lambda: datetime(2026, 8, 6, tzinfo=UTC),
    )
    return recorder, active_sink


def test_nested_runs_share_trace_and_preserve_parent_correlation() -> None:
    recorder, sink = runtime()

    with recorder.run(agent_id="parent", workflow_id="workflow") as parent:
        assert recorder.current_run == parent.context
        with recorder.run(agent_id="child", workflow_id="subworkflow") as child:
            assert child.context.trace_id == parent.context.trace_id
            assert child.context.parent_run_id == parent.context.run_id
            assert child.context.parent_span_id == parent.context.span_id
        assert recorder.current_run == parent.context

    assert recorder.current_run is None
    assert [event.kind for event in sink.events] == [
        EventKind.RUN_STARTED,
        EventKind.RUN_STARTED,
        EventKind.RUN_FINISHED,
        EventKind.RUN_FINISHED,
    ]
    assert [event.sequence for event in sink.events] == [1, 2, 3, 4]


def test_invalid_event_construction_never_leaks_task_local_context() -> None:
    invalid_ids = GlassBox(InMemorySink(), id_generator=InvalidTraceIds())

    with pytest.raises(ValueError, match="trace_id"):
        with invalid_ids.run(agent_id="agent", workflow_id="workflow"):
            pass

    assert invalid_ids.current_run is None

    naive_clock = GlassBox(
        InMemorySink(),
        clock=lambda: datetime(2026, 8, 6),  # noqa: DTZ001
    )
    with pytest.raises(ValueError, match="timezone-aware"):
        with naive_clock.run(agent_id="agent", workflow_id="workflow"):
            pass

    assert naive_clock.current_run is None


def test_explicit_empty_run_id_is_rejected() -> None:
    recorder, _ = runtime()

    with pytest.raises(ValueError, match="run_id"):
        with recorder.run(agent_id="agent", workflow_id="workflow", run_id=""):
            pass


def test_context_manager_marks_exception_failed_without_recording_message() -> None:
    recorder, sink = runtime()

    with pytest.raises(ValueError, match="private detail"):
        with recorder.run(agent_id="agent", workflow_id="workflow"):
            raise ValueError("private detail")

    finished = sink.events[-1]
    assert finished.to_dict()["spec_version"] == "0.1.0"
    assert finished.attributes["run.status"] == RunStatus.FAILED.value
    assert finished.attributes["error.type"] == "ValueError"
    assert "private detail" not in json.dumps(finished.to_dict())


def test_consequential_decorator_records_sync_and_async_output_digests() -> None:
    recorder, sink = runtime()

    @recorder.consequential(agent_id="pricing", workflow_id="recommend")
    def sync_agent(value: int) -> dict[str, int]:
        return {"price": value}

    @recorder.consequential(agent_id="pricing", workflow_id="recommend-async")
    async def async_agent(value: int) -> dict[str, int]:
        return {"price": value}

    assert sync_agent(42) == {"price": 42}
    assert asyncio.run(async_agent(43)) == {"price": 43}

    finished = [event for event in sink.events if event.kind is EventKind.RUN_FINISHED]
    assert finished[0].attributes["output.digest"] == digest_value({"price": 42})
    assert finished[1].attributes["output.digest"] == digest_value({"price": 43})


def test_run_handle_can_abstain_or_cancel() -> None:
    recorder, sink = runtime()

    with recorder.run(agent_id="agent", workflow_id="abstain") as handle:
        handle.abstain()
    with recorder.run(agent_id="agent", workflow_id="cancel") as handle:
        handle.cancel()

    statuses = [
        event.attributes["run.status"]
        for event in sink.events
        if event.kind is EventKind.RUN_FINISHED
    ]
    assert statuses == [RunStatus.ABSTAINED.value, RunStatus.CANCELLED.value]


def test_observed_evidence_requires_runtime_representation() -> None:
    recorder, _ = runtime()

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        with pytest.raises(EvidenceValidationError, match="captured representation"):
            recorder.observe_evidence(
                entity_type="dataset",
                state=EvidenceState.OBSERVED,
                role=EvidenceRole.INPUT,
            )


def test_inferred_evidence_requires_rule_confidence_and_valid_range() -> None:
    recorder, _ = runtime()

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        with pytest.raises(EvidenceValidationError, match="rule_id and confidence"):
            recorder.observe_evidence(
                entity_type="document",
                state=EvidenceState.INFERRED,
                role=EvidenceRole.REFERENCE,
            )
        with pytest.raises(EvidenceValidationError, match="between 0 and 1"):
            recorder.observe_evidence(
                entity_type="document",
                state=EvidenceState.INFERRED,
                role=EvidenceRole.REFERENCE,
                rule_id="rule-1",
                confidence=1.1,
            )


def test_evidence_records_digest_and_redacts_sensitive_metadata() -> None:
    policy = RedactionPolicy(sensitive_paths=frozenset({"customer.ssn"}))
    sink = InMemorySink()
    recorder = GlassBox(
        sink,
        redaction_policy=policy,
        id_generator=DeterministicIds(),
        clock=lambda: datetime(2026, 8, 6, tzinfo=UTC),
    )

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        observation = recorder.observe_evidence(
            entity_type="dataset",
            datahub_urn="urn:li:dataset:(urn:li:dataPlatform:test,orders,PROD)",
            state=EvidenceState.OBSERVED,
            role=EvidenceRole.INPUT,
            representation={"count": 7, "customer": "not-stored"},
            metadata={
                "Authorization": "Bearer top-secret",
                "customer": {"ssn": "111-22-3333", "region": "NG"},
            },
        )

    assert observation.representation_digest is not None
    encoded = json.dumps(sink.events[-2].to_dict())
    assert "top-secret" not in encoded
    assert "111-22-3333" not in encoded
    assert "not-stored" not in encoded
    assert encoded.count("[REDACTED]") == 2


def test_unknown_evidence_does_not_become_observed() -> None:
    recorder, sink = runtime()

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        observation = recorder.observe_evidence(
            entity_type="dataset",
            state=EvidenceState.UNKNOWN,
            role=EvidenceRole.REFERENCE,
        )

    assert observation.state is EvidenceState.UNKNOWN
    assert observation.representation_digest is None
    assert sink.events[-2].attributes["evidence.state"] == "UNKNOWN"


def test_evidence_and_actions_require_an_active_run() -> None:
    recorder, _ = runtime()

    with pytest.raises(NoActiveRunError):
        recorder.observe_evidence(
            entity_type="dataset",
            state=EvidenceState.UNKNOWN,
            role=EvidenceRole.INPUT,
        )
    with pytest.raises(NoActiveRunError):
        recorder.call_tool("lookup", lambda: None, effect=ActionEffect.READ_ONLY)


def test_tool_success_records_attempt_and_terminal_digest_without_payload() -> None:
    recorder, sink = runtime()

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        output = recorder.call_tool(
            "orders.lookup",
            lambda query: {"total": 99, "raw": "sensitive-output"},
            {"customer": "sensitive-input"},
            effect=ActionEffect.READ_ONLY,
            metadata={"x-api-key": "secret-key", "region": "west"},
        )

    assert output["total"] == 99
    actions = [event for event in sink.events if "action.status" in event.attributes]
    assert [event.kind for event in actions] == [
        EventKind.ACTION_ATTEMPTED,
        EventKind.ACTION_FINISHED,
    ]
    assert actions[-1].attributes["action.status"] == ActionStatus.SUCCEEDED.value
    encoded = json.dumps([event.to_dict() for event in actions])
    assert "sensitive-input" not in encoded
    assert "sensitive-output" not in encoded
    assert "secret-key" not in encoded
    assert "[REDACTED]" in encoded


def test_failed_tool_records_error_type_and_reraises() -> None:
    recorder, sink = runtime()

    def fail() -> None:
        raise LookupError("secret failure message")

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        with pytest.raises(LookupError, match="secret failure"):
            recorder.call_tool("orders.lookup", fail, effect=ActionEffect.READ_ONLY)

    action = next(event for event in sink.events if event.kind is EventKind.ACTION_FINISHED)
    assert action.attributes["action.status"] == ActionStatus.FAILED.value
    assert action.attributes["error.type"] == "LookupError"
    assert "secret failure message" not in json.dumps(action.to_dict())


@pytest.mark.parametrize(
    ("effect", "idempotency_key", "approval_id", "message"),
    [
        (ActionEffect.REVERSIBLE, None, None, "idempotency_key"),
        (ActionEffect.IRREVERSIBLE, "mutation-1", None, "approval_id"),
    ],
)
def test_governed_actions_are_blocked_before_invocation(
    effect: ActionEffect,
    idempotency_key: str | None,
    approval_id: str | None,
    message: str,
) -> None:
    recorder, sink = runtime()
    called = False

    def mutate() -> None:
        nonlocal called
        called = True

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        with pytest.raises(PolicyViolationError, match=message):
            recorder.call_tool(
                "crm.mutate",
                mutate,
                effect=effect,
                idempotency_key=idempotency_key,
                approval_id=approval_id,
            )

    assert called is False
    blocked = next(event for event in sink.events if event.kind is EventKind.ACTION_FINISHED)
    assert blocked.attributes["action.status"] == ActionStatus.BLOCKED.value


def test_read_only_export_failure_fails_open_without_leaking_sink_message() -> None:
    recorder = GlassBox(
        FailingSink(),
        id_generator=DeterministicIds(),
        clock=lambda: datetime(2026, 8, 6, tzinfo=UTC),
    )

    with recorder.run(agent_id="agent", workflow_id="workflow"):
        assert recorder.call_tool("lookup", lambda: 7, effect=ActionEffect.READ_ONLY) == 7

    assert recorder.export_failures
    assert {failure.error_type for failure in recorder.export_failures} == {"OSError"}
    assert "never-record-this" not in repr(recorder.export_failures)


def test_irreversible_export_failure_stops_before_invocation() -> None:
    recorder = GlassBox(
        FailingSink(),
        id_generator=DeterministicIds(),
        clock=lambda: datetime(2026, 8, 6, tzinfo=UTC),
    )
    called = False

    def mutate() -> None:
        nonlocal called
        called = True

    with pytest.raises(TelemetryExportError, match="failed closed"):
        with recorder.run(agent_id="agent", workflow_id="workflow"):
            recorder.call_tool(
                "payments.capture",
                mutate,
                effect=ActionEffect.IRREVERSIBLE,
                idempotency_key="capture-1",
                approval_id="approval-1",
            )

    assert called is False


@pytest.mark.parametrize(
    ("status", "output", "error_type", "message"),
    [
        (ActionStatus.ATTEMPTED, None, None, "terminal action status"),
        (ActionStatus.SUCCEEDED, None, "ValueError", "cannot include error_type"),
        (ActionStatus.FAILED, None, None, "require error_type"),
        (ActionStatus.BLOCKED, None, "PolicyViolationError", "cannot include an output"),
    ],
)
def test_terminal_action_state_rejects_ambiguous_combinations(
    status: ActionStatus,
    output: object,
    error_type: str | None,
    message: str,
) -> None:
    recorder, _ = runtime()
    with recorder.run(agent_id="agent", workflow_id="workflow"):
        with pytest.raises(ValueError, match=message):
            recorder.record_action(
                tool_id="tool",
                input_value={},
                effect=ActionEffect.READ_ONLY,
                status=status,
                output_value=output,
                error_type=error_type,
            )


def test_successful_framework_action_requires_explicit_output_even_when_none() -> None:
    recorder, _ = runtime()
    with recorder.run(agent_id="agent", workflow_id="workflow"):
        with pytest.raises(ValueError, match="require an output value"):
            recorder.record_action(
                tool_id="tool",
                input_value={},
                effect=ActionEffect.READ_ONLY,
                status=ActionStatus.SUCCEEDED,
            )


def test_direct_mcp_and_callback_modes_produce_same_normalized_action() -> None:
    async def scenario() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        async def call_next(name: str, arguments: object) -> dict[str, object]:
            return {"name": name, "arguments": arguments, "count": 1}

        direct_runtime, direct_sink = runtime()
        with direct_runtime.run(agent_id="agent", workflow_id="direct"):
            await direct_runtime.call_tool_async(
                "inventory.lookup",
                call_next,
                "lookup",
                {"sku": "A-1"},
                effect=ActionEffect.READ_ONLY,
                metadata={"mcp.server": "inventory"},
            )

        mcp_runtime, mcp_sink = runtime()
        middleware = MCPToolMiddleware(mcp_runtime)
        with mcp_runtime.run(agent_id="agent", workflow_id="mcp"):
            await middleware.call_tool(
                "lookup",
                {"sku": "A-1"},
                call_next,
                server="inventory",
                effect=ActionEffect.READ_ONLY,
            )

        direct_action = next(
            event for event in direct_sink.events if event.kind is EventKind.ACTION_FINISHED
        )
        mcp_action = next(
            event for event in mcp_sink.events if event.kind is EventKind.ACTION_FINISHED
        )

        callback_runtime, callback_sink = runtime()
        callbacks = CallbackActionAdapter(callback_runtime)
        with callback_runtime.run(agent_id="agent", workflow_id="callbacks"):
            callbacks.on_tool_start(
                "external-call-1",
                tool_id="inventory.lookup",
                input_value={"args": ("lookup", {"sku": "A-1"}), "kwargs": {}},
                effect=ActionEffect.READ_ONLY,
                metadata={"mcp.server": "inventory"},
            )
            callbacks.on_tool_end(
                "external-call-1",
                {"name": "lookup", "arguments": {"sku": "A-1"}, "count": 1},
            )
        callback_action = next(
            event for event in callback_sink.events if event.kind is EventKind.ACTION_FINISHED
        )
        return (
            direct_action.attributes,
            mcp_action.attributes,
            callback_action.attributes,
        )

    direct, mcp, callback = asyncio.run(scenario())
    assert direct == mcp == callback


def test_callback_adapter_correlates_out_of_order_calls_and_failures() -> None:
    recorder, sink = runtime()
    callbacks = CallbackActionAdapter(recorder)

    with recorder.run(agent_id="agent", workflow_id="callbacks"):
        callbacks.on_tool_start(
            "call-a", tool_id="tool-a", input_value={"value": "a"}, effect=ActionEffect.READ_ONLY
        )
        callbacks.on_tool_start(
            "call-b", tool_id="tool-b", input_value={"value": "b"}, effect=ActionEffect.READ_ONLY
        )
        callbacks.on_tool_error("call-b", ValueError("secret callback failure"))
        callbacks.on_tool_end("call-a", {"ok": True})

    assert callbacks.pending_count == 0
    finished = [event for event in sink.events if event.kind is EventKind.ACTION_FINISHED]
    assert [event.attributes["tool.id"] for event in finished] == ["tool-b", "tool-a"]
    assert finished[0].attributes["error.type"] == "ValueError"
    assert "secret callback failure" not in json.dumps(finished[0].to_dict())


def test_callback_adapter_rejects_duplicate_and_unknown_call_ids() -> None:
    recorder, _ = runtime()
    callbacks = CallbackActionAdapter(recorder)

    with recorder.run(agent_id="agent", workflow_id="callbacks"):
        callbacks.on_tool_start(
            "call-a", tool_id="tool-a", input_value={}, effect=ActionEffect.READ_ONLY
        )
        with pytest.raises(DuplicateActionError, match="already pending"):
            callbacks.on_tool_start(
                "call-a", tool_id="tool-a", input_value={}, effect=ActionEffect.READ_ONLY
            )
        callbacks.on_tool_end("call-a", None)
        with pytest.raises(UnknownActionError, match="not pending"):
            callbacks.on_tool_end("missing", None)


def test_redaction_handles_bytes_sequences_and_unknown_objects_without_repr() -> None:
    class DangerousRepr:
        def __repr__(self) -> str:
            raise AssertionError("repr must never be called")

    policy = RedactionPolicy()
    safe = policy.sanitize({"payload": [b"bytes", DangerousRepr()], "password": "hidden"})

    assert isinstance(safe, dict)
    assert safe["password"] == "[REDACTED]"
    assert safe["payload"][0]["type"] == "bytes"  # type: ignore[index]
    assert safe["payload"][1]["type"].endswith("DangerousRepr")  # type: ignore[index, union-attr]


def test_redaction_hides_secrets_but_integrity_digest_distinguishes_them() -> None:
    policy = RedactionPolicy()
    first = {"username": "agent", "password": "secret-one"}
    second = {"username": "agent", "password": "secret-two"}

    assert policy.sanitize(first) == policy.sanitize(second)
    assert digest_value(first, policy=policy) != digest_value(second, policy=policy)


def test_digest_normalization_handles_non_json_values_and_cycles() -> None:
    cyclic: list[object] = []
    cyclic.append(cyclic)
    value = {
        "big": 2**80,
        "decimal": Decimal("19.9900"),
        "infinite": float("inf"),
        "not_a_number": float("nan"),
        "uuid": UUID("12345678-1234-5678-1234-567812345678"),
        "unordered": {"b", "a"},
        "cyclic": cyclic,
    }

    first = digest_value(value)
    second = digest_value(value)

    assert first == second
    assert len(first) == 64


def test_dataclass_metadata_obeys_configured_field_redaction() -> None:
    @dataclass
    class Customer:
        name: str
        ssn: str

    policy = RedactionPolicy(sensitive_keys=frozenset({"ssn"}))

    assert policy.sanitize(Customer(name="Ada", ssn="111-22-3333")) == {
        "name": "Ada",
        "ssn": "[REDACTED]",
    }


def test_non_string_mapping_keys_cannot_collide_with_string_keys() -> None:
    assert digest_value({1: "value"}) != digest_value({"1": "value"})
