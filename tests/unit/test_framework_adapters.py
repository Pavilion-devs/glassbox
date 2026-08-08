"""Named framework adapters produce the shared normalized action contract."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass

import pytest

from glassbox import (
    ActionEffect,
    EventKind,
    GoogleADKToolAdapter,
    LangChainToolCallbackAdapter,
    MappingToolPolicyResolver,
    ToolPolicy,
)
from tests.unit.test_runtime import runtime


def _read_only_policies() -> MappingToolPolicyResolver:
    return MappingToolPolicyResolver(
        {"inventory.lookup": ToolPolicy(effect=ActionEffect.READ_ONLY)}
    )


def test_langchain_adapter_uses_structured_inputs_and_sanitizes_callback_context() -> None:
    recorder, sink = runtime()
    adapter = LangChainToolCallbackAdapter(recorder, policy_resolver=_read_only_policies())

    with recorder.run(agent_id="agent", workflow_id="langgraph"):
        adapter.on_tool_start(
            {"name": "inventory.lookup"},
            "raw input is not the authoritative structure",
            run_id="lc-call-1",
            parent_run_id="lc-parent-1",
            tags=["production"],
            metadata={"Authorization": "Bearer framework-secret"},
            inputs={"sku": "A-1", "password": "input-secret"},
        )
        adapter.on_tool_end({"available": True, "token": "output-secret"}, run_id="lc-call-1")

    action = next(event for event in sink.events if event.kind is EventKind.ACTION_FINISHED)
    assert action.attributes["tool.id"] == "inventory.lookup"
    assert action.attributes["action.effect"] == "READ_ONLY"
    assert action.attributes["action.status"] == "SUCCEEDED"
    assert adapter.pending_count == 0
    encoded = json.dumps(action.to_dict())
    assert "framework-secret" not in encoded
    assert "input-secret" not in encoded
    assert "output-secret" not in encoded


def test_langchain_error_records_only_exception_type() -> None:
    recorder, sink = runtime()
    adapter = LangChainToolCallbackAdapter(recorder, policy_resolver=_read_only_policies())

    with recorder.run(agent_id="agent", workflow_id="langgraph"):
        adapter.on_tool_start(
            {"name": "inventory.lookup"},
            "{}",
            run_id="lc-call-1",
            inputs={},
        )
        adapter.on_tool_error(ValueError("private error detail"), run_id="lc-call-1")

    action = next(event for event in sink.events if event.kind is EventKind.ACTION_FINISHED)
    assert action.attributes["error.type"] == "ValueError"
    assert "private error detail" not in json.dumps(action.to_dict())


@dataclass
class FakeADKTool:
    name: str


@dataclass
class FakeADKContext:
    function_call_id: str | None
    agent_name: str = "pricing-agent"


def test_google_adk_plugin_callbacks_share_the_normalized_action_contract() -> None:
    async def scenario() -> tuple[dict[str, object], int]:
        recorder, sink = runtime()
        adapter = GoogleADKToolAdapter(recorder, policy_resolver=_read_only_policies())
        tool = FakeADKTool("inventory.lookup")
        context = FakeADKContext("adk-call-1")
        with recorder.run(agent_id="agent", workflow_id="google-adk"):
            assert (
                await adapter.before_tool_callback(
                    tool=tool,
                    tool_args={"sku": "A-1"},
                    tool_context=context,
                )
                is None
            )
            assert (
                await adapter.after_tool_callback(
                    tool=tool,
                    tool_args={"sku": "A-1"},
                    tool_context=context,
                    result={"available": True},
                )
                is None
            )
        action = next(event for event in sink.events if event.kind is EventKind.ACTION_FINISHED)
        return action.attributes, adapter.pending_count

    action, pending_count = asyncio.run(scenario())
    assert action["tool.id"] == "inventory.lookup"
    assert action["action.effect"] == "READ_ONLY"
    assert action["action.status"] == "SUCCEEDED"
    assert pending_count == 0


def test_google_adk_error_hook_preserves_failure_and_requires_call_identity() -> None:
    async def scenario() -> dict[str, object]:
        recorder, sink = runtime()
        adapter = GoogleADKToolAdapter(recorder, policy_resolver=_read_only_policies())
        tool = FakeADKTool("inventory.lookup")
        with recorder.run(agent_id="agent", workflow_id="google-adk"):
            with pytest.raises(ValueError, match="function_call_id"):
                await adapter.before_tool_callback(
                    tool=tool,
                    tool_args={},
                    tool_context=FakeADKContext(None),
                )
            context = FakeADKContext("adk-call-1")
            await adapter.before_tool_callback(tool=tool, tool_args={}, tool_context=context)
            await adapter.on_tool_error_callback(
                tool=tool,
                tool_args={},
                tool_context=context,
                error=LookupError("private error detail"),
            )
        action = next(event for event in sink.events if event.kind is EventKind.ACTION_FINISHED)
        return action.attributes

    action = asyncio.run(scenario())
    assert action["action.status"] == "FAILED"
    assert action["error.type"] == "LookupError"
