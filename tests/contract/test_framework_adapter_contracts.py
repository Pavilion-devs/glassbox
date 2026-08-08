"""Contract tests against installed LangChain and Google ADK base classes."""

from __future__ import annotations

import asyncio

import pytest

from glassbox import (
    ActionEffect,
    MappingToolPolicyResolver,
    ToolPolicy,
    create_google_adk_plugin,
    create_langchain_callback,
)
from tests.unit.test_framework_adapters import FakeADKContext, FakeADKTool
from tests.unit.test_runtime import runtime


def _policies() -> MappingToolPolicyResolver:
    return MappingToolPolicyResolver(
        {"inventory.lookup": ToolPolicy(effect=ActionEffect.READ_ONLY)}
    )


def test_factory_returns_real_langchain_base_callback_handler() -> None:
    callbacks = pytest.importorskip("langchain_core.callbacks")
    recorder, sink = runtime()
    handler = create_langchain_callback(recorder, policy_resolver=_policies())

    assert isinstance(handler, callbacks.BaseCallbackHandler)
    with recorder.run(agent_id="agent", workflow_id="langgraph"):
        handler.on_tool_start(
            {"name": "inventory.lookup"},
            '{"sku":"A-1"}',
            run_id="lc-call-1",
            inputs={"sku": "A-1"},
        )
        handler.on_tool_end({"available": True}, run_id="lc-call-1")
    assert any(event.attributes.get("tool.id") == "inventory.lookup" for event in sink.events)


def test_factory_returns_real_google_adk_base_plugin() -> None:
    plugin_module = pytest.importorskip("google.adk.plugins.base_plugin")

    async def scenario() -> bool:
        recorder, sink = runtime()
        plugin = create_google_adk_plugin(recorder, policy_resolver=_policies())
        assert isinstance(plugin, plugin_module.BasePlugin)
        tool = FakeADKTool("inventory.lookup")
        context = FakeADKContext("adk-call-1")
        with recorder.run(agent_id="agent", workflow_id="google-adk"):
            await plugin.before_tool_callback(
                tool=tool,
                tool_args={"sku": "A-1"},
                tool_context=context,
            )
            await plugin.after_tool_callback(
                tool=tool,
                tool_args={"sku": "A-1"},
                tool_context=context,
                result={"available": True},
            )
        return any(event.attributes.get("tool.id") == "inventory.lookup" for event in sink.events)

    assert asyncio.run(scenario())
