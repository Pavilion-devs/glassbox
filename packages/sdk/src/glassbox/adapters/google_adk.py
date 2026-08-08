"""Google ADK 2.x plugin adapter for normalized GlassBox tool actions."""

from __future__ import annotations

from typing import Any

from glassbox.adapters.callbacks import CallbackActionAdapter
from glassbox.adapters.policy import ToolPolicyResolver, unknown_tool_policy
from glassbox.runtime import GlassBox


class GoogleADKToolAdapter:
    """Implement Google ADK's before/after/error plugin callback contract."""

    def __init__(
        self,
        runtime: GlassBox,
        *,
        policy_resolver: ToolPolicyResolver = unknown_tool_policy,
    ) -> None:
        self._bridge = CallbackActionAdapter(runtime)
        self._policy_resolver = policy_resolver

    @property
    def pending_count(self) -> int:
        return self._bridge.pending_count

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
    ) -> None:
        """Preflight the ADK call and allow it to continue by returning ``None``."""

        call_id = _call_id(tool_context)
        tool_id = _tool_name(tool)
        safe_context = {
            "framework": "google-adk",
            "agent.name": _optional_string(getattr(tool_context, "agent_name", None)),
        }
        policy = self._policy_resolver(tool_id, tool_args, safe_context)
        self._bridge.on_tool_start(
            call_id,
            tool_id=tool_id,
            input_value=tool_args,
            effect=policy.effect,
            idempotency_key=policy.idempotency_key,
            approval_id=policy.approval_id,
            metadata=safe_context,
        )

    async def after_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
        result: dict[str, Any],
    ) -> None:
        """Record successful ADK completion and preserve the framework result."""

        del tool, tool_args
        self._bridge.on_tool_end(_call_id(tool_context), result)

    async def on_tool_error_callback(
        self,
        *,
        tool: Any,
        tool_args: dict[str, Any],
        tool_context: Any,
        error: Exception,
    ) -> None:
        """Record an ADK failure and allow the original error to propagate."""

        del tool, tool_args
        self._bridge.on_tool_error(_call_id(tool_context), error)


def create_google_adk_plugin(
    runtime: GlassBox,
    *,
    policy_resolver: ToolPolicyResolver = unknown_tool_policy,
    name: str = "glassbox_provenance",
) -> Any:
    """Create a concrete Google ADK ``BasePlugin`` against the installed SDK."""

    try:
        from google.adk.plugins.base_plugin import BasePlugin
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise ImportError("Google ADK integration requires the 'google-adk' dependency") from exc

    adapter = GoogleADKToolAdapter(runtime, policy_resolver=policy_resolver)

    class GlassBoxADKPlugin(BasePlugin):
        def __init__(self) -> None:
            super().__init__(name=name)

        async def before_tool_callback(self, **kwargs: Any) -> None:
            await adapter.before_tool_callback(**kwargs)

        async def after_tool_callback(self, **kwargs: Any) -> None:
            await adapter.after_tool_callback(**kwargs)

        async def on_tool_error_callback(self, **kwargs: Any) -> None:
            await adapter.on_tool_error_callback(**kwargs)

    return GlassBoxADKPlugin()


def _call_id(tool_context: Any) -> str:
    candidate = getattr(tool_context, "function_call_id", None)
    if not isinstance(candidate, str) or not candidate:
        raise ValueError("Google ADK tool callback requires tool_context.function_call_id")
    return candidate


def _tool_name(tool: Any) -> str:
    candidate = getattr(tool, "name", None)
    if not isinstance(candidate, str) or not candidate:
        raise ValueError("Google ADK tool callback requires tool.name")
    return candidate


def _optional_string(value: object) -> str | None:
    return value if isinstance(value, str) else None
