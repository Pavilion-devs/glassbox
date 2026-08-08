"""Dependency-light LangChain and LangGraph tool callback adapter."""

from __future__ import annotations

from typing import Any

from glassbox.adapters.callbacks import CallbackActionAdapter
from glassbox.adapters.policy import ToolPolicyResolver, unknown_tool_policy
from glassbox.runtime import GlassBox


class LangChainToolCallbackAdapter:
    """Translate LangChain tool callbacks into normalized GlassBox actions."""

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

    def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: Any,
        parent_run_id: Any | None = None,
        tags: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
        inputs: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> None:
        """Preflight a LangChain tool before its implementation executes."""

        tool_id = _tool_name(serialized, kwargs)
        input_value: Any = inputs if inputs is not None else input_str
        safe_context = {
            "framework": "langchain",
            "parent_run_id": None if parent_run_id is None else str(parent_run_id),
            "tags": tags or [],
            "callback_metadata": metadata or {},
        }
        policy = self._policy_resolver(tool_id, input_value, safe_context)
        self._bridge.on_tool_start(
            str(run_id),
            tool_id=tool_id,
            input_value=input_value,
            effect=policy.effect,
            idempotency_key=policy.idempotency_key,
            approval_id=policy.approval_id,
            metadata=safe_context,
        )

    def on_tool_end(self, output: Any, *, run_id: Any, **kwargs: Any) -> None:
        """Record a successful LangChain tool callback."""

        del kwargs
        self._bridge.on_tool_end(str(run_id), output)

    def on_tool_error(self, error: BaseException, *, run_id: Any, **kwargs: Any) -> None:
        """Record a failed callback without retaining its exception message."""

        del kwargs
        self._bridge.on_tool_error(str(run_id), error)


def create_langchain_callback(
    runtime: GlassBox,
    *,
    policy_resolver: ToolPolicyResolver = unknown_tool_policy,
) -> Any:
    """Create a LangChain ``BaseCallbackHandler`` without a hard dependency."""

    try:
        from langchain_core.callbacks import BaseCallbackHandler
    except ImportError as exc:  # pragma: no cover - optional dependency path
        raise ImportError(
            "LangChain integration requires the 'langchain-core' optional dependency"
        ) from exc

    adapter = LangChainToolCallbackAdapter(runtime, policy_resolver=policy_resolver)

    class GlassBoxCallbackHandler(BaseCallbackHandler):
        """Concrete handler defined against the installed LangChain version."""

        def on_tool_start(self, serialized: dict[str, Any], input_str: str, **kwargs: Any) -> None:
            adapter.on_tool_start(serialized, input_str, **kwargs)

        def on_tool_end(self, output: Any, **kwargs: Any) -> None:
            adapter.on_tool_end(output, **kwargs)

        def on_tool_error(self, error: BaseException, **kwargs: Any) -> None:
            adapter.on_tool_error(error, **kwargs)

    return GlassBoxCallbackHandler()


def _tool_name(serialized: dict[str, Any], kwargs: dict[str, Any]) -> str:
    candidate = serialized.get("name") or kwargs.get("name")
    if not isinstance(candidate, str) or not candidate:
        raise ValueError("LangChain tool callback requires serialized['name']")
    return candidate
