"""Direct MCP client middleware with digest-only argument and result capture."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from glassbox.models import ActionEffect
from glassbox.runtime import GlassBox


class MCPToolMiddleware:
    """Wrap an MCP call-next function without depending on a specific client SDK."""

    def __init__(self, runtime: GlassBox) -> None:
        self.runtime = runtime

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        call_next: Callable[[str, Mapping[str, Any]], Awaitable[Any]],
        *,
        server: str | None = None,
        effect: ActionEffect = ActionEffect.UNKNOWN_EFFECT,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Any:
        """Execute a tool and preserve only normalized metadata plus payload digests."""

        tool_id = f"{server}.{name}" if server else name
        safe_metadata: dict[str, Any] = dict(metadata or {})
        if server is not None:
            safe_metadata["mcp.server"] = server
        return await self.runtime.call_tool_async(
            tool_id,
            call_next,
            name,
            arguments,
            effect=effect,
            idempotency_key=idempotency_key,
            approval_id=approval_id,
            metadata=safe_metadata,
        )
