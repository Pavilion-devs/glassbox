"""Explicit tool-effect policy shared by framework adapters."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol

from glassbox.models import ActionEffect


@dataclass(frozen=True)
class ToolPolicy:
    """Preflight classification and authority for one framework tool call."""

    effect: ActionEffect = ActionEffect.UNKNOWN_EFFECT
    idempotency_key: str | None = None
    approval_id: str | None = None


class ToolPolicyResolver(Protocol):
    """Resolve policy from the tool identity and sanitized call context."""

    def __call__(self, tool_id: str, input_value: Any, metadata: Any) -> ToolPolicy:
        """Return an explicit policy; unknown tools should remain unknown-effect."""


class MappingToolPolicyResolver:
    """Resolve static policies by exact tool ID with a fail-closed default."""

    def __init__(
        self,
        policies: Mapping[str, ToolPolicy],
        *,
        default: ToolPolicy | None = None,
    ) -> None:
        self._policies = dict(policies)
        self._default = default or ToolPolicy()

    def __call__(self, tool_id: str, input_value: Any, metadata: Any) -> ToolPolicy:
        del input_value, metadata
        return self._policies.get(tool_id, self._default)


def unknown_tool_policy(tool_id: str, input_value: Any, metadata: Any) -> ToolPolicy:
    """Classify an unconfigured tool as unknown-effect and therefore fail closed."""

    del tool_id, input_value, metadata
    return ToolPolicy()
