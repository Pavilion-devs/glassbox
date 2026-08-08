"""Concurrency-safe callback bridge for framework-managed tool lifecycles."""

from __future__ import annotations

from threading import Lock
from typing import Any

from glassbox.errors import DuplicateActionError, UnknownActionError
from glassbox.models import ActionEffect, ActionObservation, ActionStatus, ActionToken
from glassbox.runtime import GlassBox


class CallbackActionAdapter:
    """Join out-of-order framework callbacks without retaining tool arguments."""

    def __init__(self, runtime: GlassBox) -> None:
        self.runtime = runtime
        self._pending: dict[str, ActionToken] = {}
        self._starting: set[str] = set()
        self._lock = Lock()

    @property
    def pending_count(self) -> int:
        with self._lock:
            return len(self._pending)

    def on_tool_start(
        self,
        call_id: str,
        *,
        tool_id: str,
        input_value: Any,
        effect: ActionEffect = ActionEffect.UNKNOWN_EFFECT,
        idempotency_key: str | None = None,
        approval_id: str | None = None,
        metadata: Any = None,
    ) -> None:
        """Preflight and remember a framework tool call by opaque external ID."""

        if not call_id:
            raise ValueError("call_id must not be empty")
        with self._lock:
            if call_id in self._pending or call_id in self._starting:
                raise DuplicateActionError(f"action {call_id!r} is already pending")
            self._starting.add(call_id)
        try:
            token = self.runtime.begin_action(
                tool_id=tool_id,
                input_value=input_value,
                effect=effect,
                idempotency_key=idempotency_key,
                approval_id=approval_id,
                metadata=metadata,
            )
        except BaseException:
            with self._lock:
                self._starting.discard(call_id)
            raise
        with self._lock:
            self._starting.discard(call_id)
            self._pending[call_id] = token

    def on_tool_end(self, call_id: str, output: Any) -> ActionObservation:
        """Complete a successful call and remove its privacy-safe token."""

        token = self._take(call_id)
        try:
            return self.runtime.finish_action(
                token,
                status=ActionStatus.SUCCEEDED,
                output_value=output,
            )
        except BaseException:
            self._restore(call_id, token)
            raise

    def on_tool_error(self, call_id: str, error: BaseException) -> ActionObservation:
        """Complete a failed call while recording only its exception type."""

        token = self._take(call_id)
        try:
            return self.runtime.finish_action(
                token,
                status=ActionStatus.FAILED,
                error_type=type(error).__name__,
            )
        except BaseException:
            self._restore(call_id, token)
            raise

    def _take(self, call_id: str) -> ActionToken:
        with self._lock:
            try:
                return self._pending.pop(call_id)
            except KeyError as exc:
                raise UnknownActionError(f"action {call_id!r} is not pending") from exc

    def _restore(self, call_id: str, token: ActionToken) -> None:
        with self._lock:
            self._pending.setdefault(call_id, token)
