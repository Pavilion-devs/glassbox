"""Default-deny structured metadata redaction."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from glassbox.models import JSONValue
from glassbox_dbom.canonical import canonicalize

_DIGEST_DOMAIN = b"glassbox.runtime.value.v1\0"
_DEFAULT_SENSITIVE_KEYS = frozenset(
    {
        "api-key",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "password",
        "refresh_token",
        "secret",
        "set-cookie",
        "token",
        "x-api-key",
    }
)


@dataclass(frozen=True)
class RedactionPolicy:
    """Recursively redact sensitive keys and configured dotted paths."""

    policy_id: str = "glassbox.default-deny-v1"
    sensitive_keys: frozenset[str] = _DEFAULT_SENSITIVE_KEYS
    sensitive_paths: frozenset[str] = field(default_factory=frozenset)
    replacement: str = "[REDACTED]"

    def sanitize(self, value: Any) -> JSONValue:
        """Return a JSON-safe structure that never calls an object's repr."""

        normalized_paths = frozenset(path.casefold() for path in self.sensitive_paths)
        normalized_keys = frozenset(key.casefold() for key in self.sensitive_keys)
        return self._normalize(value, (), normalized_paths, normalized_keys, set())

    def normalize_for_digest(self, value: Any) -> JSONValue:
        """Normalize without redaction so commitments distinguish secret values."""

        return self._normalize(value, (), frozenset(), frozenset(), set())

    def _normalize(
        self,
        value: Any,
        path: tuple[str, ...],
        sensitive_paths: frozenset[str],
        sensitive_keys: frozenset[str],
        seen: set[int],
    ) -> JSONValue:
        if value is None or isinstance(value, (str, bool)):
            return value
        if isinstance(value, int):
            if -(2**53) + 1 <= value <= 2**53 - 1:
                return value
            return {"type": "integer", "decimal": str(value)}
        if isinstance(value, float):
            if math.isfinite(value):
                return value
            if math.isnan(value):
                label = "nan"
            elif value > 0:
                label = "positive-infinity"
            else:
                label = "negative-infinity"
            return {"type": "float", "value": label}
        if isinstance(value, Decimal):
            return {"type": "decimal", "value": str(value)}
        if isinstance(value, UUID):
            return {"type": "uuid", "value": str(value)}
        if isinstance(value, datetime):
            return {"type": "datetime", "value": value.isoformat()}
        if isinstance(value, date):
            return {"type": "date", "value": value.isoformat()}
        if isinstance(value, Enum):
            return self._normalize(value.value, path, sensitive_paths, sensitive_keys, seen)
        if isinstance(value, (bytes, bytearray)):
            digest = hashlib.sha256(bytes(value)).hexdigest()
            return {"type": "bytes", "sha256": digest}

        track_identity = isinstance(value, (Mapping, Sequence, set, frozenset)) or is_dataclass(
            value
        )
        value_id = id(value)
        if track_identity and value_id in seen:
            return {"type": "cycle"}
        if track_identity:
            seen.add(value_id)
        try:
            return self._normalize_container(value, path, sensitive_paths, sensitive_keys, seen)
        finally:
            if track_identity:
                seen.remove(value_id)

    def _normalize_container(
        self,
        value: Any,
        path: tuple[str, ...],
        sensitive_paths: frozenset[str],
        sensitive_keys: frozenset[str],
        seen: set[int],
    ) -> JSONValue:
        if isinstance(value, Mapping):
            sanitized: dict[str, JSONValue] = {}
            for raw_key, item in value.items():
                key = self._mapping_key(raw_key, path, seen)
                child_path = (*path, key.casefold())
                dotted_path = ".".join(child_path)
                if key.casefold() in sensitive_keys or dotted_path in sensitive_paths:
                    sanitized[key] = self.replacement
                else:
                    sanitized[key] = self._normalize(
                        item, child_path, sensitive_paths, sensitive_keys, seen
                    )
            return sanitized
        if is_dataclass(value) and not isinstance(value, type):
            return self._normalize(
                {item.name: getattr(value, item.name) for item in fields(value)},
                path,
                sensitive_paths,
                sensitive_keys,
                seen,
            )
        if isinstance(value, (set, frozenset)):
            normalized = [
                self._normalize(item, (*path, "set"), sensitive_paths, sensitive_keys, seen)
                for item in value
            ]
            return sorted(normalized, key=canonicalize)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            return [
                self._normalize(
                    item,
                    (*path, str(index)),
                    sensitive_paths,
                    sensitive_keys,
                    seen,
                )
                for index, item in enumerate(value)
            ]
        return {"type": f"{type(value).__module__}.{type(value).__qualname__}"}

    def _mapping_key(self, value: Any, path: tuple[str, ...], seen: set[int]) -> str:
        if isinstance(value, str):
            return value
        normalized = self._normalize(
            value,
            (*path, "<mapping-key>"),
            frozenset(),
            frozenset(),
            seen,
        )
        digest = hashlib.sha256(canonicalize(normalized)).hexdigest()
        type_name = f"{type(value).__module__}.{type(value).__qualname__}"
        return f"@glassbox-key:{type_name}:{digest}"


def digest_value(value: Any, *, policy: RedactionPolicy | None = None) -> str:
    """Commit a value using domain-separated SHA-256 without retaining plaintext."""

    active_policy = policy or RedactionPolicy()
    normalized_value = active_policy.normalize_for_digest(value)
    return hashlib.sha256(_DIGEST_DOMAIN + canonicalize(normalized_value)).hexdigest()
