"""Pure, dependency-free pricing capability shared by live and isolated execution."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def apply_replayable_pricing_policy(
    aggregate: dict[str, int | str],
) -> dict[str, int | str]:
    """Versioned pricing policy that materially consumes average order value."""

    order_count = aggregate["order_count"]
    average_order_value = aggregate["average_order_value"]
    assert isinstance(order_count, int)
    numeric_average = int(average_order_value)
    adjustment = min(order_count, 15) + min(numeric_average // 10, 5)
    return {
        "customer_id": aggregate["customer_id"],
        "recommended_price": 100 - adjustment,
        "currency": "USD",
    }


def pricing_policy_source_digest() -> str:
    """Commit the exact pure capability source copied into the OCI image."""

    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def pricing_policy_schema_digest() -> str:
    """Commit the policy's closed input/output schema without retaining values."""

    schema: dict[str, Any] = {
        "input": {
            "type": "object",
            "required": ["customer_id", "order_count", "average_order_value"],
            "properties": {
                "customer_id": {"type": "string"},
                "order_count": {"type": "integer"},
                "average_order_value": {"type": ["integer", "string"]},
            },
        },
        "output": {
            "type": "object",
            "required": ["customer_id", "recommended_price", "currency"],
            "properties": {
                "customer_id": {"type": "string"},
                "recommended_price": {"type": "integer"},
                "currency": {"const": "USD"},
            },
        },
    }
    encoded = json.dumps(schema, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


__all__ = [
    "apply_replayable_pricing_policy",
    "pricing_policy_schema_digest",
    "pricing_policy_source_digest",
]
