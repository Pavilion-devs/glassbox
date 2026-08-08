"""RFC 8785 canonical JSON serialization."""

from __future__ import annotations

from typing import Any

import rfc8785

from glassbox_dbom.errors import CanonicalizationError


def canonicalize(value: Any) -> bytes:
    """Return RFC 8785 canonical JSON bytes.

    RFC 8785 deliberately rejects values such as NaN, infinity, integers outside
    the interoperable JSON range, non-string object keys, and unsupported Python
    objects. They must never be silently stringified into digest material.
    """

    try:
        result = rfc8785.dumps(value)
    except (TypeError, ValueError, rfc8785.CanonicalizationError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    if not isinstance(result, bytes):
        raise CanonicalizationError("RFC 8785 implementation returned non-byte output")
    return result
