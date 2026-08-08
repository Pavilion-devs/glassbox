from __future__ import annotations

import math

import pytest
from hypothesis import given
from hypothesis import strategies as st

import glassbox_dbom.canonical as canonical_module
from glassbox_dbom.canonical import canonicalize
from glassbox_dbom.errors import CanonicalizationError


def test_object_key_order_does_not_change_canonical_bytes() -> None:
    assert canonicalize({"z": 1, "a": 2}) == canonicalize({"a": 2, "z": 1})


def test_array_order_remains_semantically_significant() -> None:
    assert canonicalize(["first", "second"]) != canonicalize(["second", "first"])


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_numbers_are_rejected(value: float) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize({"unsafe": value})


@given(st.dictionaries(st.text(min_size=1), st.integers(min_value=-1000, max_value=1000)))
def test_canonicalization_is_idempotent(value: dict[str, int]) -> None:
    first = canonicalize(value)
    second = canonicalize(value)
    assert first == second


def test_non_byte_canonicalizer_output_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(canonical_module.rfc8785, "dumps", lambda value: "not-bytes")

    with pytest.raises(CanonicalizationError, match="non-byte"):
        canonicalize({"safe": True})
