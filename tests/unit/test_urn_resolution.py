"""Verified DataHub URN resolution tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from examples.deterministic_pricing_agent import ORDERS_URN, build_pricing_agent

from glassbox import GlassBox, InMemorySink
from glassbox_compiler import (
    CompilationProfile,
    Environment,
    ResolutionStatus,
    URNCandidate,
    URNResolutionError,
    URNSource,
    VerifiedURNResolver,
    compile_events,
)


class FakeLookup:
    def __init__(self, existing: set[str], *, error: Exception | None = None) -> None:
        self.existing = existing
        self.error = error
        self.calls: list[str] = []

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        self.calls.append(urn)
        if self.error is not None:
            raise self.error
        return ("key",) if urn in self.existing else ()


def test_resolution_uses_first_verified_source_not_first_unverified_claim() -> None:
    tool_urn = "urn:li:dataset:(urn:li:dataPlatform:postgres,verified.orders,PROD)"
    configured_urn = "urn:li:dataset:(urn:li:dataPlatform:postgres,configured.orders,PROD)"
    backend = FakeLookup({tool_urn, configured_urn})
    resolver = VerifiedURNResolver(backend)

    result = resolver.resolve(
        (
            URNCandidate(ORDERS_URN, URNSource.EXPLICIT_INSTRUMENTATION),
            URNCandidate(configured_urn, URNSource.CONFIGURED_MAPPING),
            URNCandidate(tool_urn, URNSource.DATAHUB_TOOL_RESULT),
        )
    )

    assert result.status is ResolutionStatus.RESOLVED
    assert result.urn == tool_urn
    assert result.source is URNSource.DATAHUB_TOOL_RESULT
    assert [attempt.exists for attempt in result.attempts] == [False, True]
    assert configured_urn not in backend.calls


def test_unresolved_result_is_explicit_and_lookup_is_cached() -> None:
    backend = FakeLookup(set())
    resolver = VerifiedURNResolver(backend)
    candidate = URNCandidate(ORDERS_URN, URNSource.EXPLICIT_INSTRUMENTATION)

    first = resolver.resolve((candidate, candidate))
    second = resolver.resolve((candidate,))

    assert first.status is ResolutionStatus.UNRESOLVED
    assert first.urn is None
    assert second.status is ResolutionStatus.UNRESOLVED
    assert backend.calls == [ORDERS_URN]


def test_ambiguous_same_priority_claims_fail_closed() -> None:
    other = "urn:li:dataset:(urn:li:dataPlatform:postgres,other.orders,PROD)"
    resolver = VerifiedURNResolver(FakeLookup({ORDERS_URN, other}))

    with pytest.raises(URNResolutionError, match="ambiguous verified"):
        resolver.resolve(
            (
                URNCandidate(ORDERS_URN, URNSource.QUERY_PARSE),
                URNCandidate(other, URNSource.QUERY_PARSE),
            )
        )


def test_malformed_urn_and_lookup_failures_are_sanitized_errors() -> None:
    with pytest.raises(URNResolutionError, match="malformed"):
        URNCandidate("orders", URNSource.CONFIGURED_MAPPING)

    resolver = VerifiedURNResolver(FakeLookup(set(), error=RuntimeError("secret-server-text")))
    with pytest.raises(URNResolutionError) as caught:
        resolver.resolve((URNCandidate(ORDERS_URN, URNSource.EXPLICIT_INSTRUMENTATION),))
    assert "RuntimeError" in str(caught.value)
    assert "secret-server-text" not in str(caught.value)


def test_compiler_drops_unverified_urn_but_preserves_evidence_and_diagnostic() -> None:
    sink = InMemorySink()
    build_pricing_agent(GlassBox(sink))("synthetic-resolution-customer")
    profile = CompilationProfile(
        environment=Environment.DEV,
        output_kind="recommendation",
        output_mime_type="application/json",
        urn_resolver=VerifiedURNResolver(FakeLookup(set())),
    )

    receipt = compile_events(sink.events, profile=profile)

    assert receipt["evidence"][0]["state"] == "OBSERVED"
    assert receipt["evidence"][0]["datahub_urn"] is None
    assert receipt["extensions"]["glassbox.compiler.urn_resolutions"] == [
        {
            "evidence_id": receipt["evidence"][0]["evidence_id"],
            "status": "UNRESOLVED",
            "source": None,
            "attempt_count": 1,
        }
    ]


def test_compiler_keeps_only_a_directly_verified_evidence_urn() -> None:
    sink = InMemorySink()
    build_pricing_agent(GlassBox(sink))("synthetic-resolution-customer")
    profile = CompilationProfile(
        environment=Environment.DEV,
        output_kind="recommendation",
        output_mime_type="application/json",
        urn_resolver=VerifiedURNResolver(FakeLookup({ORDERS_URN})),
    )

    receipt: Mapping[str, Any] = compile_events(sink.events, profile=profile)
    assert receipt["evidence"][0]["datahub_urn"] == ORDERS_URN
    assert receipt["extensions"]["glassbox.compiler.urn_resolutions"][0]["status"] == "RESOLVED"
