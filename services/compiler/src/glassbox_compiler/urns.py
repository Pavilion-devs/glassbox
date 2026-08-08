"""Verified, deterministic DataHub URN resolution."""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol

from glassbox_compiler.errors import CompilationError

_URN_PATTERN = re.compile(r"^urn:li:[A-Za-z][A-Za-z0-9]*:[^\s]+$")


class URNResolutionError(CompilationError):
    """Raised when URN candidates are malformed, ambiguous, or unverifiable."""


class URNSource(StrEnum):
    """Candidate origins in the binding GlassBox resolution order."""

    EXPLICIT_INSTRUMENTATION = "EXPLICIT_INSTRUMENTATION"
    DATAHUB_TOOL_RESULT = "DATAHUB_TOOL_RESULT"
    FRAMEWORK_ANNOTATION = "FRAMEWORK_ANNOTATION"
    QUERY_PARSE = "QUERY_PARSE"
    CONFIGURED_MAPPING = "CONFIGURED_MAPPING"


_SOURCE_PRIORITY = {
    URNSource.EXPLICIT_INSTRUMENTATION: 0,
    URNSource.DATAHUB_TOOL_RESULT: 1,
    URNSource.FRAMEWORK_ANNOTATION: 2,
    URNSource.QUERY_PARSE: 3,
    URNSource.CONFIGURED_MAPPING: 4,
}


class ResolutionStatus(StrEnum):
    """Outcome of a direct-read-backed resolution attempt."""

    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class URNCandidate:
    """An exact URN claim and the mechanism that produced it."""

    urn: str
    source: URNSource

    def __post_init__(self) -> None:
        if not _URN_PATTERN.fullmatch(self.urn):
            raise URNResolutionError(f"malformed DataHub URN candidate: {self.urn!r}")


@dataclass(frozen=True)
class ResolutionAttempt:
    """One direct existence check, retained without server error text."""

    urn: str
    source: URNSource
    exists: bool


@dataclass(frozen=True)
class URNResolution:
    """A verified resolution or an explicit unresolved result."""

    status: ResolutionStatus
    urn: str | None
    source: URNSource | None
    attempts: tuple[ResolutionAttempt, ...]


class URNLookup(Protocol):
    """Read-only DataHub existence boundary."""

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]: ...


class VerifiedURNResolver:
    """Resolve only exact URNs proven to exist through a direct entity read."""

    def __init__(self, backend: URNLookup) -> None:
        self._backend = backend
        self._cache: dict[str, bool] = {}

    def resolve(self, candidates: Sequence[URNCandidate]) -> URNResolution:
        unique = {(candidate.source, candidate.urn): candidate for candidate in candidates}
        ordered = sorted(
            unique.values(),
            key=lambda candidate: (_SOURCE_PRIORITY[candidate.source], candidate.urn),
        )
        attempts: list[ResolutionAttempt] = []
        for source in URNSource:
            at_priority = [candidate for candidate in ordered if candidate.source is source]
            verified: list[URNCandidate] = []
            for candidate in at_priority:
                exists = self._exists(candidate.urn)
                attempts.append(
                    ResolutionAttempt(urn=candidate.urn, source=candidate.source, exists=exists)
                )
                if exists:
                    verified.append(candidate)
            if len(verified) > 1:
                raise URNResolutionError(
                    f"ambiguous verified {source.value} URNs: "
                    + ", ".join(candidate.urn for candidate in verified)
                )
            if verified:
                winner = verified[0]
                return URNResolution(
                    status=ResolutionStatus.RESOLVED,
                    urn=winner.urn,
                    source=winner.source,
                    attempts=tuple(attempts),
                )
        return URNResolution(
            status=ResolutionStatus.UNRESOLVED,
            urn=None,
            source=None,
            attempts=tuple(attempts),
        )

    def _exists(self, urn: str) -> bool:
        cached = self._cache.get(urn)
        if cached is not None:
            return cached
        try:
            exists = bool(self._backend.direct_read_aspects(urn))
        except Exception as exc:
            raise URNResolutionError(
                f"DataHub direct-read failed while resolving {urn!r}: {type(exc).__name__}"
            ) from exc
        self._cache[urn] = exists
        return exists
