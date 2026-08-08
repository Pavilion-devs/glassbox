"""Idempotent DataHub Core projection for verified replay supersession records."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Protocol

from glassbox_datahub.capability_probe import PINNED_DATAHUB_SDK_VERSION
from glassbox_datahub.receipt_emitter import receipt_document_urn
from glassbox_replay import SupersessionRecord


class SupersessionEmissionError(RuntimeError):
    """Raised when DataHub does not preserve or prove the supersession projection."""


@dataclass(frozen=True)
class SupersessionReadback:
    """Direct server readback of the projection fields and persisted aspects."""

    properties: Mapping[str, str]
    aspect_names: tuple[str, ...]


@dataclass(frozen=True)
class SupersessionEmissionReport:
    """Evidence of idempotent double-write and exact direct readback."""

    supersession_id: str
    document_urn: str
    aspect_names: tuple[str, ...]
    verified_property_count: int
    emissions: int = 2

    @property
    def valid(self) -> bool:
        return (
            self.emissions == 2
            and self.verified_property_count == len(_MANAGED_KEYS)
            and bool(self.aspect_names)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "supersession_id": self.supersession_id,
            "document_urn": self.document_urn,
            "aspect_names": list(self.aspect_names),
            "verified_property_count": self.verified_property_count,
            "emissions": self.emissions,
        }


class SupersessionBackend(Protocol):
    """Narrow transport boundary for a separate, history-preserving relation record."""

    def upsert_supersession(self, record: SupersessionRecord) -> str: ...

    def direct_read_supersession(self, urn: str) -> SupersessionReadback: ...


class SupersessionEmitter:
    """Double-write one verified record and require exact direct server readback."""

    def __init__(self, backend: SupersessionBackend) -> None:
        self._backend = backend

    def emit_verified(self, record: SupersessionRecord) -> SupersessionEmissionReport:
        if not record.valid:
            raise SupersessionEmissionError("refusing invalid supersession content address")
        expected_urn = supersession_document_urn(record.supersession_id)
        first = self._backend.upsert_supersession(record)
        second = self._backend.upsert_supersession(record)
        if first != second:
            raise SupersessionEmissionError("supersession emission was not idempotent")
        if first != expected_urn:
            raise SupersessionEmissionError("supersession backend returned an unexpected URN")
        readback = self._backend.direct_read_supersession(first)
        expected = supersession_properties(record)
        mismatches = sorted(
            key for key, value in expected.items() if readback.properties.get(key) != value
        )
        if mismatches:
            raise SupersessionEmissionError(
                "supersession direct readback mismatch: " + ", ".join(mismatches)
            )
        if not readback.aspect_names:
            raise SupersessionEmissionError("supersession direct readback returned no aspects")
        return SupersessionEmissionReport(
            supersession_id=record.supersession_id,
            document_urn=first,
            aspect_names=readback.aspect_names,
            verified_property_count=len(expected),
        )


class DataHubSupersessionBackend:  # pragma: no cover - live integration boundary
    """Pinned SDK Document projection; source and replay receipt Documents are untouched."""

    def __init__(
        self,
        *,
        server: str,
        token: str | None = None,
        expected_sdk_version: str = PINNED_DATAHUB_SDK_VERSION,
    ) -> None:
        from datahub.ingestion.graph.client import DataHubGraph
        from datahub.ingestion.graph.config import DatahubClientConfig
        from datahub.metadata.schema_classes import DocumentInfoClass
        from datahub.sdk.document import Document
        from datahub.sdk.main_client import DataHubClient

        self._graph = DataHubGraph(config=DatahubClientConfig(server=server, token=token))
        self._client = DataHubClient(graph=self._graph)
        self._Document = Document
        self._DocumentInfo = DocumentInfoClass
        self._expected_sdk_version = expected_sdk_version
        self.sdk_version = metadata.version("acryl-datahub")

    def test_connection(self) -> None:
        self._graph.test_connection()
        if self.sdk_version != self._expected_sdk_version:
            raise SupersessionEmissionError(
                f"SDK drift: expected {self._expected_sdk_version}, found {self.sdk_version}"
            )

    def upsert_supersession(self, record: SupersessionRecord) -> str:
        digest = _supersession_digest(record.supersession_id)
        urn = supersession_document_urn(record.supersession_id)
        existing = self._graph.get_aspect(urn, self._DocumentInfo)
        existing_properties = (
            existing.customProperties
            if existing is not None and existing.customProperties is not None
            else {}
        )
        document = self._Document.create_document(
            id=f"glassbox.replay.supersession.{digest}",
            title=f"GlassBox Replay Supersession {digest[:12]}",
            text=_summary(record),
            subtype="Agent Decision Replay Supersession",
            show_in_global_context=False,
            related_assets=[],
            custom_properties={**existing_properties, **supersession_properties(record)},
        )
        self._client.entities.upsert(document)
        return str(document.urn)

    def direct_read_supersession(self, urn: str) -> SupersessionReadback:
        raw = self._graph.get_entity_raw(urn)
        aspects = raw.get("aspects")
        aspect_names = (
            tuple(sorted(key for key, value in aspects.items() if value is not None))
            if isinstance(aspects, dict)
            else ()
        )
        info = self._graph.get_aspect(urn, self._DocumentInfo)
        properties = (
            info.customProperties if info is not None and info.customProperties is not None else {}
        )
        return SupersessionReadback(properties=properties, aspect_names=aspect_names)


def supersession_properties(record: SupersessionRecord) -> dict[str, str]:
    """Return the complete managed, digest-only DataHub projection."""

    return {
        "glassbox.supersession_id": record.supersession_id,
        "glassbox.supersession_relation": record.relation,
        "glassbox.supersession_policy_version": record.policy_version,
        "glassbox.supersession_created_at": record.created_at,
        "glassbox.source_receipt_id": record.source_receipt_id,
        "glassbox.source_receipt_urn": receipt_document_urn(record.source_receipt_id),
        "glassbox.replay_receipt_id": record.replay_receipt_id,
        "glassbox.replay_receipt_urn": receipt_document_urn(record.replay_receipt_id),
        "glassbox.replay_bundle_id": record.bundle_id,
        "glassbox.replay_plan_id": record.plan_id,
        "glassbox.replay_execution_id": record.execution_id,
        "glassbox.replay_diff_id": record.diff_id,
        "glassbox.replay_semantic_method": record.semantic_method,
        "glassbox.replay_semantic_policy_id": record.semantic_policy_id,
        "glassbox.replay_semantic_rule_id": record.semantic_rule_id,
        "glassbox.replay_semantic_rule_version": record.semantic_rule_version,
        "glassbox.replay_semantic_result": record.semantic_result,
        "glassbox.replay_semantic_exact_match": str(record.semantic_exact_match).lower(),
        "glassbox.replay_structural_change_count": str(record.structural_change_count),
    }


def supersession_document_urn(supersession_id: str) -> str:
    """Return the deterministic DataHub Core Document URN for the relation record."""

    return f"urn:li:document:glassbox.replay.supersession.{_supersession_digest(supersession_id)}"


def _supersession_digest(value: str) -> str:
    prefix = "gbx:replay-supersession:sha256:"
    if not value.startswith(prefix):
        raise SupersessionEmissionError("supersession_id has an invalid content-address type")
    digest = value.removeprefix(prefix)
    if len(digest) != 64 or any(item not in "0123456789abcdef" for item in digest):
        raise SupersessionEmissionError("supersession_id has an invalid SHA-256 digest")
    return digest


def _summary(record: SupersessionRecord) -> str:
    return (
        "Content-addressed GlassBox replay supersession. This relation preserves both DBOMs "
        "and stores no raw prompts, evidence, tool payloads, or outputs.\n\n"
        f"Source receipt: {record.source_receipt_id}\n"
        f"Replay receipt: {record.replay_receipt_id}\n"
        f"Diff: {record.diff_id}\n"
        f"Deterministic semantic result: {record.semantic_result}\n"
        f"Semantic policy: {record.semantic_policy_id}"
    )


_MANAGED_KEYS = frozenset(
    {
        "glassbox.supersession_id",
        "glassbox.supersession_relation",
        "glassbox.supersession_policy_version",
        "glassbox.supersession_created_at",
        "glassbox.source_receipt_id",
        "glassbox.source_receipt_urn",
        "glassbox.replay_receipt_id",
        "glassbox.replay_receipt_urn",
        "glassbox.replay_bundle_id",
        "glassbox.replay_plan_id",
        "glassbox.replay_execution_id",
        "glassbox.replay_diff_id",
        "glassbox.replay_semantic_method",
        "glassbox.replay_semantic_policy_id",
        "glassbox.replay_semantic_rule_id",
        "glassbox.replay_semantic_rule_version",
        "glassbox.replay_semantic_result",
        "glassbox.replay_semantic_exact_match",
        "glassbox.replay_structural_change_count",
    }
)


__all__ = [
    "DataHubSupersessionBackend",
    "SupersessionBackend",
    "SupersessionEmissionError",
    "SupersessionEmissionReport",
    "SupersessionEmitter",
    "SupersessionReadback",
    "supersession_document_urn",
    "supersession_properties",
]
