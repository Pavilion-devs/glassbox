"""Real, bounded DataHub connection and permission verification."""

from __future__ import annotations

from importlib import metadata
from typing import Any
from urllib.parse import urlparse

from glassbox_datahub.capability_probe import PINNED_DATAHUB_SDK_VERSION

_PROBE_DOCUMENT_ID = "glassbox.connection.probe"


class DataHubConnectionTestError(RuntimeError):
    """Bounded test failure that never carries a remote response or credential."""

    def __init__(self, stage: str, failure_type: str) -> None:
        super().__init__(f"{stage}: {failure_type}")
        self.stage = stage
        self.failure_type = failure_type


class DataHubPublicationReadbackVerifier:  # pragma: no cover - live SDK boundary
    """Freshly prove that a deterministic receipt Document still exists in DataHub."""

    def verify(self, *, server_url: str, token: str, receipt_id: str) -> dict[str, Any]:
        from glassbox_datahub import DataHubReceiptBackend, receipt_document_urn

        document_urn = receipt_document_urn(receipt_id)
        try:
            backend = DataHubReceiptBackend(server=server_url, token=token)
            backend.test_connection()
            aspect_names = tuple(sorted(set(backend.direct_read_aspects(document_urn))))
        except Exception as exc:
            raise DataHubConnectionTestError(
                "PUBLICATION_READBACK",
                type(exc).__name__,
            ) from exc
        if not aspect_names:
            raise DataHubConnectionTestError("PUBLICATION_READBACK", "DocumentNotFound")
        return {
            "contract_version": "glassbox.publication-readback.v1",
            "receipt_id": receipt_id,
            "document_urn": document_urn,
            "verification_state": "VERIFIED_NOW",
            "aspect_names": list(aspect_names),
            "aspect_count": len(aspect_names),
            "raw_content_returned": False,
        }


def normalize_datahub_url(value: str, *, label: str) -> str:
    selected = value.strip().rstrip("/")
    parsed = urlparse(selected)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(f"{label} must be an HTTP(S) origin without credentials or a path")
    return selected


class DataHubConnectionTester:  # pragma: no cover - live SDK boundary
    """Prove reachability and optionally prove write/readback permission."""

    def test(self, *, server_url: str, token: str, write_proof: bool) -> dict[str, Any]:
        from datahub.ingestion.graph.client import DataHubGraph
        from datahub.ingestion.graph.config import DatahubClientConfig

        if not token:
            raise ValueError("DataHub service-account token is required")
        server_url = normalize_datahub_url(server_url, label="DataHub GMS URL")
        sdk_version = metadata.version("acryl-datahub")
        if sdk_version != PINNED_DATAHUB_SDK_VERSION:
            raise DataHubConnectionTestError("SDK_COMPATIBILITY", "SdkVersionMismatch")
        graph = DataHubGraph(config=DatahubClientConfig(server=server_url, token=token))
        try:
            graph.test_connection()
            config = graph.get_config()
        except Exception as exc:
            raise DataHubConnectionTestError("CONNECTION", type(exc).__name__) from exc

        report: dict[str, Any] = {
            "contract_version": "glassbox.datahub-connection.v1",
            "connection": "PROVEN",
            "authentication": "PROVEN",
            "sdk_compatibility": "PROVEN",
            "sdk_version": sdk_version,
            "server_version": _server_version(config),
            "write_proof": "UNVERIFIED",
            "probe_document_urn": None,
            "raw_content_returned": False,
        }
        if not write_proof:
            return report

        try:
            from datahub.sdk.document import Document
            from datahub.sdk.main_client import DataHubClient

            client = DataHubClient(graph=graph)
            document = Document.create_document(
                id=_PROBE_DOCUMENT_ID,
                title="GlassBox connection permission proof",
                text=(
                    "Synthetic, idempotent control-plane probe. Contains no credential, "
                    "customer record, prompt, model output, or agent payload."
                ),
                subtype="GlassBox Connection Probe",
                show_in_global_context=False,
                custom_properties={
                    "glassbox.probe_contract": "glassbox.datahub-connection.v1",
                    "glassbox.synthetic": "true",
                },
            )
            client.entities.upsert(document)
            urn = str(document.urn)
            raw = graph.get_entity_raw(urn)
            aspects = raw.get("aspects") if isinstance(raw, dict) else None
            if not isinstance(aspects, dict) or not any(
                value is not None for value in aspects.values()
            ):
                raise RuntimeError("direct readback returned no persisted aspects")
        except Exception as exc:
            raise DataHubConnectionTestError("WRITE_READBACK", type(exc).__name__) from exc
        report["write_proof"] = "PROVEN"
        report["probe_document_urn"] = urn
        return report


def _server_version(config: Any) -> str | None:
    if not isinstance(config, dict):
        return None
    candidates = (
        config.get("datahub", {}).get("version")
        if isinstance(config.get("datahub"), dict)
        else None,
        config.get("versions", {}).get("acryldata/datahub")
        if isinstance(config.get("versions"), dict)
        else None,
        config.get("version"),
    )
    return next((value for value in candidates if isinstance(value, str) and value), None)
