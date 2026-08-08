"""Idempotent DataHub publication for verified DBOM receipt summaries."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from importlib import metadata
from typing import Any, Protocol

from glassbox_datahub.capability_probe import PINNED_DATAHUB_SDK_VERSION
from glassbox_dbom import SignerTrustMode, SignerTrustPolicy, verify_receipt


class ReceiptEmissionError(RuntimeError):
    """Raised when a receipt cannot be safely persisted and directly verified."""


@dataclass(frozen=True)
class ReceiptEmissionReport:
    """Evidence of deterministic emission and direct DataHub readback."""

    receipt_id: str
    document_urn: str
    aspect_names: tuple[str, ...]
    emissions: int = 2

    @property
    def valid(self) -> bool:
        return self.emissions == 2 and bool(self.aspect_names)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "receipt_id": self.receipt_id,
            "document_urn": self.document_urn,
            "aspect_names": list(self.aspect_names),
            "emissions": self.emissions,
        }


@dataclass(frozen=True)
class ReceiptReadbackReport:
    """Evidence that sealed receipt aspects still exist without performing a write."""

    receipt_id: str
    document_urn: str
    aspect_names: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return bool(self.aspect_names)


class ReceiptBackend(Protocol):
    """Narrow transport boundary for receipt publication."""

    def upsert_receipt(self, receipt: Mapping[str, Any]) -> str: ...

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]: ...


class ReceiptEmitter:
    """Verify, idempotently emit twice, and directly read back one receipt."""

    def __init__(
        self,
        backend: ReceiptBackend,
        *,
        require_signature: bool = True,
        signer_trust_policy: SignerTrustPolicy | None = None,
    ) -> None:
        self._backend = backend
        self._require_signature = require_signature
        self._signer_trust_policy = signer_trust_policy

    def emit_verified(
        self,
        receipt: Mapping[str, Any],
        *,
        trust_mode: SignerTrustMode = SignerTrustMode.ADMISSION,
    ) -> ReceiptEmissionReport:
        """Publish a receipt, using current-time admission unless state proved history."""

        self._verify_receipt(receipt, operation="emit", trust_mode=trust_mode)

        receipt_id = _required_string(receipt, "receipt_id")
        expected_urn = receipt_document_urn(receipt_id)
        try:
            first_urn = self._backend.upsert_receipt(receipt)
            second_urn = self._backend.upsert_receipt(receipt)
        except Exception as exc:
            raise ReceiptEmissionError(
                f"receipt backend write failed ({type(exc).__name__})"
            ) from exc
        if first_urn != second_urn:
            raise ReceiptEmissionError(
                f"receipt emission was not idempotent: {first_urn!r} != {second_urn!r}"
            )
        if first_urn != expected_urn:
            raise ReceiptEmissionError(
                f"emitted receipt URN {first_urn!r} did not equal expected {expected_urn!r}"
            )
        try:
            aspects = tuple(sorted(set(self._backend.direct_read_aspects(first_urn))))
        except Exception as exc:
            raise ReceiptEmissionError(
                f"receipt backend readback failed ({type(exc).__name__})"
            ) from exc
        if not aspects:
            raise ReceiptEmissionError("receipt direct readback returned no persisted aspects")
        return ReceiptEmissionReport(
            receipt_id=receipt_id,
            document_urn=first_urn,
            aspect_names=aspects,
        )

    def verify_published(
        self,
        receipt: Mapping[str, Any],
        *,
        document_urn: str,
        aspect_names: tuple[str, ...],
    ) -> ReceiptReadbackReport:
        """Directly verify sealed publication evidence without mutating DataHub."""

        self._verify_receipt(
            receipt,
            operation="verify",
            trust_mode=SignerTrustMode.HISTORICAL,
        )
        receipt_id = _required_string(receipt, "receipt_id")
        expected_urn = receipt_document_urn(receipt_id)
        if document_urn != expected_urn:
            raise ReceiptEmissionError("sealed publication URN does not match receipt identity")
        expected_aspects = tuple(sorted(set(aspect_names)))
        if not expected_aspects or expected_aspects != aspect_names:
            raise ReceiptEmissionError("sealed publication aspects are invalid")
        try:
            observed_aspects = tuple(sorted(set(self._backend.direct_read_aspects(document_urn))))
        except Exception as exc:
            raise ReceiptEmissionError(
                f"receipt backend readback failed ({type(exc).__name__})"
            ) from exc
        if not set(expected_aspects).issubset(observed_aspects):
            raise ReceiptEmissionError(
                "receipt direct readback diverged from sealed publication evidence"
            )
        return ReceiptReadbackReport(
            receipt_id=receipt_id,
            document_urn=document_urn,
            aspect_names=observed_aspects,
        )

    def _verify_receipt(
        self,
        receipt: Mapping[str, Any],
        *,
        operation: str,
        trust_mode: SignerTrustMode,
    ) -> None:
        if self._signer_trust_policy is not None:
            trust = self._signer_trust_policy.verify_receipt(
                receipt,
                mode=trust_mode,
            )
            if not trust.valid:
                codes = ",".join(trust.failure_codes) or "SIGNER_TRUST_FAILED"
                raise ReceiptEmissionError(
                    f"refusing to {operation} untrusted DBOM receipt ({codes})"
                )
            return
        verification = verify_receipt(receipt, require_signature=self._require_signature)
        if not verification.valid:
            details = "; ".join(verification.errors) or "verification failed"
            raise ReceiptEmissionError(f"refusing to {operation} invalid DBOM receipt: {details}")


class DataHubReceiptBackend:  # pragma: no cover - exercised by the live integration proof
    """Pinned stable-SDK implementation of the receipt transport boundary."""

    def __init__(
        self,
        *,
        server: str,
        token: str | None = None,
        expected_sdk_version: str = PINNED_DATAHUB_SDK_VERSION,
    ) -> None:
        from datahub.ingestion.graph.client import DataHubGraph
        from datahub.ingestion.graph.config import DatahubClientConfig
        from datahub.sdk.document import Document
        from datahub.sdk.main_client import DataHubClient

        self._graph = DataHubGraph(config=DatahubClientConfig(server=server, token=token))
        self._client = DataHubClient(graph=self._graph)
        self._Document = Document
        self._expected_sdk_version = expected_sdk_version
        self.sdk_version = metadata.version("acryl-datahub")

    def test_connection(self) -> None:
        self._graph.test_connection()
        if self.sdk_version != self._expected_sdk_version:
            raise ReceiptEmissionError(
                f"SDK drift: expected {self._expected_sdk_version}, found {self.sdk_version}"
            )

    def upsert_receipt(self, receipt: Mapping[str, Any]) -> str:
        receipt_id = _required_string(receipt, "receipt_id")
        digest = _receipt_digest(receipt_id)
        run = _required_mapping(receipt, "run")
        agent = _required_mapping(receipt, "agent")
        replay = _required_mapping(receipt, "replay")
        integrity = _required_mapping(receipt, "integrity")
        payload_digest = _required_mapping(integrity, "payload_digest")
        merkle_root = _required_mapping(integrity, "merkle_root")
        output = _required_mapping(receipt, "output")
        output_digest = _required_mapping(output, "digest")
        evidence = _required_list(receipt, "evidence")
        actions = _required_list(receipt, "actions")
        signatures = _required_list(integrity, "signatures")

        reference_urns = _referenced_datahub_urns(receipt)
        related_assets = [urn for urn in reference_urns if urn.startswith("urn:li:dataset:")]
        optional_properties: dict[str, str] = {}
        agent_urn = agent.get("datahub_urn")
        if isinstance(agent_urn, str):
            optional_properties["glassbox.agent_urn"] = agent_urn
        if reference_urns:
            optional_properties["glassbox.referenced_urns"] = ",".join(reference_urns)
        managed_properties = {
            "glassbox.spec_version": _required_string(receipt, "spec_version"),
            "glassbox.receipt_id": receipt_id,
            "glassbox.payload_digest": _required_string(payload_digest, "value"),
            "glassbox.merkle_root": _required_string(merkle_root, "value"),
            "glassbox.run_id": _required_string(run, "run_id"),
            "glassbox.trace_id": _required_string(run, "trace_id"),
            "glassbox.run_status": _required_string(run, "status"),
            "glassbox.agent_id": _required_string(agent, "id"),
            "glassbox.replay_eligibility": _required_string(replay, "eligibility"),
            "glassbox.output_digest": _required_string(output_digest, "value"),
            "glassbox.evidence_count": str(len(evidence)),
            "glassbox.action_count": str(len(actions)),
            "glassbox.signature_count": str(len(signatures)),
            "glassbox.compatibility_mode": "document-projection",
            "glassbox.native_entity_type": "decisionReceipt",
            **optional_properties,
        }
        existing_properties = self._existing_custom_properties(receipt_document_urn(receipt_id))
        document = self._Document.create_document(
            id=f"glassbox.receipt.{digest}",
            title=f"GlassBox Decision Receipt {digest[:12]}",
            text=_receipt_summary(receipt),
            subtype="Agent Decision Receipt",
            show_in_global_context=False,
            related_assets=related_assets,
            custom_properties=merge_receipt_custom_properties(
                existing_properties,
                managed_properties,
            ),
        )
        self._client.entities.upsert(document)
        return str(document.urn)

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        response = self._graph.get_entity_raw(urn)
        aspects = response.get("aspects")
        if not isinstance(aspects, dict):
            return ()
        return tuple(sorted(name for name, value in aspects.items() if value is not None))

    def _existing_custom_properties(self, urn: str) -> Mapping[str, str]:
        from datahub.metadata.schema_classes import DocumentInfoClass

        existing = self._graph.get_aspect(urn, DocumentInfoClass)
        if existing is None or existing.customProperties is None:
            return {}
        return existing.customProperties


def receipt_document_urn(receipt_id: str) -> str:
    """Return the deterministic stable-Core Document URN for a receipt ID."""

    return f"urn:li:document:glassbox.receipt.{_receipt_digest(receipt_id)}"


def merge_receipt_custom_properties(
    existing: Mapping[str, str], managed: Mapping[str, str]
) -> dict[str, str]:
    """Preserve quarantine and third-party properties while refreshing receipt facts."""

    return {**existing, **managed}


def _receipt_digest(receipt_id: str) -> str:
    prefix = "gbx:receipt:sha256:"
    if not receipt_id.startswith(prefix):
        raise ReceiptEmissionError("receipt_id is not a GlassBox SHA-256 content address")
    digest = receipt_id.removeprefix(prefix)
    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
        raise ReceiptEmissionError("receipt_id has an invalid SHA-256 digest")
    return digest


def _referenced_datahub_urns(receipt: Mapping[str, Any]) -> list[str]:
    urns: set[str] = set()
    agent = _required_mapping(receipt, "agent")
    _add_urn(urns, agent.get("datahub_urn"))
    for section in ("models", "skills", "tools", "evidence"):
        for item in _required_list(receipt, section):
            if isinstance(item, Mapping):
                _add_urn(urns, item.get("datahub_urn"))
    return sorted(urns)


def _add_urn(urns: set[str], value: object) -> None:
    if isinstance(value, str) and value.startswith("urn:li:"):
        urns.add(value)


def _receipt_summary(receipt: Mapping[str, Any]) -> str:
    run = _required_mapping(receipt, "run")
    agent = _required_mapping(receipt, "agent")
    replay = _required_mapping(receipt, "replay")
    evidence = _required_list(receipt, "evidence")
    actions = _required_list(receipt, "actions")
    return (
        "Content-addressed GlassBox DBOM summary. Raw prompts, tool payloads, evidence values, "
        "model outputs, credentials, and customer data are not stored here.\n\n"
        f"Run: {_required_string(run, 'run_id')} ({_required_string(run, 'status')})\n"
        f"Agent: {_required_string(agent, 'id')}\n"
        f"Evidence records: {len(evidence)}\n"
        f"Actions: {len(actions)}\n"
        f"Replay: {_required_string(replay, 'eligibility')} — "
        f"{_required_string(replay, 'reason')}"
    )


def _required_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    child = value.get(key)
    if not isinstance(child, Mapping):
        raise ReceiptEmissionError(f"receipt field {key!r} must be an object")
    return child


def _required_list(value: Mapping[str, Any], key: str) -> list[Any]:
    child = value.get(key)
    if not isinstance(child, list):
        raise ReceiptEmissionError(f"receipt field {key!r} must be an array")
    return child


def _required_string(value: Mapping[str, Any], key: str) -> str:
    child = value.get(key)
    if not isinstance(child, str) or not child:
        raise ReceiptEmissionError(f"receipt field {key!r} must be a non-empty string")
    return child
