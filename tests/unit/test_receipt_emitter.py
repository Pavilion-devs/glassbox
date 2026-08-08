"""DataHub receipt emission boundary tests."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_datahub import (
    ReceiptEmissionError,
    ReceiptEmitter,
    merge_receipt_custom_properties,
    receipt_document_urn,
)
from glassbox_datahub import receipt_emitter as emitter_module
from glassbox_dbom import SigningKey, seal_receipt
from tests.helpers import receipt_payload


class FakeReceiptBackend:
    def __init__(
        self,
        *,
        change_second_urn: bool = False,
        wrong_urn: bool = False,
        aspects: tuple[str, ...] = ("documentInfo", "status"),
    ) -> None:
        self.change_second_urn = change_second_urn
        self.wrong_urn = wrong_urn
        self.aspects = aspects
        self.receipts: list[Mapping[str, Any]] = []

    def upsert_receipt(self, receipt: Mapping[str, Any]) -> str:
        self.receipts.append(receipt)
        urn = receipt_document_urn(str(receipt["receipt_id"]))
        if self.wrong_urn:
            return urn + ".wrong"
        if self.change_second_urn and len(self.receipts) == 2:
            return urn + ".duplicate"
        return urn

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        del urn
        return self.aspects


def _signed_receipt() -> dict[str, Any]:
    key = SigningKey("receipt-emitter-test", Ed25519PrivateKey.generate())
    return seal_receipt(receipt_payload(), signing_keys=(key,))


def test_verified_receipt_is_emitted_twice_and_directly_read_back() -> None:
    backend = FakeReceiptBackend()
    receipt = _signed_receipt()

    report = ReceiptEmitter(backend).emit_verified(receipt)

    assert report.valid
    assert report.receipt_id == receipt["receipt_id"]
    assert report.document_urn == receipt_document_urn(receipt["receipt_id"])
    assert report.aspect_names == ("documentInfo", "status")
    assert report.to_dict()["emissions"] == 2
    assert backend.receipts == [receipt, receipt]


def test_unsigned_receipt_requires_explicit_test_only_opt_out() -> None:
    receipt = seal_receipt(receipt_payload())
    backend = FakeReceiptBackend()

    with pytest.raises(ReceiptEmissionError, match="at least one valid signature"):
        ReceiptEmitter(backend).emit_verified(receipt)
    report = ReceiptEmitter(backend, require_signature=False).emit_verified(receipt)
    assert report.valid


def test_tampered_receipt_is_rejected_before_any_datahub_write() -> None:
    receipt = _signed_receipt()
    receipt["output"]["kind"] = "tampered"
    backend = FakeReceiptBackend()

    with pytest.raises(ReceiptEmissionError, match="refusing to emit invalid"):
        ReceiptEmitter(backend).emit_verified(receipt)
    assert backend.receipts == []


def test_non_idempotent_or_wrong_urn_is_rejected() -> None:
    receipt = _signed_receipt()
    with pytest.raises(ReceiptEmissionError, match="not idempotent"):
        ReceiptEmitter(FakeReceiptBackend(change_second_urn=True)).emit_verified(receipt)
    with pytest.raises(ReceiptEmissionError, match="did not equal expected"):
        ReceiptEmitter(FakeReceiptBackend(wrong_urn=True)).emit_verified(receipt)


def test_empty_direct_readback_is_not_success() -> None:
    with pytest.raises(ReceiptEmissionError, match="no persisted aspects"):
        ReceiptEmitter(FakeReceiptBackend(aspects=())).emit_verified(_signed_receipt())


def test_sealed_publication_is_reverified_without_an_additional_write() -> None:
    backend = FakeReceiptBackend()
    receipt = _signed_receipt()
    emitter = ReceiptEmitter(backend)
    emission = emitter.emit_verified(receipt)

    readback = emitter.verify_published(
        receipt,
        document_urn=emission.document_urn,
        aspect_names=emission.aspect_names,
    )

    assert readback.valid
    assert readback.aspect_names == emission.aspect_names
    assert backend.receipts == [receipt, receipt]


def test_zero_write_readback_fails_when_sealed_aspects_diverge() -> None:
    backend = FakeReceiptBackend()
    receipt = _signed_receipt()
    emitter = ReceiptEmitter(backend)
    emission = emitter.emit_verified(receipt)
    backend.aspects = ("documentInfo",)

    with pytest.raises(ReceiptEmissionError, match="diverged"):
        emitter.verify_published(
            receipt,
            document_urn=emission.document_urn,
            aspect_names=emission.aspect_names,
        )
    assert len(backend.receipts) == 2


def test_backend_exception_is_bounded_without_transport_details() -> None:
    class FailingBackend:
        def upsert_receipt(self, receipt: Mapping[str, Any]) -> str:
            del receipt
            raise ConnectionError("token=secret private-host")

        def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
            del urn
            raise AssertionError("readback must not run")

    with pytest.raises(ReceiptEmissionError) as failure:
        ReceiptEmitter(FailingBackend()).emit_verified(_signed_receipt())

    assert "ConnectionError" in str(failure.value)
    assert "secret" not in str(failure.value)
    assert "private-host" not in str(failure.value)


@pytest.mark.parametrize(
    "receipt_id",
    ["receipt:wrong", "gbx:receipt:sha256:abc", "gbx:receipt:sha256:" + "G" * 64],
)
def test_document_urn_rejects_malformed_receipt_ids(receipt_id: str) -> None:
    with pytest.raises(ReceiptEmissionError):
        receipt_document_urn(receipt_id)


def test_receipt_projection_helpers_preserve_references_without_raw_values() -> None:
    receipt = _signed_receipt()

    references = emitter_module._referenced_datahub_urns(receipt)
    summary = emitter_module._receipt_summary(receipt)

    assert references == [
        "urn:li:agentSkill:glassbox.pricing-analysis",
        "urn:li:aiAgent:glassbox.pricing-agent",
        "urn:li:api:glassbox.orders.lookup",
        "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)",
    ]
    assert "Run: run-pricing-001 (SUCCEEDED)" in summary
    assert "Evidence records: 1" in summary
    assert "Raw prompts" in summary


def test_receipt_republication_preserves_quarantine_and_unmanaged_properties() -> None:
    merged = merge_receipt_custom_properties(
        {
            "glassbox.invalidation_state": "STALE",
            "glassbox.receipt_id": "old-managed-value",
            "third.party.annotation": "preserve-me",
        },
        {
            "glassbox.receipt_id": "current-content-address",
            "glassbox.payload_digest": "a" * 64,
        },
    )

    assert merged["glassbox.invalidation_state"] == "STALE"
    assert merged["third.party.annotation"] == "preserve-me"
    assert merged["glassbox.receipt_id"] == "current-content-address"


@pytest.mark.parametrize(
    ("helper", "value", "key"),
    [
        (emitter_module._required_mapping, {"field": []}, "field"),
        (emitter_module._required_list, {"field": {}}, "field"),
        (emitter_module._required_string, {"field": ""}, "field"),
    ],
)
def test_receipt_projection_helpers_reject_wrong_shapes(
    helper: Any, value: Mapping[str, Any], key: str
) -> None:
    with pytest.raises(ReceiptEmissionError):
        helper(value, key)
