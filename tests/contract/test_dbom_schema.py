from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from glassbox_dbom import seal_receipt, validate_receipt, verify_receipt
from glassbox_dbom.errors import SchemaValidationError
from tests.helpers import receipt_payload

_FIXTURE_DIRECTORY = Path(__file__).parents[1] / "fixtures" / "dbom"


def test_reference_receipt_satisfies_dbom_0_1_schema() -> None:
    validate_receipt(seal_receipt(receipt_payload()))


def test_unknown_evidence_cannot_be_relabeled_observed_without_runtime_proof() -> None:
    payload = receipt_payload()
    evidence = payload["evidence"][0]
    evidence["source_span_id"] = None
    evidence["observed_at"] = None
    evidence["provenance"] = {
        "capture_method": "UNAVAILABLE",
        "rule_id": None,
        "confidence": None,
    }

    with pytest.raises(SchemaValidationError):
        seal_receipt(payload)


def test_inferred_evidence_requires_rule_and_confidence() -> None:
    payload = receipt_payload()
    evidence = payload["evidence"][0]
    evidence["state"] = "INFERRED"
    evidence["source_span_id"] = None
    evidence["observed_at"] = None
    evidence["provenance"] = {
        "capture_method": "QUERY_PARSE",
        "rule_id": None,
        "confidence": None,
    }

    with pytest.raises(SchemaValidationError):
        seal_receipt(payload)


def test_receipt_rejects_undeclared_top_level_properties() -> None:
    sealed = seal_receipt(receipt_payload())
    invalid = copy.deepcopy(sealed)
    invalid["truth_score"] = 1.0

    with pytest.raises(SchemaValidationError):
        validate_receipt(invalid)


def test_redacted_receipt_remains_valid() -> None:
    sealed = seal_receipt(receipt_payload())

    assert sealed["output"]["redacted"] is True
    assert sealed["evidence"][0]["redaction"]["status"] == "DIGEST_ONLY"
    validate_receipt(sealed)


def test_committed_positive_fixture_is_valid_and_verifiable() -> None:
    with (_FIXTURE_DIRECTORY / "valid-read-only.json").open(encoding="utf-8") as handle:
        receipt = json.load(handle)

    validate_receipt(receipt)
    assert verify_receipt(receipt).valid


def test_committed_tamper_vector_has_expected_integrity_failures() -> None:
    with (_FIXTURE_DIRECTORY / "tamper-output-digest.vector.json").open(encoding="utf-8") as handle:
        vector = json.load(handle)
    with (_FIXTURE_DIRECTORY / vector["base_fixture"]).open(encoding="utf-8") as handle:
        receipt = json.load(handle)

    digest = receipt["output"]["digest"]["value"]
    receipt["output"]["digest"]["value"] = ("0" if digest[0] != "0" else "1") + digest[1:]

    report = verify_receipt(receipt)
    for key, expected in vector["expected"].items():
        assert getattr(report, key) == expected
