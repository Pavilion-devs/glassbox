from __future__ import annotations

import copy
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import glassbox_invalidation.state_transfer as transfer_module
from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    seal_receipt,
    signing_key_fingerprint,
    signing_key_public_key,
)
from glassbox_invalidation import (
    SQLITE_STATE_SCHEMA_VERSION,
    SQLiteInvalidationStore,
    StateTransferError,
    build_state_transfer_bundle,
    load_state_transfer_bundle,
    load_state_transfer_schema,
    verify_state_transfer_bundle,
    write_state_transfer_bundle,
)
from tests.helpers import receipt_payload


def _key(key_id: str) -> SigningKey:
    return SigningKey(key_id, Ed25519PrivateKey.generate())


def _trusted(
    key: SigningKey,
    *,
    status: SignerStatus = SignerStatus.ACTIVE,
    not_before: str = "2020-01-01T00:00:00Z",
    not_after: str | None = "2100-01-01T00:00:00Z",
) -> TrustedSigner:
    return TrustedSigner(
        key_id=key.key_id,
        public_key=signing_key_public_key(key),
        public_key_sha256=signing_key_fingerprint(key),
        status=status,
        not_before=not_before,
        not_after=not_after,
    )


def _policy(
    signer: TrustedSigner,
    policy_id: str,
) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id=policy_id,
        minimum_trusted_signatures=1,
        signers=(signer,),
    )


@pytest.fixture
def transfer_context(
    tmp_path: Path,
) -> tuple[
    SQLiteInvalidationStore,
    dict[str, Any],
    SignerTrustPolicy,
    SignerTrustPolicy,
    SigningKey,
]:
    receipt_key = _key("adversarial-receipt")
    transfer_key = _key("adversarial-transfer")
    receipt_policy = _policy(_trusted(receipt_key), "adversarial-receipts-v1")
    transfer_policy = _policy(_trusted(transfer_key), "adversarial-transfers-v1")
    store = SQLiteInvalidationStore(
        tmp_path / "adversarial-source.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    store.register(seal_receipt(receipt_payload(), signing_keys=(receipt_key,)))
    bundle = build_state_transfer_bundle(
        store,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(transfer_key,),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    return store, bundle, receipt_policy, transfer_policy, transfer_key


@pytest.mark.parametrize(
    ("mutation", "error"),
    [
        (lambda value: value.update({"integrity": {}}), "SIGNATURE_REQUIRED"),
        (
            lambda value: value["source"]["counts"].update({"dependencies": 99}),
            "RECEIPT_SET_INVALID",
        ),
        (
            lambda value: value["operational_archive"].update(
                {"receipt_publication_tasks": "not-an-array"}
            ),
            "ARCHIVE_COUNTS_INVALID",
        ),
        (
            lambda value: value["receipts"][0]["field_lineage"].update({"coverage": "UNPROVEN"}),
            "RECEIPT_SET_INVALID",
        ),
        (
            lambda value: value["receipts"][0].update({"superseded_by": 7}),
            "RECEIPT_SET_INVALID",
        ),
        (
            lambda value: value["receipts"][0]["receipt"]["extensions"].update(
                {"not_json": float("nan")}
            ),
            "PAYLOAD_CANONICALIZATION_INVALID",
        ),
    ],
)
def test_verifier_returns_bounded_failures_for_malformed_bundle_sections(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
    mutation: Any,
    error: str,
) -> None:
    _, bundle, receipt_policy, transfer_policy, _ = transfer_context
    malformed = copy.deepcopy(bundle)
    mutation(malformed)

    report = verify_state_transfer_bundle(
        malformed,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )

    assert not report.valid
    assert error in report.errors
    assert report.to_dict()["raw_content_returned"] is False


@pytest.mark.parametrize(
    ("policy_factory", "reason"),
    [
        (
            lambda key, signer: _policy(
                _trusted(_key(key.key_id)),
                "public-key-mismatch",
            ),
            "PUBLIC_KEY_MISMATCH",
        ),
        (
            lambda key, signer: _policy(
                TrustedSigner(
                    key_id=signer.key_id,
                    public_key=signer.public_key,
                    public_key_sha256=signer.public_key_sha256,
                    status=SignerStatus.REVOKED,
                    not_before=signer.not_before,
                    not_after=signer.not_after,
                ),
                "revoked-transfer",
            ),
            "SIGNER_REVOKED",
        ),
        (
            lambda key, signer: _policy(
                TrustedSigner(
                    key_id=signer.key_id,
                    public_key=signer.public_key,
                    public_key_sha256=signer.public_key_sha256,
                    status=SignerStatus.RETIRED,
                    not_before=signer.not_before,
                    not_after=signer.not_after,
                ),
                "retired-transfer",
            ),
            "SIGNER_RETIRED",
        ),
        (
            lambda key, signer: _policy(
                TrustedSigner(
                    key_id=signer.key_id,
                    public_key=signer.public_key,
                    public_key_sha256=signer.public_key_sha256,
                    status=SignerStatus.ACTIVE,
                    not_before="2099-01-01T00:00:00Z",
                    not_after="2100-01-01T00:00:00Z",
                ),
                "future-transfer",
            ),
            "BEFORE_VALIDITY_WINDOW",
        ),
        (
            lambda key, signer: _policy(
                TrustedSigner(
                    key_id=signer.key_id,
                    public_key=signer.public_key,
                    public_key_sha256=signer.public_key_sha256,
                    status=SignerStatus.ACTIVE,
                    not_before="2020-01-01T00:00:00Z",
                    not_after="2025-01-01T00:00:00Z",
                ),
                "expired-transfer",
            ),
            "AFTER_VALIDITY_WINDOW",
        ),
    ],
)
def test_transfer_signature_lifecycle_reasons_are_explicit_and_raw_free(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
    policy_factory: Any,
    reason: str,
) -> None:
    _, bundle, receipt_policy, transfer_policy, transfer_key = transfer_context
    policy = policy_factory(transfer_key, transfer_policy.signers[0])

    report = verify_state_transfer_bundle(
        bundle,
        bundle_trust_policy=policy,
        receipt_trust_policy=receipt_policy,
        evaluated_at=datetime(2026, 8, 7, tzinfo=UTC),
    )

    assert not report.valid
    assert report.signatures[0].cryptographically_valid
    assert not report.signatures[0].trusted
    assert report.signatures[0].reason == reason


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        (
            lambda signatures: signatures[0].update(
                {
                    "value": (
                        ("A" if signatures[0]["value"][0] != "A" else "B")
                        + signatures[0]["value"][1:]
                    )
                }
            ),
            "SIGNATURE_INVALID",
        ),
        (lambda signatures: signatures[0].update({"algorithm": "RSA"}), "SIGNATURE_INVALID"),
        (lambda signatures: signatures.append(copy.deepcopy(signatures[0])), "DUPLICATE_KEY_ID"),
        (lambda signatures: signatures.append("malformed"), "SIGNATURE_MALFORMED"),
        (lambda signatures: signatures[0].update({"public_key": "A" * 43}), "SIGNATURE_INVALID"),
    ],
)
def test_malformed_transfer_signatures_fail_closed(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
    mutation: Any,
    reason: str,
) -> None:
    _, bundle, receipt_policy, transfer_policy, _ = transfer_context
    malformed = copy.deepcopy(bundle)
    signatures = malformed["integrity"]["signatures"]
    mutation(signatures)

    report = verify_state_transfer_bundle(
        malformed,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )

    assert not report.valid
    assert reason in {item.reason for item in report.signatures}


def test_build_rejects_invalid_export_parameters_and_disappearing_receipt(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _, receipt_policy, transfer_policy, transfer_key = transfer_context
    common = {
        "source_schema_version": SQLITE_STATE_SCHEMA_VERSION,
        "bundle_trust_policy": transfer_policy,
        "receipt_trust_policy": receipt_policy,
    }
    with pytest.raises(StateTransferError, match="engine"):
        build_state_transfer_bundle(
            store,
            source_engine="MYSQL",
            signing_keys=(transfer_key,),
            **common,
        )
    with pytest.raises(StateTransferError, match="schema version"):
        build_state_transfer_bundle(
            store,
            source_engine="SQLITE",
            source_schema_version="",
            signing_keys=(transfer_key,),
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=receipt_policy,
        )
    with pytest.raises(StateTransferError, match="at least one"):
        build_state_transfer_bundle(
            store,
            source_engine="SQLITE",
            signing_keys=(),
            **common,
        )
    with pytest.raises(StateTransferError, match="exceeds"):
        build_state_transfer_bundle(
            store,
            source_engine="SQLITE",
            signing_keys=tuple(transfer_key for _ in range(17)),
            **common,
        )
    with pytest.raises(StateTransferError, match="unique"):
        build_state_transfer_bundle(
            store,
            source_engine="SQLITE",
            signing_keys=(transfer_key, transfer_key),
            **common,
        )
    monkeypatch.setattr(store, "get_receipt", lambda receipt_id: None)
    with pytest.raises(StateTransferError, match="disappeared"):
        build_state_transfer_bundle(
            store,
            source_engine="SQLITE",
            signing_keys=(transfer_key,),
            **common,
        )


def test_file_and_schema_loaders_reject_unavailable_nonregular_empty_and_invalid_inputs(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
    tmp_path: Path,
) -> None:
    del transfer_context
    with pytest.raises(StateTransferError, match="unavailable"):
        load_state_transfer_bundle(tmp_path / "missing.json")
    with pytest.raises(StateTransferError, match="regular file"):
        load_state_transfer_bundle(tmp_path)
    empty = tmp_path / "empty.json"
    empty.touch()
    with pytest.raises(StateTransferError, match="size"):
        load_state_transfer_bundle(empty)
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{", encoding="utf-8")
    with pytest.raises(StateTransferError, match="valid JSON"):
        load_state_transfer_bundle(invalid_json)

    schema = tmp_path / "schema.json"
    schema.write_text(json.dumps({"type": "object"}), encoding="utf-8")
    assert load_state_transfer_schema(schema) == {"type": "object"}
    schema.write_text("not-json", encoding="utf-8")
    with pytest.raises(StateTransferError, match="schema is not valid JSON"):
        load_state_transfer_schema(schema)
    schema.write_text("[]", encoding="utf-8")
    with pytest.raises(StateTransferError, match="schema root"):
        load_state_transfer_schema(schema)


def test_writer_rejects_missing_parent_and_size_limit_then_cleans_failed_write(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, bundle, _, _, _ = transfer_context
    with pytest.raises(StateTransferError, match="parent directory"):
        write_state_transfer_bundle(tmp_path / "missing" / "bundle.json", bundle)

    monkeypatch.setattr(transfer_module, "_MAX_BUNDLE_BYTES", 1)
    with pytest.raises(StateTransferError, match="file-size limit"):
        write_state_transfer_bundle(tmp_path / "too-large.json", bundle)
    monkeypatch.undo()

    def fail_write(descriptor: int, value: bytes | memoryview[Any]) -> int:
        del descriptor, value
        raise OSError("synthetic write failure")

    monkeypatch.setattr(os, "write", fail_write)
    target = tmp_path / "write-failure.json"
    with pytest.raises(StateTransferError, match="write failed"):
        write_state_transfer_bundle(target, bundle)
    assert not target.exists()


def test_reader_detects_changed_size_and_read_failure(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, bundle, _, _, _ = transfer_context
    path = tmp_path / "read-race.json"
    write_state_transfer_bundle(path, bundle)
    original_fstat = os.fstat

    def changed_size(descriptor: int) -> SimpleNamespace:
        metadata = original_fstat(descriptor)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_size=metadata.st_size + 1,
        )

    monkeypatch.setattr(os, "fstat", changed_size)
    with pytest.raises(StateTransferError, match="changed"):
        load_state_transfer_bundle(path)
    monkeypatch.undo()

    def fail_read(descriptor: int, size: int) -> bytes:
        del descriptor, size
        raise OSError("synthetic read failure")

    monkeypatch.setattr(os, "read", fail_read)
    with pytest.raises(StateTransferError, match="could not be read"):
        load_state_transfer_bundle(path)


def test_naive_signature_evaluation_time_is_rejected(
    transfer_context: tuple[
        SQLiteInvalidationStore,
        dict[str, Any],
        SignerTrustPolicy,
        SignerTrustPolicy,
        SigningKey,
    ],
) -> None:
    _, bundle, receipt_policy, transfer_policy, _ = transfer_context
    with pytest.raises(StateTransferError, match="timezone"):
        verify_state_transfer_bundle(
            bundle,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=receipt_policy,
            evaluated_at=datetime(2026, 8, 7, tzinfo=UTC).replace(tzinfo=None),
        )
