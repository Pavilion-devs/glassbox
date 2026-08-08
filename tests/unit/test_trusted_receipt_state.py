from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import glassbox_invalidation.datahub_action as datahub_action_module
from glassbox_compiler import ReceiptPublicationWorker
from glassbox_datahub import ReceiptEmitter, receipt_document_urn
from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    seal_receipt,
    signing_key_fingerprint,
    signing_key_public_key,
)
from glassbox_forensics import ForensicsService
from glassbox_invalidation import (
    ReceiptStoreError,
    SQLiteInvalidationStore,
    TransactionalStoreError,
    VerifiedReceiptStore,
)
from glassbox_invalidation.state_cli import main as state_main
from glassbox_policy import PolicyInputError
from tests.helpers import receipt_payload


def _policy(
    key: SigningKey,
    *,
    status: SignerStatus = SignerStatus.ACTIVE,
) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id="glassbox-state-test-trust-v1",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=key.key_id,
                public_key=signing_key_public_key(key),
                public_key_sha256=signing_key_fingerprint(key),
                status=status,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )


def _receipt(key: SigningKey, *, run_id: str = "run-pricing-001") -> dict[str, Any]:
    payload = receipt_payload()
    payload["run"]["run_id"] = run_id
    return seal_receipt(payload, signing_keys=(key,))


def test_sqlite_admission_rejects_untrusted_signer_before_receipt_or_outbox_write(
    tmp_path: Path,
) -> None:
    trusted = SigningKey("trusted", Ed25519PrivateKey.generate())
    unknown = SigningKey("unknown", Ed25519PrivateKey.generate())
    store = SQLiteInvalidationStore(
        tmp_path / "state.sqlite3",
        signer_trust_policy=_policy(trusted),
    )

    with pytest.raises(PolicyInputError, match="UNKNOWN_KEY_ID"):
        store.register(_receipt(unknown))

    report = store.verify_integrity()
    assert report.receipts == 0
    assert report.dependencies == 0
    assert report.receipt_publication_tasks == 0


def test_sqlite_rotation_keeps_exact_history_but_blocks_new_retired_key_admission(
    tmp_path: Path,
) -> None:
    key = SigningKey("rotating-key", Ed25519PrivateKey.generate())
    path = tmp_path / "rotation.sqlite3"
    original = _receipt(key)
    active_store = SQLiteInvalidationStore(path, signer_trust_policy=_policy(key))
    assert active_store.register(original)

    retired_store = SQLiteInvalidationStore(
        path,
        signer_trust_policy=_policy(key, status=SignerStatus.RETIRED),
    )

    assert retired_store.register(original) is False
    assert retired_store.get_receipt(original["receipt_id"]) == original
    with pytest.raises(PolicyInputError, match="SIGNER_RETIRED"):
        retired_store.register(_receipt(key, run_id="new-backdated-run"))
    assert retired_store.verify_integrity().receipts == 1


def test_revocation_invalidates_previously_stored_receipt_on_fresh_read(
    tmp_path: Path,
) -> None:
    key = SigningKey("compromised-key", Ed25519PrivateKey.generate())
    path = tmp_path / "revocation.sqlite3"
    store = SQLiteInvalidationStore(path, signer_trust_policy=_policy(key))
    store.register(_receipt(key))

    with pytest.raises(TransactionalStoreError, match="stored receipt failed verification"):
        SQLiteInvalidationStore(
            path,
            signer_trust_policy=_policy(key, status=SignerStatus.REVOKED),
        )


def test_sqlite_cannot_silently_promote_pre_policy_state_to_trusted_history(
    tmp_path: Path,
) -> None:
    key = SigningKey("legacy-sqlite-key", Ed25519PrivateKey.generate())
    path = tmp_path / "legacy.sqlite3"
    legacy = SQLiteInvalidationStore(path)
    legacy.register(_receipt(key))

    with pytest.raises(TransactionalStoreError, match="stored receipt failed verification"):
        SQLiteInvalidationStore(path, signer_trust_policy=_policy(key))


def test_jsonl_store_applies_admission_and_historical_rotation_rules(tmp_path: Path) -> None:
    key = SigningKey("jsonl-key", Ed25519PrivateKey.generate())
    other = SigningKey("other-key", Ed25519PrivateKey.generate())
    path = tmp_path / "receipts.jsonl"
    active_store = VerifiedReceiptStore(path, signer_trust_policy=_policy(key))

    with pytest.raises(PolicyInputError, match="UNKNOWN_KEY_ID"):
        active_store.register(_receipt(other))
    original = _receipt(key)
    assert active_store.register(original)

    retired_store = VerifiedReceiptStore(
        path,
        signer_trust_policy=_policy(key, status=SignerStatus.RETIRED),
    )
    assert retired_store.register(original) is False
    with pytest.raises(PolicyInputError, match="SIGNER_RETIRED"):
        retired_store.register(_receipt(key, run_id="new-jsonl-backdated-run"))
    with pytest.raises(ReceiptStoreError, match="invalid receipt"):
        VerifiedReceiptStore(
            path,
            signer_trust_policy=_policy(key, status=SignerStatus.REVOKED),
        )


def test_jsonl_cannot_silently_promote_pre_policy_state_to_trusted_history(
    tmp_path: Path,
) -> None:
    key = SigningKey("legacy-jsonl-key", Ed25519PrivateKey.generate())
    path = tmp_path / "legacy.jsonl"
    legacy = VerifiedReceiptStore(path)
    legacy.register(_receipt(key))

    with pytest.raises(ReceiptStoreError, match="invalid receipt"):
        VerifiedReceiptStore(path, signer_trust_policy=_policy(key))


def test_revoked_receipt_never_reaches_datahub_projection() -> None:
    key = SigningKey("projection-key", Ed25519PrivateKey.generate())
    receipt = _receipt(key)

    class Backend:
        writes = 0

        def upsert_receipt(self, value: Mapping[str, Any]) -> str:
            del value
            self.writes += 1
            return "unused"

        def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
            del urn
            return ()

    backend = Backend()
    emitter = ReceiptEmitter(
        backend,
        signer_trust_policy=_policy(key, status=SignerStatus.REVOKED),
    )

    with pytest.raises(RuntimeError, match="SIGNER_REVOKED"):
        emitter.emit_verified(receipt)
    assert backend.writes == 0


def test_retired_key_cannot_backdate_a_direct_datahub_emission() -> None:
    key = SigningKey("retired-projection-key", Ed25519PrivateKey.generate())
    receipt = _receipt(key, run_id="backdated-direct-publication")

    class Backend:
        writes = 0

        def upsert_receipt(self, value: Mapping[str, Any]) -> str:
            del value
            self.writes += 1
            return "unused"

        def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
            del urn
            return ()

    backend = Backend()
    emitter = ReceiptEmitter(
        backend,
        signer_trust_policy=_policy(key, status=SignerStatus.RETIRED),
    )

    with pytest.raises(RuntimeError, match="SIGNER_RETIRED"):
        emitter.emit_verified(receipt)
    assert backend.writes == 0


def test_retired_history_can_publish_only_through_verified_state_outbox(
    tmp_path: Path,
) -> None:
    key = SigningKey("retired-outbox-key", Ed25519PrivateKey.generate())
    receipt = _receipt(key, run_id="admitted-before-retirement")
    path = tmp_path / "retired-outbox.sqlite3"
    active = SQLiteInvalidationStore(path, signer_trust_policy=_policy(key))
    assert active.register(receipt)

    retired_policy = _policy(key, status=SignerStatus.RETIRED)
    retired = SQLiteInvalidationStore(path, signer_trust_policy=retired_policy)

    class Backend:
        writes = 0

        def upsert_receipt(self, value: Mapping[str, Any]) -> str:
            self.writes += 1
            return receipt_document_urn(str(value["receipt_id"]))

        def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
            del urn
            return ("documentInfo",)

    backend = Backend()
    emission, attempts, wrote = ReceiptPublicationWorker(
        retired,
        ReceiptEmitter(backend, signer_trust_policy=retired_policy),
        worker_id="retired-history-publisher",
    ).process(str(receipt["receipt_id"]))

    assert emission.valid
    assert attempts == 1
    assert wrote is True
    assert backend.writes == 2


def test_forensics_reports_operator_trust_not_only_signature_math(tmp_path: Path) -> None:
    key = SigningKey("forensics-trust-key", Ed25519PrivateKey.generate())
    receipt = _receipt(key)
    store = VerifiedReceiptStore(
        tmp_path / "forensics.jsonl",
        signer_trust_policy=_policy(key),
    )
    store.register(receipt)
    service = ForensicsService(
        store,
        artifacts=store,
        signer_trust_policy=_policy(key),
    )

    report = service.verify_decision_receipt(str(receipt["receipt_id"]))

    assert report["valid"] is True
    assert report["checks"]["trusted_signer_policy"] is True
    assert report["checks"]["trusted_signature_count"] == 1
    assert report["checks"]["minimum_trusted_signatures"] == 1


def test_operator_cli_accepts_a_real_policy_path_and_rejects_unknown_signer(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    trusted = SigningKey("cli-trusted", Ed25519PrivateKey.generate())
    unknown = SigningKey("cli-unknown", Ed25519PrivateKey.generate())
    policy_path = tmp_path / "trusted-signers.json"
    policy_path.write_text(json.dumps(_policy(trusted).to_dict()), encoding="utf-8")
    database = tmp_path / "operator.sqlite3"
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_text(json.dumps(_receipt(unknown)), encoding="utf-8")

    assert state_main(["init", str(database), "--signer-trust-policy", str(policy_path)]) == 0
    capsys.readouterr()
    with pytest.raises(PolicyInputError, match="UNKNOWN_KEY_ID"):
        state_main(
            [
                "register-receipt",
                str(database),
                str(receipt_path),
                "--signer-trust-policy",
                str(policy_path),
            ]
        )

    assert (
        SQLiteInvalidationStore(
            database,
            signer_trust_policy=_policy(trusted),
        )
        .verify_integrity()
        .receipts
        == 0
    )


def test_datahub_action_loads_and_enforces_the_configured_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trusted = SigningKey("action-trusted", Ed25519PrivateKey.generate())
    unknown = SigningKey("action-unknown", Ed25519PrivateKey.generate())
    policy_path = tmp_path / "trusted-signers.json"
    policy_path.write_text(json.dumps(_policy(trusted).to_dict()), encoding="utf-8")

    class Backend:
        def test_connection(self) -> None:
            return None

    backend = Backend()
    monkeypatch.setattr(
        datahub_action_module.DataHubInvalidationBackend,
        "from_graph",
        classmethod(lambda cls, graph, actor_urn: backend),
    )
    action = datahub_action_module.GlassBoxInvalidationAction.create(
        {
            "state_database_path": str(tmp_path / "action.sqlite3"),
            "signer_trust_policy_path": str(policy_path),
        },
        SimpleNamespace(
            graph=SimpleNamespace(graph=object()),
            pipeline_name="trusted-action-test",
        ),
    )

    with pytest.raises(PolicyInputError, match="UNKNOWN_KEY_ID"):
        action._receipt_store.register(_receipt(unknown))
