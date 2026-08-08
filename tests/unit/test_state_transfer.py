from __future__ import annotations

import base64
import copy
import json
import stat
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

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
    OutboxStatus,
    ReceiptPublicationEvidence,
    SQLiteInvalidationStore,
    StateTransferError,
    TransactionalStoreError,
    build_state_transfer_bundle,
    import_state_transfer_bundle,
    load_state_transfer_bundle,
    verify_state_transfer_bundle,
    write_state_transfer_bundle,
)
from glassbox_invalidation.state_cli import main as state_main
from glassbox_policy import (
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    InvalidationWriteEvidence,
    NormalizedChange,
    create_campaign,
)
from tests.helpers import receipt_payload


def _key(key_id: str) -> SigningKey:
    return SigningKey(key_id, Ed25519PrivateKey.generate())


def _private_key_base64url(key: SigningKey) -> str:
    raw = key.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _policy(
    key: SigningKey,
    policy_id: str,
    *,
    status: SignerStatus = SignerStatus.ACTIVE,
) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id=policy_id,
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


def _receipt(key: SigningKey, run_id: str) -> dict[str, Any]:
    payload = receipt_payload()
    payload["run"]["run_id"] = run_id
    return seal_receipt(payload, signing_keys=(key,))


def _source_bundle(
    tmp_path: Path,
    *,
    receipts: int = 1,
) -> tuple[
    SQLiteInvalidationStore,
    dict[str, Any],
    SignerTrustPolicy,
    SignerTrustPolicy,
]:
    receipt_key = _key("receipt-authority")
    transfer_key = _key("transfer-authority")
    receipt_policy = _policy(receipt_key, "production-receipts-v1")
    transfer_policy = _policy(transfer_key, "production-transfers-v1")
    store = SQLiteInvalidationStore(
        tmp_path / "source.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    for index in range(receipts):
        store.register(_receipt(receipt_key, f"transfer-run-{index:03d}"))
    bundle = build_state_transfer_bundle(
        store,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(transfer_key,),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    return store, bundle, receipt_policy, transfer_policy


def test_bundle_is_content_addressed_and_verification_is_raw_free(
    tmp_path: Path,
) -> None:
    source, first, receipt_policy, transfer_policy = _source_bundle(tmp_path)
    signature = first["integrity"]["signatures"][0]

    verification = verify_state_transfer_bundle(
        first,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )

    assert verification.valid
    assert first["bundle_id"].startswith("gbx:state-transfer:sha256:")
    assert first["source"]["integrity_verified"] is True
    assert first["source"]["import_scope"] == "RECEIPTS_ONLY"
    assert signature["key_id"] == "transfer-authority"
    assert verification.to_dict()["raw_content_returned"] is False
    assert source.verify_integrity().receipts == 1


def test_import_reactivates_receipts_with_fresh_publication_only(tmp_path: Path) -> None:
    source, bundle, receipt_policy, transfer_policy = _source_bundle(tmp_path)
    receipt_id = source.all_profiles()[0].receipt_id
    claimed = source.claim_receipt_publication(
        receipt_id,
        worker_id="old-publisher",
        now_ms=1_000,
        lease_duration_ms=1_000,
    )
    assert claimed is not None
    source.complete_receipt_publication(
        receipt_id,
        ReceiptPublicationEvidence(
            document_urn=f"urn:li:document:glassbox.receipt.{receipt_id.removeprefix('gbx:receipt:sha256:')}",
            aspect_names=("documentInfo", "status"),
        ),
        worker_id="old-publisher",
    )
    campaign = create_campaign(
        NormalizedChange(
            event_id="archived-state-change",
            entity_urn=("urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"),
            aspect_name="schemaMetadata",
            kind=ChangeKind.SCHEMA_CHANGED,
            occurred_at="2026-08-07T00:00:00Z",
        ),
        source.all_profiles(),
    )
    assert source.stage_campaign(campaign)
    assert source.claim(
        campaign.campaign_id,
        worker_id="old-campaign-worker",
        now_ms=1_000,
        lease_duration_ms=1_000,
    )
    assert source.complete(
        campaign,
        InvalidationWriteEvidence(
            incident_aspects=("incidentInfo", "incidentKey"),
            target_summary_verified=True,
            quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
        ),
        worker_id="old-campaign-worker",
    )
    assert source.claim_owner_routing(
        campaign.campaign_id,
        worker_id="old-routing-worker",
        now_ms=2_000,
        lease_duration_ms=1_000,
    )
    source.complete_owner_routing(
        campaign,
        ("urn:li:corpGroup:glassbox-test",),
        worker_id="old-routing-worker",
    )
    transfer_key = _key("transfer-authority-new")
    transfer_policy = _policy(transfer_key, "production-transfers-new-v1")
    bundle = build_state_transfer_bundle(
        source,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(transfer_key,),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    target = SQLiteInvalidationStore(
        tmp_path / "target.sqlite3",
        signer_trust_policy=receipt_policy,
    )

    report = import_state_transfer_bundle(
        target,
        bundle,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )

    assert report.valid and report.inserted == 1 and report.reused == 0
    assert target.get_receipt(receipt_id) == source.get_receipt(receipt_id)
    task = target.get_receipt_publication_task(receipt_id)
    assert task is not None
    assert task.status is OutboxStatus.READY
    assert task.attempt_count == 0
    assert task.lease_owner is None and task.publication_evidence is None
    assert target.list_tasks() == ()
    assert target.list_owner_routing_tasks() == ()
    assert target.read_audit_records() == ()
    assert bundle["operational_archive"]["activated_on_import"] is False
    assert bundle["operational_archive"]["receipt_publication_tasks"][0]["status"] == ("COMPLETED")
    assert bundle["operational_archive"]["campaign_tasks"][0]["status"] == "COMPLETED"
    assert bundle["operational_archive"]["owner_routing_tasks"][0]["status"] == ("COMPLETED")
    assert len(bundle["operational_archive"]["audit_records"]) == 3


def test_import_is_idempotent(tmp_path: Path) -> None:
    _, bundle, receipt_policy, transfer_policy = _source_bundle(tmp_path)
    target = SQLiteInvalidationStore(
        tmp_path / "target.sqlite3",
        signer_trust_policy=receipt_policy,
    )

    first = import_state_transfer_bundle(
        target,
        bundle,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    second = import_state_transfer_bundle(
        target,
        bundle,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )

    assert (first.inserted, first.reused) == (1, 0)
    assert (second.inserted, second.reused) == (0, 1)
    assert target.verify_integrity().receipt_publication_tasks == 1


def test_transfer_authority_enforces_multi_signature_threshold(tmp_path: Path) -> None:
    source, _, receipt_policy, _ = _source_bundle(tmp_path)
    first = _key("transfer-threshold-a")
    second = _key("transfer-threshold-b")
    threshold_policy = SignerTrustPolicy(
        policy_id="production-transfer-threshold-v1",
        minimum_trusted_signatures=2,
        signers=(
            _policy(first, "unused-a").signers[0],
            _policy(second, "unused-b").signers[0],
        ),
    )

    bundle = build_state_transfer_bundle(
        source,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(first, second),
        bundle_trust_policy=threshold_policy,
        receipt_trust_policy=receipt_policy,
    )
    verification = verify_state_transfer_bundle(
        bundle,
        bundle_trust_policy=threshold_policy,
        receipt_trust_policy=receipt_policy,
    )
    assert verification.valid and verification.trusted_signature_count == 2

    with pytest.raises(StateTransferError, match="failed verification"):
        build_state_transfer_bundle(
            source,
            source_engine="SQLITE",
            source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
            signing_keys=(first,),
            bundle_trust_policy=threshold_policy,
            receipt_trust_policy=receipt_policy,
        )


def test_tamper_and_self_signed_transfer_fail_before_target_writes(tmp_path: Path) -> None:
    _, bundle, receipt_policy, transfer_policy = _source_bundle(tmp_path)
    tampered = copy.deepcopy(bundle)
    tampered["receipts"][0]["receipt"]["run"]["status"] = "FAILED"
    target = SQLiteInvalidationStore(
        tmp_path / "target.sqlite3",
        signer_trust_policy=receipt_policy,
    )

    verification = verify_state_transfer_bundle(
        tampered,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    assert not verification.valid
    assert "PAYLOAD_DIGEST_INVALID" in verification.errors
    with pytest.raises(StateTransferError, match="verification failed"):
        import_state_transfer_bundle(
            target,
            tampered,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=receipt_policy,
        )

    attacker = _key("attacker")
    source = SQLiteInvalidationStore(
        tmp_path / "attacker-source.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    for entry in bundle["receipts"]:
        source.register(entry["receipt"])
    forged = build_state_transfer_bundle(
        source,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(attacker,),
        bundle_trust_policy=_policy(attacker, "attacker-policy"),
        receipt_trust_policy=receipt_policy,
    )
    forged_verification = verify_state_transfer_bundle(
        forged,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )
    assert not forged_verification.valid
    assert forged_verification.signatures[0].reason == "UNKNOWN_KEY_ID"
    assert target.verify_integrity().receipts == 0


def test_retired_receipt_signer_cannot_be_laundered_by_valid_bundle(tmp_path: Path) -> None:
    _, bundle, active_receipt_policy, transfer_policy = _source_bundle(tmp_path)
    signer = active_receipt_policy.signers[0]
    retired_receipt_policy = SignerTrustPolicy(
        policy_id=active_receipt_policy.policy_id,
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=signer.key_id,
                public_key=signer.public_key,
                public_key_sha256=signer.public_key_sha256,
                status=SignerStatus.RETIRED,
                not_before=signer.not_before,
                not_after=signer.not_after,
            ),
        ),
    )
    target = SQLiteInvalidationStore(
        tmp_path / "target.sqlite3",
        signer_trust_policy=retired_receipt_policy,
    )

    verification = verify_state_transfer_bundle(
        bundle,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=retired_receipt_policy,
    )
    assert not verification.valid and not verification.receipt_set_valid
    with pytest.raises(StateTransferError, match="RECEIPT_SET_INVALID"):
        import_state_transfer_bundle(
            target,
            bundle,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=retired_receipt_policy,
        )
    assert target.verify_integrity().receipts == 0


def test_sqlite_batch_rolls_back_earlier_insert_on_late_conflict(tmp_path: Path) -> None:
    _, bundle, receipt_policy, transfer_policy = _source_bundle(tmp_path, receipts=2)
    transferred = [entry["receipt"] for entry in bundle["receipts"]]
    target = SQLiteInvalidationStore(
        tmp_path / "target.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    target.register(
        transferred[-1],
        field_lineage=FieldLineageProof(
            coverage=FieldCoverage.PARTIAL,
            rule_id="conflicting-target-proof",
        ),
    )

    with pytest.raises(TransactionalStoreError, match="conflicting dependency metadata"):
        import_state_transfer_bundle(
            target,
            bundle,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=receipt_policy,
        )

    assert target.get_receipt(transferred[0]["receipt_id"]) is None
    assert target.verify_integrity().receipts == 1


def test_bundle_file_io_is_private_bounded_and_refuses_links_or_overwrite(
    tmp_path: Path,
) -> None:
    _, bundle, _, _ = _source_bundle(tmp_path)
    path = tmp_path / "transfer.json"
    write_state_transfer_bundle(path, bundle)

    assert load_state_transfer_bundle(path) == bundle
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(StateTransferError, match="new file"):
        write_state_transfer_bundle(path, bundle)
    mismatched = copy.deepcopy(bundle)
    mismatched["source"]["schema_version"] = "changed-without-resigning"
    rejected = tmp_path / "rejected-transfer.json"
    with pytest.raises(StateTransferError, match="content-address"):
        write_state_transfer_bundle(rejected, mismatched)
    assert not rejected.exists()
    alias = tmp_path / "transfer-link.json"
    alias.symlink_to(path)
    with pytest.raises(StateTransferError, match="symbolic link"):
        load_state_transfer_bundle(alias)
    malformed = tmp_path / "malformed.json"
    malformed.write_text(json.dumps(["not", "an", "object"]), encoding="utf-8")
    with pytest.raises(StateTransferError, match="root must be an object"):
        load_state_transfer_bundle(malformed)


def test_operator_cli_exports_verifies_and_imports_without_printing_secrets(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt_key = _key("cli-receipt")
    transfer_key = _key("cli-transfer")
    receipt_policy = _policy(receipt_key, "cli-receipts-v1")
    transfer_policy = _policy(transfer_key, "cli-transfers-v1")
    receipt_policy_path = tmp_path / "receipt-policy.json"
    transfer_policy_path = tmp_path / "transfer-policy.json"
    receipt_policy_path.write_text(json.dumps(receipt_policy.to_dict()), encoding="utf-8")
    transfer_policy_path.write_text(json.dumps(transfer_policy.to_dict()), encoding="utf-8")
    source_path = tmp_path / "cli-source.sqlite3"
    source = SQLiteInvalidationStore(source_path, signer_trust_policy=receipt_policy)
    source.register(_receipt(receipt_key, "cli-transfer-run"))
    bundle_path = tmp_path / "cli-transfer.json"
    secret = _private_key_base64url(transfer_key)
    monkeypatch.setenv("GLASSBOX_TEST_TRANSFER_KEY", secret)

    assert (
        state_main(
            [
                "export-transfer",
                str(source_path),
                str(bundle_path),
                "--signer-trust-policy",
                str(receipt_policy_path),
                "--transfer-trust-policy",
                str(transfer_policy_path),
                "--transfer-signing-key",
                "cli-transfer=GLASSBOX_TEST_TRANSFER_KEY",
            ]
        )
        == 0
    )
    exported = capsys.readouterr().out
    assert '"valid": true' in exported
    assert '"raw_content_returned": false' in exported
    assert secret not in exported

    assert (
        state_main(
            [
                "verify-transfer",
                str(bundle_path),
                "--signer-trust-policy",
                str(receipt_policy_path),
                "--transfer-trust-policy",
                str(transfer_policy_path),
            ]
        )
        == 0
    )
    verified = capsys.readouterr().out
    assert '"valid": true' in verified and secret not in verified

    target_path = tmp_path / "cli-target.sqlite3"
    assert (
        state_main(
            [
                "import-transfer",
                str(target_path),
                str(bundle_path),
                "--signer-trust-policy",
                str(receipt_policy_path),
                "--transfer-trust-policy",
                str(transfer_policy_path),
            ]
        )
        == 0
    )
    imported = capsys.readouterr().out
    assert '"inserted": 1' in imported
    assert '"operational_archive_activated": false' in imported
    assert secret not in imported

    tampered = load_state_transfer_bundle(bundle_path)
    tampered["source"]["schema_version"] = "attacker"
    tampered_path = tmp_path / "tampered-transfer.json"
    tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
    rejected_target = tmp_path / "rejected.sqlite3"
    with pytest.raises(StateTransferError, match="verification failed"):
        state_main(
            [
                "import-transfer",
                str(rejected_target),
                str(tampered_path),
                "--signer-trust-policy",
                str(receipt_policy_path),
                "--transfer-trust-policy",
                str(transfer_policy_path),
            ]
        )
    assert not rejected_target.exists()
