"""Campaign-to-replay recovery authorization contract tests."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox.redaction import digest_value
from glassbox_dbom import SigningKey, seal_receipt, signing_key_fingerprint
from glassbox_invalidation import OutboxStatus, OutboxTask
from glassbox_policy import (
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    InvalidationWriteEvidence,
    NormalizedChange,
    ReceiptDependencyProfile,
    create_campaign,
)
from glassbox_replay import (
    ActionInputReplacement,
    ContextReplacement,
    ModelDeterminism,
    ModelReplayConfig,
    ReplayExecutionError,
    ReplayMode,
    ReplaySupplement,
    build_replay_bundle,
    issue_recovery_authorization,
    verify_recovery_authorization,
)
from tests.helpers import receipt_payload

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD = f"urn:li:schemaField:({DATASET},average_order_value)"
ISSUED_AT = "2026-08-08T12:00:00Z"
EVALUATED_AT = "2026-08-08T12:05:00Z"
EXPIRES_AT = "2026-08-08T13:00:00Z"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _source() -> dict[str, Any]:
    payload = receipt_payload()
    payload["evidence"][0]["datahub_urn"] = DATASET
    payload["evidence"][0]["schema_field_urn"] = FIELD
    payload["actions"][0]["input_digest"] = {
        "algorithm": "sha256",
        "value": digest_value({"average_order_value": "44"}),
    }
    return seal_receipt(
        payload,
        signing_keys=(SigningKey("recovery-source", Ed25519PrivateKey.generate()),),
    )


def _bundle(source: dict[str, Any], *, corrected_value: object = 44.0) -> dict[str, Any]:
    evidence_id = source["evidence"][0]["evidence_id"]
    action_id = source["actions"][0]["action_id"]
    authority = "runtime-observation:orders-v2"
    model = source["models"][0]
    corrected_input = {"average_order_value": corrected_value}
    return build_replay_bundle(
        source,
        mode=ReplayMode.CORRECTED,
        supplement=ReplaySupplement(
            input_digest=_sha("recovery-input"),
            input_reference="artifact://recovery/input",
            feature_flags_digest=_sha("feature-flags"),
            model_configs=(
                ModelReplayConfig(
                    model["id"],
                    "synthetic-provider",
                    _sha("temperature=0"),
                    ModelDeterminism.DETERMINISTIC,
                    "artifact-store:test",
                ),
            ),
        ),
        context_replacements=(
            ContextReplacement(evidence_id, digest_value(corrected_input), authority),
        ),
        action_input_replacements=(
            ActionInputReplacement(
                action_id,
                digest_value(corrected_input),
                (evidence_id,),
                authority,
            ),
        ),
        signing_keys=(SigningKey("recovery-bundle", Ed25519PrivateKey.generate()),),
    )


def _task(source: dict[str, Any]) -> OutboxTask:
    profile = ReceiptDependencyProfile.from_receipt(
        source,
        field_lineage=FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.recovery-test.v1",
            wildcard_query=False,
        ),
    )
    campaign = create_campaign(
        NormalizedChange(
            event_id="mcl-recovery-001",
            entity_urn=DATASET,
            aspect_name="schemaMetadata",
            kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
            occurred_at="2026-08-08T11:55:00Z",
            schema_field_urn=FIELD,
            before_digest=_sha("varchar-schema"),
            after_digest=_sha("decimal-schema"),
        ),
        (profile,),
    )
    evidence = InvalidationWriteEvidence(
        incident_aspects=("incidentInfo", "incidentKey"),
        target_summary_verified=True,
        quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
    )
    return OutboxTask(
        campaign=campaign,
        status=OutboxStatus.COMPLETED,
        attempt_count=1,
        lease_owner=None,
        lease_expires_at_ms=None,
        last_error_type=None,
        write_evidence=evidence,
    )


def test_recovery_authorization_binds_completed_stale_campaign_to_exact_bundle() -> None:
    source = _source()
    bundle = _bundle(source)
    task = _task(source)
    operator = SigningKey("trusted-recovery-operator", Ed25519PrivateKey.generate())
    first = issue_recovery_authorization(
        task,
        source,
        bundle,
        issuer="urn:li:corpuser:recovery-operator",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signing_keys=(operator,),
    )
    second = issue_recovery_authorization(
        task,
        source,
        bundle,
        issuer="urn:li:corpuser:recovery-operator",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signing_keys=(operator,),
    )
    verification = verify_recovery_authorization(
        first,
        task,
        source,
        bundle,
        evaluated_at=EVALUATED_AT,
        trusted_signer_fingerprints={
            operator.key_id: signing_key_fingerprint(operator),
        },
    )

    assert first == second and first.valid
    assert verification.valid
    assert first.finding_state == "STALE"
    assert first.matched_evidence_ids == (source["evidence"][0]["evidence_id"],)
    assert first.bundle_id == bundle["bundle_id"]
    encoded = json.dumps(first.to_dict())
    assert "average_order_value" not in encoded
    assert "artifact://" not in encoded
    assert first.to_dict()["raw_content_returned"] is False


def test_recovery_authorization_rejects_pending_or_unverified_campaigns() -> None:
    source = _source()
    bundle = _bundle(source)
    task = _task(source)
    operator = SigningKey("recovery-operator", Ed25519PrivateKey.generate())

    with pytest.raises(ReplayExecutionError, match="completed"):
        issue_recovery_authorization(
            replace(task, status=OutboxStatus.READY),
            source,
            bundle,
            issuer="operator",
            issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
            signing_keys=(operator,),
        )
    with pytest.raises(ReplayExecutionError, match="writeback"):
        issue_recovery_authorization(
            replace(task, write_evidence=None),
            source,
            bundle,
            issuer="operator",
            issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
            signing_keys=(operator,),
        )


def test_recovery_verification_fails_closed_on_drift_trust_expiry_and_revocation() -> None:
    source = _source()
    bundle = _bundle(source)
    task = _task(source)
    operator = SigningKey("recovery-operator", Ed25519PrivateKey.generate())
    authorization = issue_recovery_authorization(
        task,
        source,
        bundle,
        issuer="operator",
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signing_keys=(operator,),
    )
    trusted = {operator.key_id: signing_key_fingerprint(operator)}

    untrusted = verify_recovery_authorization(
        authorization,
        task,
        source,
        bundle,
        evaluated_at=EVALUATED_AT,
        trusted_signer_fingerprints={operator.key_id: "0" * 64},
    )
    expired = verify_recovery_authorization(
        authorization,
        task,
        source,
        bundle,
        evaluated_at=EXPIRES_AT,
        trusted_signer_fingerprints=trusted,
    )
    revoked = verify_recovery_authorization(
        replace(authorization, revoked=True),
        task,
        source,
        bundle,
        evaluated_at=EVALUATED_AT,
        trusted_signer_fingerprints=trusted,
    )
    drifted = verify_recovery_authorization(
        authorization,
        replace(task, attempt_count=2),
        source,
        bundle,
        evaluated_at=EVALUATED_AT,
        trusted_signer_fingerprints=trusted,
    )

    assert not untrusted.valid and not untrusted.trusted_signer_present
    assert not expired.valid and not expired.time_valid
    assert not revoked.valid and not revoked.not_revoked
    assert not drifted.valid and not drifted.exact_binding_valid
