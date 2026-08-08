"""Replay bundle, approval binding, deterministic policy, and dry-run tests."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey, seal_receipt
from glassbox_replay import (
    ActionInputReplacement,
    ContextReplacement,
    DryRunExecutor,
    ModelDeterminism,
    ModelReplayConfig,
    ReplayBundleError,
    ReplayDecision,
    ReplayInputError,
    ReplayMode,
    ReplayReason,
    ReplaySupplement,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
    build_replay_bundle,
    issue_replay_approval,
    load_replay_bundle_schema,
    plan_replay,
    validate_replay_bundle,
    verify_replay_approval,
    verify_replay_bundle,
)
from glassbox_replay.cli import main as replay_main
from tests.helpers import receipt_payload

EVALUATED_AT = "2026-08-06T12:30:00Z"
ISSUED_AT = "2026-08-06T12:00:00Z"
EXPIRES_AT = "2026-08-06T13:00:00Z"


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _value(value: dict[str, str] | None) -> str | None:
    return value["value"] if value is not None else None


def _receipt(
    *,
    effect: str = "READ_ONLY",
    status: str = "SUCCEEDED",
    eligibility: str = "ELIGIBLE",
    run_id: str = "replay-source-run",
) -> dict[str, Any]:
    payload = receipt_payload()
    payload["run"]["run_id"] = run_id
    payload["actions"][0]["effect"] = effect
    payload["actions"][0]["status"] = status
    if status in {"ATTEMPTED", "FAILED", "BLOCKED"}:
        payload["actions"][0]["output_digest"] = None
    payload["replay"]["eligibility"] = eligibility
    payload["replay"]["reason"] = "Synthetic replay policy fixture."
    return seal_receipt(
        payload,
        signing_keys=(SigningKey("source-receipt", Ed25519PrivateKey.generate()),),
    )


def _bundle_key(key_id: str = "bundle-signer") -> SigningKey:
    return SigningKey(key_id, Ed25519PrivateKey.generate())


def _supplement(
    *, determinism: ModelDeterminism = ModelDeterminism.DETERMINISTIC
) -> ReplaySupplement:
    return ReplaySupplement(
        input_digest=_sha("authorized-replay-input"),
        input_reference="artifact://glassbox/replay-input/synthetic",
        feature_flags_digest=_sha("feature-flags-v1"),
        model_configs=(
            ModelReplayConfig(
                model_id="deterministic-demo-model",
                provider_id="synthetic-provider",
                parameters_digest=_sha("temperature=0"),
                determinism=determinism,
                verification_authority="artifact-store:synthetic",
            ),
        ),
    )


def _inventory(receipt: dict[str, Any], *, rollback: bool = False) -> ResourceInventory:
    agent = receipt["agent"]
    workflow = receipt["workflow"]
    model = receipt["models"][0]
    skill = receipt["skills"][0]
    tool = receipt["tools"][0]
    return ResourceInventory(
        (
            ResourceAvailability(
                ResourceKind.AGENT,
                agent["id"],
                agent["version"],
                source_digest=_value(agent["source_digest"]),
            ),
            ResourceAvailability(
                ResourceKind.WORKFLOW,
                workflow["id"],
                workflow["version"],
            ),
            ResourceAvailability(
                ResourceKind.MODEL,
                model["id"],
                model["version"],
                source_digest=_value(model["source_digest"]),
            ),
            ResourceAvailability(
                ResourceKind.SKILL,
                skill["id"],
                skill["version"],
                source_digest=_value(skill["source_digest"]),
            ),
            ResourceAvailability(
                ResourceKind.TOOL,
                tool["id"],
                tool["version"],
                source_digest=_value(tool["source_digest"]),
                schema_digest=_value(tool["schema_digest"]),
                rollback_contract_digest=_sha("rollback-v1") if rollback else None,
            ),
        )
    )


def _bundle(
    receipt: dict[str, Any],
    *,
    mode: ReplayMode = ReplayMode.PINNED,
    supplement: ReplaySupplement | None = None,
    replacements: tuple[ContextReplacement, ...] = (),
    input_replacements: tuple[ActionInputReplacement, ...] = (),
    key: SigningKey | None = None,
) -> dict[str, Any]:
    return build_replay_bundle(
        receipt,
        mode=mode,
        supplement=supplement if supplement is not None else _supplement(),
        context_replacements=replacements,
        action_input_replacements=input_replacements,
        signing_keys=(key or _bundle_key(),),
    )


def test_replay_bundle_is_deterministic_signed_and_bound_to_source() -> None:
    receipt = _receipt()
    key = _bundle_key()
    first = _bundle(receipt, key=key)
    second = _bundle(receipt, key=key)

    assert first == second
    assert first["bundle_id"].startswith("gbx:replay-bundle:sha256:")
    assert first["source"]["receipt_id"] == receipt["receipt_id"]
    assert first["recipe"]["actions"][0]["input_digest"] == receipt["actions"][0]["input_digest"]
    validate_replay_bundle(first)
    report = verify_replay_bundle(first, source_receipt=receipt)
    assert report.valid and report.source_receipt_valid
    assert report.action_digests_valid
    assert report.to_dict()["signatures"] == [
        {"key_id": "bundle-signer", "valid": True, "error": None}
    ]

    other = _receipt(run_id="different-source")
    mismatch = verify_replay_bundle(first, source_receipt=other)
    assert not mismatch.valid and mismatch.source_receipt_valid is False


def test_replay_bundle_tamper_and_signature_requirements_fail_closed() -> None:
    receipt = _receipt()
    bundle = _bundle(receipt)
    tampered = copy.deepcopy(bundle)
    tampered["recipe"]["actions"][0]["input_digest"]["value"] = _sha("tampered")
    report = verify_replay_bundle(tampered, source_receipt=receipt)
    assert not report.valid
    assert not report.payload_digest_valid
    assert not report.bundle_id_valid
    assert not report.action_digests_valid

    unsigned = build_replay_bundle(
        receipt,
        mode=ReplayMode.PINNED,
        supplement=_supplement(),
    )
    assert verify_replay_bundle(unsigned, require_signature=False).valid
    assert not verify_replay_bundle(unsigned).valid
    malformed = copy.deepcopy(bundle)
    malformed["unexpected"] = True
    with pytest.raises(ReplayBundleError, match="Additional properties"):
        validate_replay_bundle(malformed)

    invalid_source = copy.deepcopy(receipt)
    invalid_source["output"]["digest"]["value"] = _sha("changed-after-seal")
    with pytest.raises(ReplayBundleError, match="source receipt verification failed"):
        _bundle(invalid_source)


def test_bundle_signature_verifier_rejects_malformed_and_duplicate_material() -> None:
    receipt = _receipt()
    bundle = _bundle(receipt)

    invalid_encoding = copy.deepcopy(bundle)
    invalid_encoding["integrity"]["signatures"][0]["public_key"] = "!" * 43
    report = verify_replay_bundle(invalid_encoding, source_receipt=receipt)
    assert not report.valid
    assert report.payload_digest_valid
    assert report.signatures[0].error == "invalid base64url signature material"

    duplicate = copy.deepcopy(bundle)
    duplicate["integrity"]["signatures"].append(
        copy.deepcopy(duplicate["integrity"]["signatures"][0])
    )
    duplicate_report = verify_replay_bundle(duplicate, source_receipt=receipt)
    assert not duplicate_report.valid
    assert duplicate_report.signatures[1].error == "duplicate key_id"

    malformed_algorithm = copy.deepcopy(bundle)
    malformed_algorithm["integrity"]["signatures"][0]["algorithm"] = "RSA"
    algorithm_report = verify_replay_bundle(malformed_algorithm)
    assert not algorithm_report.valid
    assert algorithm_report.signatures[0].error == "unsupported signature algorithm"


def test_schema_loader_rejects_non_object_root(tmp_path: Path) -> None:
    schema_path = tmp_path / "schema.json"
    schema_path.write_text("[]")
    with pytest.raises(ReplayBundleError, match="schema root"):
        load_replay_bundle_schema(schema_path)


def test_context_replacement_modes_are_closed_and_preserve_epistemic_state() -> None:
    receipt = _receipt()
    evidence_id = receipt["evidence"][0]["evidence_id"]
    replacement = ContextReplacement(
        evidence_id,
        _sha("corrected-context"),
        "datahub-direct-read:synthetic",
    )
    corrected = _bundle(
        receipt,
        mode=ReplayMode.CORRECTED,
        replacements=(replacement,),
        input_replacements=(
            ActionInputReplacement(
                receipt["actions"][0]["action_id"],
                _sha("corrected-action-input"),
                (evidence_id,),
                "datahub-direct-read:synthetic",
            ),
        ),
    )
    context = corrected["context"][0]
    action = corrected["recipe"]["actions"][0]
    assert context["state"] == receipt["evidence"][0]["state"]
    assert context["origin"] == "CONTEXT_REPLACEMENT"
    assert context["active_representation_digest"]["value"] == replacement.representation_digest
    assert action["original_input_digest"] == receipt["actions"][0]["input_digest"]
    assert action["input_digest"]["value"] == _sha("corrected-action-input")
    assert action["input_evidence_ids"] == [evidence_id]

    with pytest.raises(ReplayInputError, match="every replaced INPUT evidence"):
        _bundle(
            receipt,
            mode=ReplayMode.CORRECTED,
            replacements=(replacement,),
        )
    with pytest.raises(ReplayInputError, match="authorities must match"):
        _bundle(
            receipt,
            mode=ReplayMode.CORRECTED,
            replacements=(replacement,),
            input_replacements=(
                ActionInputReplacement(
                    receipt["actions"][0]["action_id"],
                    _sha("different-corrected-input"),
                    (evidence_id,),
                    "different-authority",
                ),
            ),
        )

    with pytest.raises(ReplayInputError, match="does not permit"):
        _bundle(receipt, replacements=(replacement,))
    with pytest.raises(ReplayInputError, match="requires at least one"):
        _bundle(receipt, mode=ReplayMode.CORRECTED)
    with pytest.raises(ReplayInputError, match="exactly one"):
        _bundle(receipt, mode=ReplayMode.COUNTERFACTUAL)
    with pytest.raises(ReplayInputError, match="unknown evidence"):
        _bundle(
            receipt,
            mode=ReplayMode.CORRECTED,
            replacements=(ContextReplacement("missing", _sha("value")),),
        )
    with pytest.raises(ReplayInputError, match="unique evidence"):
        _bundle(
            receipt,
            mode=ReplayMode.CORRECTED,
            replacements=(replacement, replacement),
        )


def test_safe_read_only_plan_and_dry_run_are_content_addressed_and_inert() -> None:
    receipt = _receipt()
    bundle = _bundle(receipt)
    inventory = _inventory(receipt)
    first = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    second = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )

    assert first == second and first.valid
    assert first.decision is ReplayDecision.ALLOW
    assert first.execution_permitted
    assert first.reason_codes == (ReplayReason.SAFE_READ_ONLY_REPLAY,)
    dry_run = DryRunExecutor().render(bundle, first, source_receipt=receipt)
    assert dry_run.valid
    assert dry_run.status == "READY_FOR_ISOLATED_EXECUTOR"
    assert dry_run.external_calls == dry_run.history_mutations == 0
    assert not dry_run.would_invoke_actions
    assert dry_run.steps[0]["operation"] == "DESCRIBE_ONLY"
    assert "artifact://" not in json.dumps(dry_run.to_dict())


def test_dry_mode_reports_every_problem_but_never_executes() -> None:
    receipt = _receipt(
        effect="IRREVERSIBLE",
        status="ATTEMPTED",
        eligibility="UNREPLAYABLE",
    )
    bundle = _bundle(
        receipt,
        mode=ReplayMode.DRY,
        supplement=ReplaySupplement(),
    )
    plan = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=ResourceInventory(()),
        evaluated_at=EVALUATED_AT,
    )
    assert plan.decision is ReplayDecision.DRY_RUN_ONLY
    assert not plan.execution_permitted
    assert {
        ReplayReason.DRY_MODE_REQUESTED,
        ReplayReason.SOURCE_UNREPLAYABLE,
        ReplayReason.ACTION_OUTCOME_UNCERTAIN,
        ReplayReason.IRREVERSIBLE_ACTION,
        ReplayReason.RESOURCE_UNAVAILABLE,
    }.issubset(plan.reason_codes)
    report = DryRunExecutor().render(bundle, plan, source_receipt=receipt)
    assert report.valid and report.status == "POLICY_LIMITED"

    broken_report = replace(report, external_calls=1)
    assert not broken_report.valid


@pytest.mark.parametrize(
    ("effect", "status", "eligibility", "reason", "decision"),
    [
        (
            "IRREVERSIBLE",
            "SUCCEEDED",
            "UNREPLAYABLE",
            ReplayReason.IRREVERSIBLE_ACTION,
            ReplayDecision.BLOCK,
        ),
        (
            "UNKNOWN_EFFECT",
            "SUCCEEDED",
            "NOT_EVALUATED",
            ReplayReason.UNKNOWN_ACTION_EFFECT,
            ReplayDecision.DRY_RUN_ONLY,
        ),
        (
            "READ_ONLY",
            "FAILED",
            "UNREPLAYABLE",
            ReplayReason.ACTION_FAILED_OR_BLOCKED,
            ReplayDecision.BLOCK,
        ),
    ],
)
def test_unsafe_or_uncertain_actions_are_never_executable(
    effect: str,
    status: str,
    eligibility: str,
    reason: ReplayReason,
    decision: ReplayDecision,
) -> None:
    receipt = _receipt(effect=effect, status=status, eligibility=eligibility)
    bundle = _bundle(receipt)
    plan = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=_inventory(receipt),
        evaluated_at=EVALUATED_AT,
    )
    assert plan.decision is decision
    assert reason in plan.reason_codes
    assert not plan.execution_permitted
    if decision is ReplayDecision.BLOCK:
        report = DryRunExecutor().render(
            bundle,
            plan,
            source_receipt=receipt,
        )
        assert report.status == "BLOCKED"


def test_dry_run_rejects_plan_tampering_and_cross_bundle_confusion() -> None:
    receipt = _receipt()
    bundle = _bundle(receipt)
    plan = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=_inventory(receipt),
        evaluated_at=EVALUATED_AT,
    )
    with pytest.raises(ReplayBundleError, match="plan content address"):
        DryRunExecutor().render(
            bundle,
            replace(plan, plan_id="gbx:replay-plan:sha256:" + "0" * 64),
            source_receipt=receipt,
        )

    other_receipt = _receipt(run_id="other-run")
    other_bundle = _bundle(other_receipt)
    other_plan = plan_replay(
        other_bundle,
        source_receipt=other_receipt,
        inventory=_inventory(other_receipt),
        evaluated_at=EVALUATED_AT,
    )
    with pytest.raises(ReplayBundleError, match="different bundle"):
        DryRunExecutor().render(bundle, other_plan, source_receipt=receipt)

    tampered = copy.deepcopy(bundle)
    tampered["original_output"]["digest"]["value"] = _sha("tampered")
    with pytest.raises(ReplayBundleError, match="bundle verification failed"):
        DryRunExecutor().render(tampered, plan, source_receipt=receipt)


def test_missing_or_changed_resources_block_best_effort_substitution() -> None:
    receipt = _receipt()
    bundle = _bundle(receipt)
    empty = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=ResourceInventory(()),
        evaluated_at=EVALUATED_AT,
    )
    assert empty.decision is ReplayDecision.BLOCK
    assert ReplayReason.RESOURCE_UNAVAILABLE in empty.reason_codes
    assert len(empty.missing_resources) == 5

    changed = list(_inventory(receipt).resources)
    changed[-1] = replace(changed[-1], version="2.0.0")
    mismatch = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=ResourceInventory(tuple(changed)),
        evaluated_at=EVALUATED_AT,
    )
    assert mismatch.decision is ReplayDecision.BLOCK
    assert mismatch.missing_resources == ("TOOL:glassbox.orders.lookup",)


def test_missing_execution_material_and_unknown_model_determinism_are_dry_only() -> None:
    receipt = _receipt()
    incomplete = plan_replay(
        _bundle(receipt, supplement=ReplaySupplement()),
        source_receipt=receipt,
        inventory=_inventory(receipt),
        evaluated_at=EVALUATED_AT,
    )
    assert incomplete.decision is ReplayDecision.DRY_RUN_ONLY
    assert {
        ReplayReason.EXECUTION_INPUT_UNAVAILABLE,
        ReplayReason.FEATURE_FLAGS_UNPINNED,
        ReplayReason.MODEL_CONFIG_UNPINNED,
    }.issubset(incomplete.reason_codes)

    unknown = plan_replay(
        _bundle(receipt, supplement=_supplement(determinism=ModelDeterminism.UNKNOWN)),
        source_receipt=receipt,
        inventory=_inventory(receipt),
        evaluated_at=EVALUATED_AT,
    )
    assert unknown.decision is ReplayDecision.DRY_RUN_ONLY
    assert ReplayReason.MODEL_DETERMINISM_UNKNOWN in unknown.reason_codes

    nondeterministic = plan_replay(
        _bundle(receipt, supplement=_supplement(determinism=ModelDeterminism.NONDETERMINISTIC)),
        source_receipt=receipt,
        inventory=_inventory(receipt),
        evaluated_at=EVALUATED_AT,
    )
    assert nondeterministic.decision is ReplayDecision.ALLOW
    assert ReplayReason.MODEL_NONDETERMINISM_DISCLOSED in nondeterministic.reason_codes


def test_unverified_corrected_context_is_dry_only() -> None:
    payload = receipt_payload()
    payload["evidence"][0]["role"] = "REFERENCE"
    receipt = seal_receipt(
        payload,
        signing_keys=(SigningKey("source-receipt", Ed25519PrivateKey.generate()),),
    )
    replacement = ContextReplacement(
        receipt["evidence"][0]["evidence_id"],
        _sha("declared-only-correction"),
    )
    bundle = _bundle(
        receipt,
        mode=ReplayMode.CORRECTED,
        replacements=(replacement,),
    )
    plan = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=_inventory(receipt),
        evaluated_at=EVALUATED_AT,
    )
    assert plan.decision is ReplayDecision.DRY_RUN_ONLY
    assert ReplayReason.CONTEXT_REPLACEMENT_UNVERIFIED in plan.reason_codes


def test_reversible_plan_requires_fresh_digest_bound_trusted_approval() -> None:
    receipt = _receipt(effect="REVERSIBLE", eligibility="REQUIRES_APPROVAL")
    bundle = _bundle(receipt)
    inventory = _inventory(receipt, rollback=True)
    pending = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    assert pending.decision is ReplayDecision.REQUIRE_HUMAN_APPROVAL
    assert ReplayReason.APPROVAL_REQUIRED in pending.reason_codes

    approval_key = _bundle_key("trusted-approver")
    approval = issue_replay_approval(
        bundle_id=bundle["bundle_id"],
        action_set_digest=pending.action_set_digest,
        issuer="urn:li:corpuser:synthetic-approver",
        environment=pending.environment,
        reason_digest=_sha("approve exact reversible replay"),
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signing_keys=(approval_key,),
    )
    allowed = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
        approval=approval,
        trusted_approval_key_ids=frozenset({"trusted-approver"}),
    )
    assert allowed.decision is ReplayDecision.ALLOW_WITH_RECEIPT
    assert allowed.execution_permitted
    assert allowed.approval_verification is not None
    assert allowed.approval_verification.valid

    untrusted = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
        approval=approval,
        trusted_approval_key_ids=frozenset({"somebody-else"}),
    )
    assert untrusted.decision is ReplayDecision.BLOCK
    assert ReplayReason.APPROVAL_INVALID in untrusted.reason_codes

    changed_receipt = _receipt(effect="REVERSIBLE", eligibility="REQUIRES_APPROVAL")
    changed_receipt["actions"][0]["input_digest"]["value"] = _sha("changed-action")
    changed_payload = copy.deepcopy(changed_receipt)
    changed_payload.pop("receipt_id")
    changed_payload.pop("integrity")
    changed_receipt = seal_receipt(
        changed_payload,
        signing_keys=(SigningKey("changed-source", Ed25519PrivateKey.generate()),),
    )
    changed_bundle = _bundle(changed_receipt)
    changed = plan_replay(
        changed_bundle,
        source_receipt=changed_receipt,
        inventory=_inventory(changed_receipt, rollback=True),
        evaluated_at=EVALUATED_AT,
        approval=approval,
        trusted_approval_key_ids=frozenset({"trusted-approver"}),
    )
    assert changed.decision is ReplayDecision.BLOCK
    assert ReplayReason.APPROVAL_INVALID in changed.reason_codes


def test_approval_expiry_revocation_signature_and_input_contracts_fail_closed() -> None:
    receipt = _receipt(effect="REVERSIBLE", eligibility="REQUIRES_APPROVAL")
    bundle = _bundle(receipt)
    pending = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=_inventory(receipt, rollback=True),
        evaluated_at=EVALUATED_AT,
    )
    key = _bundle_key("approval-key")
    approval = issue_replay_approval(
        bundle_id=bundle["bundle_id"],
        action_set_digest=pending.action_set_digest,
        issuer="synthetic-approver",
        environment=pending.environment,
        reason_digest=_sha("reason"),
        issued_at=ISSUED_AT,
        expires_at=EXPIRES_AT,
        signing_keys=(key,),
    )
    expired = verify_replay_approval(
        approval,
        expected_bundle_id=bundle["bundle_id"],
        expected_action_set_digest=pending.action_set_digest,
        expected_environment=pending.environment,
        evaluated_at="2026-08-06T14:00:00Z",
        trusted_key_ids=frozenset({"approval-key"}),
    )
    assert not expired.valid and not expired.time_valid
    revoked = verify_replay_approval(
        replace(approval, revoked=True),
        expected_bundle_id=bundle["bundle_id"],
        expected_action_set_digest=pending.action_set_digest,
        expected_environment=pending.environment,
        evaluated_at=EVALUATED_AT,
        trusted_key_ids=frozenset({"approval-key"}),
    )
    assert not revoked.valid and not revoked.not_revoked

    malformed_signature = replace(
        approval,
        signatures=(replace(approval.signatures[0], public_key="!" * 43),),
    )
    invalid_signature = verify_replay_approval(
        malformed_signature,
        expected_bundle_id=bundle["bundle_id"],
        expected_action_set_digest=pending.action_set_digest,
        expected_environment=pending.environment,
        evaluated_at=EVALUATED_AT,
        trusted_key_ids=frozenset({"approval-key"}),
    )
    assert not invalid_signature.valid and not invalid_signature.signatures_valid

    with pytest.raises(ReplayInputError, match="later than"):
        issue_replay_approval(
            bundle_id=bundle["bundle_id"],
            action_set_digest=pending.action_set_digest,
            issuer="issuer",
            environment="DEV",
            reason_digest=_sha("reason"),
            issued_at=ISSUED_AT,
            expires_at=ISSUED_AT,
            signing_keys=(key,),
        )
    with pytest.raises(ReplayInputError, match="at least one"):
        issue_replay_approval(
            bundle_id=bundle["bundle_id"],
            action_set_digest=pending.action_set_digest,
            issuer="issuer",
            environment="DEV",
            reason_digest=_sha("reason"),
            issued_at=ISSUED_AT,
            expires_at=EXPIRES_AT,
            signing_keys=(),
        )


def test_replay_input_models_reject_ambiguous_or_malformed_material() -> None:
    digest = _sha("value")
    with pytest.raises(ReplayInputError, match="configured together"):
        ReplaySupplement(input_digest=digest)
    config = ModelReplayConfig(
        "model",
        "provider",
        digest,
        ModelDeterminism.DETERMINISTIC,
        "authority",
    )
    with pytest.raises(ReplayInputError, match="unique model"):
        ReplaySupplement(model_configs=(config, config))
    resource = ResourceAvailability(ResourceKind.WORKFLOW, "workflow", "1")
    with pytest.raises(ReplayInputError, match="identities must be unique"):
        ResourceInventory((resource, resource))
    with pytest.raises(ReplayInputError, match="valid only for TOOL"):
        ResourceAvailability(
            ResourceKind.MODEL,
            "model",
            "1",
            schema_digest=digest,
        )
    with pytest.raises(ReplayInputError, match="SHA-256"):
        ContextReplacement("evidence", "not-a-digest")


def test_cli_builds_and_renders_without_exposing_private_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    receipt = _receipt()
    receipt_path = tmp_path / "receipt.json"
    supplement_path = tmp_path / "supplement.json"
    inventory_path = tmp_path / "inventory.json"
    receipt_path.write_text(json.dumps(receipt))
    supplement = _supplement()
    supplement_path.write_text(
        json.dumps(
            {
                "input_digest": supplement.input_digest,
                "input_reference": supplement.input_reference,
                "feature_flags_digest": supplement.feature_flags_digest,
                "model_configs": [
                    {
                        "model_id": item.model_id,
                        "provider_id": item.provider_id,
                        "parameters_digest": item.parameters_digest,
                        "determinism": item.determinism.value,
                        "verification_authority": item.verification_authority,
                    }
                    for item in supplement.model_configs
                ],
            }
        )
    )
    inventory_payload = {
        "resources": [
            {
                "kind": item.kind.value,
                "resource_id": item.resource_id,
                "version": item.version,
                "source_digest": item.source_digest,
                "schema_digest": item.schema_digest,
                "rollback_contract_digest": item.rollback_contract_digest,
            }
            for item in _inventory(receipt).resources
        ]
    }
    inventory_path.write_text(json.dumps(inventory_payload))
    private = Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    encoded = base64.urlsafe_b64encode(private).decode().rstrip("=")
    monkeypatch.setenv("GLASSBOX_TEST_REPLAY_KEY", encoded)

    assert (
        replay_main(
            [
                "dry-run",
                str(receipt_path),
                "--mode",
                "PINNED",
                "--supplement",
                str(supplement_path),
                "--inventory",
                str(inventory_path),
                "--evaluated-at",
                EVALUATED_AT,
                "--signing-key-env",
                "GLASSBOX_TEST_REPLAY_KEY",
            ]
        )
        == 0
    )
    output = capsys.readouterr().out
    result = json.loads(output)
    assert result["plan"]["decision"] == "ALLOW"
    assert result["dry_run"]["external_calls"] == 0
    assert encoded not in output

    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps(result["bundle"]))
    assert replay_main(["verify-bundle", str(bundle_path), str(receipt_path)]) == 0
    verification = json.loads(capsys.readouterr().out)
    assert verification["valid"] is True

    invalid_bundle = copy.deepcopy(result["bundle"])
    invalid_bundle["mode"] = "CORRECTED"
    bundle_path.write_text(json.dumps(invalid_bundle))
    assert replay_main(["verify-bundle", str(bundle_path), str(receipt_path)]) == 1
    assert json.loads(capsys.readouterr().out)["valid"] is False

    assert (
        replay_main(
            [
                "bundle",
                str(receipt_path),
                "--mode",
                "PINNED",
                "--supplement",
                str(supplement_path),
                "--signing-key-env",
                "GLASSBOX_TEST_REPLAY_KEY",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["mode"] == "PINNED"

    monkeypatch.setenv("GLASSBOX_TEST_REPLAY_KEY", "!!!!")
    assert (
        replay_main(
            [
                "bundle",
                str(receipt_path),
                "--mode",
                "PINNED",
                "--signing-key-env",
                "GLASSBOX_TEST_REPLAY_KEY",
            ]
        )
        == 2
    )
    assert "base64url Ed25519" in capsys.readouterr().err

    monkeypatch.delenv("GLASSBOX_TEST_REPLAY_KEY")
    assert (
        replay_main(
            [
                "bundle",
                str(receipt_path),
                "--mode",
                "PINNED",
                "--signing-key-env",
                "GLASSBOX_TEST_REPLAY_KEY",
            ]
        )
        == 2
    )
    assert "environment variable is unset" in capsys.readouterr().err
