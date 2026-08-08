"""Adversarial tests for deterministic receipt materiality classification."""

from __future__ import annotations

import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey, seal_receipt
from glassbox_policy import (
    ChangeKind,
    EvidenceDependency,
    EvidenceRole,
    EvidenceState,
    FieldCoverage,
    FieldLineageProof,
    ImpactState,
    NormalizedChange,
    PolicyInputError,
    ReceiptDependencyProfile,
    classify_materiality,
    classify_receipts,
    create_campaign,
)
from tests.helpers import receipt_payload, sha256

DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
OTHER_DATASET = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.customers,PROD)"
USED_FIELD = f"urn:li:schemaField:({DATASET},revenue)"
UNUSED_FIELD = f"urn:li:schemaField:({DATASET},internal_note)"
DIGEST = sha256("synthetic-order-aggregate")["value"]


def _dependency(
    *,
    state: EvidenceState = EvidenceState.OBSERVED,
    datahub_urn: str | None = DATASET,
    field_urn: str | None = USED_FIELD,
    role: EvidenceRole = EvidenceRole.INPUT,
    observed_at: str | None = "2026-08-06T00:00:01Z",
    digest: str | None = DIGEST,
) -> EvidenceDependency:
    return EvidenceDependency(
        evidence_id="evidence-orders-001",
        datahub_urn=datahub_urn,
        schema_field_urn=field_urn,
        state=state,
        role=role,
        observed_at=observed_at,
        representation_digest=digest,
    )


def _profile(
    *dependencies: EvidenceDependency,
    lineage: FieldLineageProof | None = None,
    superseded_by: str | None = None,
    digest_character: str = "a",
) -> ReceiptDependencyProfile:
    receipt_id = "gbx:receipt:sha256:" + digest_character * 64
    return ReceiptDependencyProfile(
        receipt_id=receipt_id,
        document_urn=f"urn:li:document:glassbox.receipt.{digest_character * 64}",
        ended_at="2026-08-06T00:00:02Z",
        dependencies=tuple(dependencies),
        field_lineage=lineage or FieldLineageProof(),
        superseded_by=superseded_by,
    )


def _change(
    kind: ChangeKind = ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
    *,
    entity_urn: str = DATASET,
    field_urn: str | None = USED_FIELD,
    occurred_at: str = "2026-08-07T00:00:00Z",
    after_digest: str | None = None,
) -> NormalizedChange:
    return NormalizedChange(
        event_id="mcl-orders-schema-0001",
        entity_urn=entity_urn,
        aspect_name="schemaMetadata",
        kind=kind,
        occurred_at=occurred_at,
        schema_field_urn=field_urn,
        before_digest=sha256("before")["value"],
        after_digest=after_digest,
    )


def test_used_observed_field_change_is_stale_and_quarantined() -> None:
    result = classify_materiality(_profile(_dependency()), _change())

    assert result.state is ImpactState.STALE
    assert result.reason_code == "OBSERVED_MATERIAL_DEPENDENCY_CHANGED"
    assert result.matched_evidence_ids == ("evidence-orders-001",)
    assert result.quarantine_required


def test_unrelated_field_requires_positive_complete_lineage_to_be_unaffected() -> None:
    complete = FieldLineageProof(
        coverage=FieldCoverage.COMPLETE,
        rule_id="glassbox.sql-column-lineage.v1",
        wildcard_query=False,
    )
    result = classify_materiality(
        _profile(_dependency(), lineage=complete),
        _change(field_urn=UNUSED_FIELD),
    )

    assert result.state is ImpactState.UNAFFECTED
    assert result.reason_code == "COMPLETE_FIELD_LINEAGE_PROVES_FIELD_UNUSED"
    assert not result.quarantine_required


@pytest.mark.parametrize(
    "lineage",
    [
        FieldLineageProof(),
        FieldLineageProof(
            coverage=FieldCoverage.PARTIAL,
            rule_id="glassbox.sql-column-lineage.v1",
            wildcard_query=False,
        ),
        FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.sql-column-lineage.v1",
            wildcard_query=True,
        ),
        FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.sql-column-lineage.v1",
            wildcard_query=None,
        ),
    ],
)
def test_unrelated_field_with_incomplete_or_wildcard_lineage_is_at_risk(
    lineage: FieldLineageProof,
) -> None:
    result = classify_materiality(
        _profile(_dependency(), lineage=lineage),
        _change(field_urn=UNUSED_FIELD),
    )

    assert result.state is ImpactState.AT_RISK
    assert result.quarantine_required


def test_asset_mismatch_is_unaffected_only_when_all_dependencies_resolve() -> None:
    resolved = classify_materiality(
        _profile(_dependency()),
        _change(entity_urn=OTHER_DATASET, field_urn=f"urn:li:schemaField:({OTHER_DATASET},id)"),
    )
    unresolved = classify_materiality(
        _profile(_dependency(datahub_urn=None, field_urn=None, state=EvidenceState.UNKNOWN)),
        _change(entity_urn=OTHER_DATASET, field_urn=f"urn:li:schemaField:({OTHER_DATASET},id)"),
    )

    assert resolved.state is ImpactState.UNAFFECTED
    assert unresolved.state is ImpactState.UNKNOWN
    assert unresolved.quarantine_required


@pytest.mark.parametrize("state", [EvidenceState.DECLARED, EvidenceState.INFERRED])
def test_exact_non_observed_dependency_is_at_risk(state: EvidenceState) -> None:
    result = classify_materiality(_profile(_dependency(state=state)), _change())

    assert result.state is ImpactState.AT_RISK
    assert result.reason_code == "MATCHED_DEPENDENCY_NOT_OBSERVED"


def test_exact_unknown_dependency_remains_unknown() -> None:
    result = classify_materiality(
        _profile(_dependency(state=EvidenceState.UNKNOWN, observed_at=None, digest=None)),
        _change(),
    )

    assert result.state is ImpactState.UNKNOWN
    assert result.reason_code == "EXACT_DEPENDENCY_STATE_UNKNOWN"


def test_non_material_changes_do_not_quarantine_output_content() -> None:
    profile = _profile(_dependency(field_urn=None))

    formatting = classify_materiality(
        profile,
        _change(ChangeKind.DESCRIPTION_FORMATTING_CHANGED, field_urn=None),
    )
    ownership = classify_materiality(
        profile,
        _change(ChangeKind.OWNERSHIP_CHANGED, field_urn=None),
    )

    assert formatting.state is ImpactState.UNAFFECTED
    assert ownership.state is ImpactState.UNAFFECTED


def test_semantic_and_freshness_constraints_are_material() -> None:
    constraint = _profile(_dependency(field_urn=None, role=EvidenceRole.CONSTRAINT))

    glossary = classify_materiality(
        constraint,
        _change(ChangeKind.GLOSSARY_DEFINITION_CHANGED, field_urn=None),
    )
    freshness = classify_materiality(
        constraint,
        _change(ChangeKind.FRESHNESS_INCIDENT, field_urn=None),
    )

    assert glossary.state is ImpactState.STALE
    assert freshness.state is ImpactState.STALE


def test_unconstrained_freshness_incident_is_at_risk_not_invented_stale() -> None:
    result = classify_materiality(
        _profile(_dependency(field_urn=None)),
        _change(ChangeKind.FRESHNESS_INCIDENT, field_urn=None),
    )

    assert result.state is ImpactState.AT_RISK
    assert result.reason_code == "FRESHNESS_REQUIREMENT_NOT_RECORDED"


def test_exact_addition_semantic_reference_and_unsupported_change_fail_safely() -> None:
    exact_addition = classify_materiality(
        _profile(_dependency()),
        _change(ChangeKind.SCHEMA_FIELD_ADDED),
    )
    semantic_reference = classify_materiality(
        _profile(_dependency(field_urn=None, role=EvidenceRole.REFERENCE)),
        _change(ChangeKind.GLOSSARY_DEFINITION_CHANGED, field_urn=None),
    )
    unsupported = classify_materiality(
        _profile(_dependency(field_urn=None)),
        _change(ChangeKind.UNKNOWN, field_urn=None),
    )

    assert exact_addition.state is ImpactState.AT_RISK
    assert exact_addition.reason_code == "FIELD_ADDITION_MAY_AFFECT_WILDCARD"
    assert semantic_reference.state is ImpactState.AT_RISK
    assert semantic_reference.reason_code == "SEMANTIC_REFERENCE_MATERIALITY_UNPROVEN"
    assert unsupported.state is ImpactState.UNKNOWN


def test_unknown_dataset_level_match_cannot_be_excluded() -> None:
    result = classify_materiality(
        _profile(
            _dependency(
                state=EvidenceState.UNKNOWN,
                field_urn=None,
                observed_at=None,
                digest=None,
            )
        ),
        _change(ChangeKind.ASSET_DEPRECATED, field_urn=None),
    )

    assert result.state is ImpactState.UNKNOWN
    assert result.reason_code == "MATCHED_ASSET_DEPENDENCY_STATE_UNKNOWN"


def test_matching_post_change_snapshot_proves_unaffected() -> None:
    result = classify_materiality(
        _profile(
            _dependency(
                observed_at="2026-08-08T00:00:00Z",
                digest=DIGEST,
            )
        ),
        _change(after_digest=DIGEST),
    )

    assert result.state is ImpactState.UNAFFECTED
    assert result.reason_code == "MATCHED_POST_CHANGE_SNAPSHOT"


def test_superseded_and_dependency_free_receipts_fail_safely() -> None:
    superseding_id = "gbx:receipt:sha256:" + "b" * 64

    superseded = classify_materiality(
        _profile(_dependency(), superseded_by=superseding_id),
        _change(),
    )
    empty = classify_materiality(_profile(), _change())

    assert superseded.state is ImpactState.SUPERSEDED
    assert empty.state is ImpactState.UNKNOWN


def test_profile_is_derived_only_from_a_verified_signed_receipt() -> None:
    payload = receipt_payload()
    payload["evidence"][0]["schema_field_urn"] = USED_FIELD
    key = SigningKey("materiality-test", Ed25519PrivateKey.generate())
    sealed = seal_receipt(payload, signing_keys=(key,))

    profile = ReceiptDependencyProfile.from_receipt(sealed)

    assert profile.dependencies[0].schema_field_urn == USED_FIELD
    assert profile.dependencies[0].state is EvidenceState.OBSERVED

    tampered = copy.deepcopy(sealed)
    tampered["evidence"][0]["role"] = "POLICY"
    with pytest.raises(PolicyInputError, match="refusing unverified receipt"):
        ReceiptDependencyProfile.from_receipt(tampered)

    unsigned = seal_receipt(payload)
    with pytest.raises(PolicyInputError, match="at least one valid signature"):
        ReceiptDependencyProfile.from_receipt(unsigned)


def test_campaign_and_reverse_traversal_are_order_independent_and_idempotent() -> None:
    first = _profile(_dependency(), digest_character="a")
    second = _profile(
        _dependency(datahub_urn=OTHER_DATASET, field_urn=None),
        digest_character="b",
    )
    change = _change()

    campaign_one = create_campaign(change, (second, first))
    campaign_two = create_campaign(change, (first, second))

    assert campaign_one == campaign_two
    assert campaign_one.campaign_id.startswith("gbx:invalidation:sha256:")
    assert campaign_one.incident_urn.startswith("urn:li:incident:glassbox.invalidation.")
    assert [item.receipt_id for item in campaign_one.assessments] == [
        first.receipt_id,
        second.receipt_id,
    ]
    assert campaign_one.quarantined == (campaign_one.assessments[0],)

    with pytest.raises(PolicyInputError, match="duplicate receipt IDs"):
        classify_receipts((first, first), change)


def test_malformed_policy_inputs_are_rejected_at_the_boundary() -> None:
    with pytest.raises(PolicyInputError, match="complete field coverage"):
        FieldLineageProof(coverage=FieldCoverage.COMPLETE, wildcard_query=False)
    with pytest.raises(PolicyInputError, match="requires schema_field_urn"):
        _change(field_urn=None)
    with pytest.raises(PolicyInputError, match="timestamp must include an offset"):
        _change(occurred_at="2026-08-07T00:00:00")
    with pytest.raises(PolicyInputError, match="DataHub URN"):
        _change(entity_urn="commerce.orders")
    with pytest.raises(PolicyInputError, match="lowercase SHA-256"):
        _change(after_digest="not-a-digest")
    with pytest.raises(PolicyInputError, match="invalid RFC 3339"):
        _change(occurred_at="not-a-timestamp")


def test_profile_rejects_wrong_document_identity_and_duplicate_evidence() -> None:
    dependency = _dependency()
    with pytest.raises(PolicyInputError, match="does not match"):
        ReceiptDependencyProfile(
            receipt_id="gbx:receipt:sha256:" + "a" * 64,
            document_urn="urn:li:document:wrong",
            ended_at="2026-08-06T00:00:02Z",
            dependencies=(dependency,),
        )
    with pytest.raises(PolicyInputError, match="evidence IDs must be unique"):
        _profile(dependency, dependency)
