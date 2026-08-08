from __future__ import annotations

import copy
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

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
    load_state_transfer_schema,
    validate_state_transfer_bundle,
)
from tests.helpers import receipt_payload


def _policy(key: SigningKey, policy_id: str) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id=policy_id,
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=key.key_id,
                public_key=signing_key_public_key(key),
                public_key_sha256=signing_key_fingerprint(key),
                status=SignerStatus.ACTIVE,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )


def _bundle(tmp_path: Path) -> dict[str, object]:
    receipt_key = SigningKey("contract-receipt", Ed25519PrivateKey.generate())
    transfer_key = SigningKey("contract-transfer", Ed25519PrivateKey.generate())
    receipt_policy = _policy(receipt_key, "contract-receipts-v1")
    transfer_policy = _policy(transfer_key, "contract-transfers-v1")
    store = SQLiteInvalidationStore(
        tmp_path / "contract.sqlite3",
        signer_trust_policy=receipt_policy,
    )
    store.register(seal_receipt(receipt_payload(), signing_keys=(receipt_key,)))
    return build_state_transfer_bundle(
        store,
        source_engine="SQLITE",
        source_schema_version=SQLITE_STATE_SCHEMA_VERSION,
        signing_keys=(transfer_key,),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=receipt_policy,
    )


def test_state_transfer_schema_is_valid_and_accepts_reference_artifact(
    tmp_path: Path,
) -> None:
    schema = load_state_transfer_schema()
    Draft202012Validator.check_schema(schema)
    validate_state_transfer_bundle(_bundle(tmp_path), schema=schema)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update({"truth_score": 1.0}),
        lambda value: value["source"].update({"import_scope": "FULL_DATABASE"}),
        lambda value: value["operational_archive"].update({"activated_on_import": True}),
        lambda value: value["integrity"]["signatures"][0].update({"algorithm": "RSA"}),
    ],
)
def test_state_transfer_schema_rejects_open_world_or_unsafe_values(
    tmp_path: Path,
    mutation: object,
) -> None:
    invalid = copy.deepcopy(_bundle(tmp_path))
    assert callable(mutation)
    mutation(invalid)

    with pytest.raises(StateTransferError, match="schema validation"):
        validate_state_transfer_bundle(invalid)
