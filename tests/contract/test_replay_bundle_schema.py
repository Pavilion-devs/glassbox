from __future__ import annotations

import copy
import hashlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator

from glassbox_dbom import SigningKey, seal_receipt
from glassbox_replay import (
    ModelDeterminism,
    ModelReplayConfig,
    ReplayBundleError,
    ReplayMode,
    ReplaySupplement,
    build_replay_bundle,
    load_replay_bundle_schema,
    validate_replay_bundle,
)
from tests.helpers import receipt_payload


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _bundle() -> dict[str, object]:
    receipt = seal_receipt(
        receipt_payload(),
        signing_keys=(SigningKey("contract-source", Ed25519PrivateKey.generate()),),
    )
    model_id = receipt["models"][0]["id"]
    return build_replay_bundle(
        receipt,
        mode=ReplayMode.PINNED,
        supplement=ReplaySupplement(
            input_digest=_digest("contract-input"),
            input_reference="artifact://glassbox/contract-input",
            feature_flags_digest=_digest("contract-flags"),
            model_configs=(
                ModelReplayConfig(
                    model_id,
                    "contract-provider",
                    _digest("contract-model-parameters"),
                    ModelDeterminism.DETERMINISTIC,
                    "contract-fixture",
                ),
            ),
        ),
        signing_keys=(SigningKey("contract-bundle", Ed25519PrivateKey.generate()),),
    )


def test_replay_bundle_schema_is_valid_and_accepts_reference_artifact() -> None:
    schema = load_replay_bundle_schema()
    Draft202012Validator.check_schema(schema)
    validate_replay_bundle(_bundle(), schema=schema)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update({"truth_score": 1.0}), "Additional properties"),
        (lambda value: value.update({"mode": "BEST_EFFORT"}), "not one of"),
        (lambda value: value["recipe"]["actions"][0].update({"effect": "MAYBE"}), "not one of"),
    ],
)
def test_replay_bundle_schema_rejects_open_world_policy_values(
    mutation: object,
    message: str,
) -> None:
    invalid = copy.deepcopy(_bundle())
    assert callable(mutation)
    mutation(invalid)
    with pytest.raises(ReplayBundleError, match=message):
        validate_replay_bundle(invalid)
