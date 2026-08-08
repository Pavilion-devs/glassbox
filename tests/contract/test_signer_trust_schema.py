from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from jsonschema import Draft202012Validator, FormatChecker

from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    load_signer_trust_schema,
    signing_key_fingerprint,
    signing_key_public_key,
)


def test_normative_signer_trust_policy_satisfies_its_schema() -> None:
    key = SigningKey("contract-key", Ed25519PrivateKey.generate())
    policy = SignerTrustPolicy(
        policy_id="glassbox-contract-trust-v1",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=key.key_id,
                public_key=signing_key_public_key(key),
                public_key_sha256=signing_key_fingerprint(key),
                status=SignerStatus.ACTIVE,
                not_before="2026-08-01T00:00:00Z",
                not_after=None,
            ),
        ),
    )

    validator = Draft202012Validator(
        load_signer_trust_schema(),
        format_checker=FormatChecker(),
    )

    assert list(validator.iter_errors(policy.to_dict())) == []


def test_committed_operator_policy_template_is_schema_valid() -> None:
    root = Path(__file__).parents[2]
    policy = SignerTrustPolicy.from_dict(
        json.loads((root / "examples" / "trusted-signers.example.json").read_text(encoding="utf-8"))
    )

    assert policy.policy_id == "replace-with-your-receipt-signing-policy-id"
