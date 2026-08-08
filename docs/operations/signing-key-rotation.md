# Receipt signing-key enrollment and rotation

This runbook rotates DBOM receipt signers without letting a retired key admit new
records and without making legitimate history disappear. It covers receipt signing
keys, not DataHub access tokens, PostgreSQL credentials, TLS keys, package-release
signatures, or replay approval keys.

## Trust model

Receipt verification has two separate gates:

1. **Integrity:** the embedded Ed25519 public key validates the signature over the
   canonical receipt digest.
2. **Authority:** the key ID and SHA-256 public-key fingerprint satisfy the
   operator-controlled `glassbox.signer-trust.v1` policy.

Passing gate 1 without gate 2 is an untrusted self-signature. It must not enter
production state.

## Enroll the first key

Generate and store a raw 32-byte Ed25519 private key in the deployment secret
manager. Expose its unpadded base64url form only through the named environment
variable used by the receiver. Never place it in the policy or command arguments.

Derive a policy-ready public entry:

```bash
glassbox-dbom signer-entry \
  --key-id glassbox-prod-2026-08 \
  --private-key-env GLASSBOX_RECEIPT_SIGNING_KEY \
  --not-before 2026-08-07T00:00:00Z
```

The command returns the public key and fingerprint and explicitly reports
`private_key_returned: false`. Put the returned `signer` object into a copy of
[`trusted-signers.example.json`](../../examples/trusted-signers.example.json), set a
stable policy ID, and validate it:

```bash
glassbox-dbom verify-policy /etc/glassbox/trusted-signers.json
export GLASSBOX_SIGNER_TRUST_POLICY_PATH=/etc/glassbox/trusted-signers.json
```

The policy file contains public material, but it is still security-sensitive
configuration: restrict who may modify it, reject symlinks, and distribute it through
the deployment configuration authority.

## Start or restart components

Use the same policy snapshot for:

- `glassbox-otlp-receiver serve` and `drain` through
  `GLASSBOX_SIGNER_TRUST_POLICY_PATH`;
- the DataHub Action through `signer_trust_policy_path`;
- `glassbox-forensics-mcp --signer-trust-policy ...`;
- `glassbox-invalidation-state --signer-trust-policy ...`;
- the DataHub Skill helper scripts through `--signer-trust-policy ...` or the same
  environment variable.

The receiver refuses startup before binding when its private key ID, fingerprint,
status, or validity window does not match an active entry.

## Rotate without downtime

1. Create replacement key B in the secret manager and derive its signer entry.
2. Add B as `ACTIVE`. Keep key A `ACTIVE` during the overlap. Increase
   `minimum_trusted_signatures` only if producers actually emit the required number
   of signatures.
3. Validate and distribute the overlapping policy, then restart readers.
4. Switch receiver producers to key B and restart them. Confirm a new receipt reports
   B's fingerprint and reaches sealed DataHub publication.
5. Confirm exact redelivery of an A-signed receipt is still read-only and valid.
6. Change A to `RETIRED`, validate and distribute the policy, and restart all
   components.
7. Prove both controls:

   ```bash
   glassbox-dbom verify old-receipt.json \
     --signer-trust-policy /etc/glassbox/trusted-signers.json \
     --trust-mode HISTORICAL

   glassbox-dbom verify old-receipt.json \
     --signer-trust-policy /etc/glassbox/trusted-signers.json \
     --trust-mode ADMISSION
   ```

   The historical check must pass when the signed run time was inside A's window;
   admission must fail with `SIGNER_RETIRED`.

8. Remove A's private key from every producer after rollback is no longer needed.
   Keep its public entry `RETIRED` for historical verification.

## Compromise response

Use `REVOKED`, not `RETIRED`, when private-key compromise is suspected or proven.
After distributing and restarting with the revoked policy:

- new admission fails;
- fresh historical verification fails;
- state startup/integrity verification fails when affected receipts are present;
- MCP and Skill investigations report signer revocation instead of presenting the
  receipt as trusted.

Do not delete or rewrite affected receipts. Preserve them as incident evidence and
record the scope, suspected compromise time, policy revision, and recovery decision.
Revocation can intentionally make operational readers unavailable; use a separate,
explicit incident-analysis environment if investigators must inspect untrusted raw
artifacts.

## Rollback

If key B cannot sign or deployments have not switched, restore A to `ACTIVE` only
when A is known uncompromised and its validity window still permits admission.
Redistribute the policy and restart readers before switching producers back. Never
use rollback to turn a compromised key from `REVOKED` to `ACTIVE` without a formally
approved incident decision.

## Required evidence

Keep raw-free operational evidence for each rotation:

- old and new key IDs and public-key fingerprints;
- policy ID and checksum;
- overlap start and retirement/revocation time;
- successful new-key admission;
- successful old-key historical verification for normal retirement;
- failed old-key admission;
- component restart completion;
- no private key, DSN, token, receipt body, or raw telemetry.
