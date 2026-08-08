# ADR-0017: Separate receipt signature integrity from operator signer trust

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0003](0003-dbom-canonical-integrity-profile.md),
  [ADR-0014](0014-shared-live-decision-state.md), and
  [ADR-0016](0016-durable-receipt-publication-and-otlp-acknowledgement.md)

## Context

DBOM 0.1 embeds each Ed25519 public key beside its detached signature. That is
sufficient to prove that the signature matches the receipt and that the signer
possessed the corresponding private key. It is not sufficient to establish that an
operator authorized that key. Before this decision, an attacker could generate a new
key pair, sign a schema-valid receipt, and pass every cryptographic integrity gate in
a state store configured only with `require_signature=true`.

Production systems also need rotation. Removing an old public key immediately would
make immutable historical receipts unreadable. Continuing to accept the old key for
new records would permit a retired signer to backdate a receipt using the signed
`run.ended_at` value. Compromise response needs stronger semantics than normal
retirement.

## Decision

- Define the closed `glassbox.signer-trust.v1` JSON policy and publish its normative
  JSON Schema under `schemas/signer-trust/0.1.0/`.
- Bind every trusted signer to both its `key_id` and the lowercase SHA-256 fingerprint
  of its raw 32-byte Ed25519 public key. A matching key ID with different key material
  is rejected.
- Give each signer an inclusive `not_before`, exclusive `not_after`, and one lifecycle
  state:
  - `ACTIVE`: may authorize new admission while the current trusted clock is inside
    the window, and may verify historical receipts signed inside the window;
  - `RETIRED`: may verify historical receipts whose signed `run.ended_at` is inside
    the window, but may never authorize new admission;
  - `REVOKED`: may authorize neither admission nor historical verification.
- Distinguish two deterministic verification modes:
  - `ADMISSION` evaluates the signer against the current UTC time. It never trusts a
    receipt-supplied timestamp to admit a new record;
  - `HISTORICAL` evaluates the signer against the integrity-protected
    `run.ended_at` so normal retirement does not erase previously admitted history.
- Require a configurable threshold of trusted signatures. Overlapping active keys
  support gradual rotation and optional multi-signature policy. A mathematically
  valid unknown signature does not count toward the threshold.
- Detect an exact existing receipt before applying new-admission rules. An identical
  redelivery remains idempotent under a retired key, but the stored artifact is still
  checked using historical trust. Revocation therefore invalidates a fresh reread.
- Seal a compact admission attestation into each checksummed state record. The
  attestation binds the policy ID, admission threshold, and trusted signer
  key-ID/fingerprint pairs to signatures on that receipt. A store opened with a
  trust policy rejects legacy rows without this evidence, preventing an old,
  pre-policy database from being silently promoted to trusted historical state.
- Bump SQLite state from version 3 to 4 and PostgreSQL state from version 2 to 3.
  Runtime components do not migrate schemas; operators rebuild pre-release state and
  re-register authoritative receipts through current-time admission.
- Keep the trust policy outside receipt canonical material and outside database rows.
  It is operator configuration, not a signer-authored assertion. Workers load one
  immutable policy snapshot at startup and must restart for policy changes.
- The production OTLP receiver, drain worker, DataHub Action, state CLI, forensics
  MCP server, DataHub Skill helpers, DataHub receipt emitter, and standalone verifier
  use the same policy implementation. Explicit development overrides are named as
  untrusted or unsigned behavior.
- Raw-file verification and direct DataHub emission default to `ADMISSION`. Only a
  reader that has verified checksummed admission evidence may deliberately select
  `HISTORICAL`; a signer-authored timestamp alone cannot establish prior admission.
- Before binding a receiver socket, require that its configured private signing key
  matches an `ACTIVE` policy entry and current validity window.
- Return only key IDs, public-key fingerprints, lifecycle reason codes, thresholds,
  and bounded integrity gates. Never return a private key, receipt body, or raw
  telemetry from trust diagnostics.

The policy decides signer authority only. It does not establish that receipt claims
are factually correct, that DataHub evidence was true, or that an approval was valid.

## Rotation protocol

1. Generate the replacement key in the deployment secret manager.
2. Derive its public entry with `glassbox-dbom signer-entry`; verify that the command
   returns no private material.
3. Add the replacement as `ACTIVE` before its first use. Keep the old key `ACTIVE`
   during a deliberate overlap if both deployments may sign.
4. Restart readers with the overlapping policy, then restart signers using the new
   private key. Admission probes must succeed with the new fingerprint.
5. Mark the old key `RETIRED` after the overlap. Fresh old-key admission must fail,
   while an exact old receipt and historical read must still succeed.
6. Use `REVOKED` instead of `RETIRED` when key compromise means old signatures can no
   longer be trusted. Expect affected stores and forensic reads to fail closed until
   the incident is explicitly resolved.

The detailed operator procedure and rollback tests are in
[`signing-key-rotation.md`](../operations/signing-key-rotation.md).

## Alternatives considered

- Treat any embedded public key as trusted: rejected because possession is not
  operator authorization.
- Trust `key_id` alone: rejected because an attacker could reuse an authorized ID
  with new key material.
- Evaluate every receipt against `run.ended_at`: rejected for admission because a
  retired key could backdate a newly created receipt.
- Evaluate every receipt against current time: rejected because ordinary rotation
  would make immutable historical receipts unverifiable.
- Delete old keys after rotation: rejected because it destroys historical audit
  availability without expressing whether compromise occurred.
- Persist the complete trust policy with each receipt: rejected because a signer or
  old deployment must not define its own future authorization, and policy changes
  such as revocation must affect fresh verification.
- Fetch keys from a remote JWKS endpoint in the integrity kernel: deferred. Offline,
  deterministic verification and bounded startup are required first. A future
  resolver can translate a pinned remote authority into the same immutable policy.

## Consequences and limits

- Production trust now has an explicit root and auditable rotation semantics.
- Policy distribution and synchronized restarts become operational responsibilities.
  A stale policy can reject a new key or continue accepting a key longer than
  intended.
- `RETIRED` assumes the key was not compromised. If that assumption changes, the
  operator must use `REVOKED` and investigate affected history.
- Historical time is signer-authored but integrity-protected. That is acceptable
  only because checksummed admission evidence proves the same key passed
  current-time authorization before insertion. Importing legacy artifacts must
  therefore use the admission path, not a direct historical bypass.
- The policy is process-global in the current reference deployments; tenant-specific
  policy selection and managed KMS/HSM signing remain future work.
- Trust-policy correctness does not replace DataHub direct readback, dependency
  completeness, materiality policy, approval verification, or replay isolation.

## Reversal conditions

Replace the file-backed registry if DataHub or a standard supply-chain identity
protocol provides an operator-controlled signer authority with equivalent offline
pinning, key-material binding, admission versus historical time semantics,
retirement, compromise revocation, threshold policy, and deterministic failure
evidence. DBOM 0.1 signature bytes and verification rules remain unchanged.
