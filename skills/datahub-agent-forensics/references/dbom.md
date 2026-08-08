# Decision Bill of Materials (DBOM) reference

A DBOM is an append-only receipt for one consequential agent output. Prefer the
signed JSON artifact over its DataHub summary projection.

## Integrity gates

Verify all of these before deterministic impact or replay:

- JSON Schema;
- RFC 8785 canonical payload digest;
- content-addressed receipt ID;
- evidence/action/evaluation/output Merkle root;
- at least one required valid Ed25519 signature;
- the configured threshold of operator-trusted key IDs and public-key fingerprints.

A failed gate makes the receipt invalid. An unavailable verifier makes it
`NOT_VERIFIED`, not valid. Signature verification establishes byte integrity and key
possession only. New receipt admission requires an `ACTIVE` signer at current time;
historical investigation accepts `ACTIVE` or `RETIRED` only when checksummed state
first proves prior admission and the signed run time is inside its window. `REVOKED`
always fails.

## Investigation fields

- `run`: identity, status, time, trace, parent, environment.
- `agent`, `workflow`, `models`, `skills`, `tools`: exact version/source pins.
- `evidence`: DataHub URNs, field URNs, epistemic state, influence role, digest, time.
- `queries`: language and statement digest; raw statements remain redacted.
- `actions`: tool, effect, outcome, input/output digests, idempotency and approval IDs.
- `approvals`: issuer, exact action digest, policy, issue/expiry/revocation.
- `output`: kind, MIME type, digest, redaction status.
- `replay`: eligibility, reason, prior receipt digest.
- `extensions`: producer and replay artifact bindings.

Array order is causal material. Reordering evidence, actions, approvals, or
evaluations changes integrity by design.

## Safe wording

Say “the verified receipt records an observed dependency” rather than “the data was
true.” Say “the DataHub projection identifies receipt X” rather than “the Document
signature verified” unless the signed DBOM was actually checked.
