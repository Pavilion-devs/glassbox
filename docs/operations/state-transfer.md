# Signed invalidation-state transfer

This runbook moves trusted GlassBox receipts between SQLite and PostgreSQL or across
future supported schema transitions. It does not restore active campaigns, leases,
audit rows, or owner notifications. Those records are preserved in the signed bundle
as an inactive operational archive.

## What the transfer proves

A successful import establishes all of the following:

1. the source store passed its native integrity checks before export;
2. the canonical bundle digest and content address match;
3. the required active migration authorities signed that digest;
4. every embedded receipt independently passes the destination's current signer
   admission policy;
5. receipt, field-lineage, and supersession metadata were activated in one target
   database transaction;
6. each new receipt has one fresh `READY` DataHub publication obligation; and
7. no archived campaign, lease, retry, routing, audit, or completion state became
   executable.

The transfer does not prove that receipt claims are factually true or that an old
remote side effect is still present.

## Prepare the authorities

Use one trust policy for receipt producers and another for migration operators. The
policies share the `glassbox.signer-trust.v1` format but should not reuse private
keys. Generate the transfer private key in a secret manager and expose it only
through a named environment variable. Derive its public policy entry exactly as in
the [signing-key rotation runbook](signing-key-rotation.md):

```bash
glassbox-dbom signer-entry \
  --key-id glassbox-transfer-2026-08 \
  --private-key-env GLASSBOX_STATE_TRANSFER_SIGNING_KEY \
  --not-before 2026-08-07T00:00:00Z
```

Create and validate a dedicated transfer policy, then set both public-policy paths:

```bash
glassbox-dbom verify-policy /etc/glassbox/trusted-receipt-signers.json
glassbox-dbom verify-policy /etc/glassbox/trusted-transfer-signers.json
export GLASSBOX_SIGNER_TRUST_POLICY_PATH=/etc/glassbox/trusted-receipt-signers.json
export GLASSBOX_STATE_TRANSFER_TRUST_POLICY_PATH=/etc/glassbox/trusted-transfer-signers.json
```

Do not place a private key in either policy, a command argument, a bundle, a log, or
shell history. The CLI argument names only the environment variable holding it.

## Export SQLite

Quiesce receipt and campaign writers when a point-in-time operational archive is
required. Export refuses an unsupported schema, a corrupt source, an untrusted
historical receipt, an inactive transfer key, a symbolic-link destination, or an
existing output file.

```bash
glassbox-invalidation-state export-transfer \
  /var/lib/glassbox/invalidation.sqlite3 \
  /secure-transfer/glassbox-state-0.1.json \
  --transfer-signing-key \
  glassbox-transfer-2026-08=GLASSBOX_STATE_TRANSFER_SIGNING_KEY
```

For a transfer policy whose threshold is two, repeat `--transfer-signing-key` with a
different key ID and environment variable. Duplicate key IDs fail closed.

## Export PostgreSQL

The source schema must already exist; export never bootstraps it.

```bash
export GLASSBOX_STATE_POSTGRES_DSN='postgresql://...'
glassbox-invalidation-state postgres-export-transfer \
  /secure-transfer/glassbox-state-0.1.json \
  --dsn-env GLASSBOX_STATE_POSTGRES_DSN \
  --schema glassbox \
  --transfer-signing-key \
  glassbox-transfer-2026-08=GLASSBOX_STATE_TRANSFER_SIGNING_KEY
```

## Verify offline before import

Move the bundle through an encrypted, access-controlled channel. On the destination,
load its independent copies of both policies and verify before provisioning target
state:

```bash
glassbox-invalidation-state verify-transfer \
  /secure-transfer/glassbox-state-0.1.json
```

Require `valid: true`, the expected content-addressed `bundle_id`, source engine and
schema version, expected receipt count, and the intended transfer key IDs and
fingerprints. The output is deliberately raw-free.

## Import SQLite

Stop target workers, back up any existing target, and import:

```bash
glassbox-invalidation-state import-transfer \
  /var/lib/glassbox/invalidation.sqlite3 \
  /secure-transfer/glassbox-state-0.1.json

glassbox-invalidation-state verify \
  /var/lib/glassbox/invalidation.sqlite3
```

`inserted + reused` must equal `total`. A conflict rolls back every insertion from
that import attempt.

## Import PostgreSQL

Use bootstrap credentials only for a new schema, then restore the normal least-
privilege runtime identity after import:

```bash
glassbox-invalidation-state postgres-import-transfer \
  /secure-transfer/glassbox-state-0.1.json \
  --dsn-env GLASSBOX_STATE_POSTGRES_DSN \
  --schema glassbox

glassbox-invalidation-state postgres-verify \
  --dsn-env GLASSBOX_STATE_POSTGRES_DSN \
  --schema glassbox
```

The CLI verifies the entire bundle before creating or modifying the target schema.
The receipt batch then commits or rolls back as one PostgreSQL transaction.

## Resume safely

Start the receipt-publication drain worker first. Every newly inserted receipt is
`READY`, regardless of the archived source task's old status. The worker's stable
Document URN, idempotent double-write, and direct readback make this a repairable
publication, not a blind replay. Start campaign consumers only after state and
publication health are confirmed.

Never treat the archived operational records as live tasks. If a campaign must be
recovered, investigate the current DataHub state and use a future explicitly
authorized recovery contract; do not edit the database or bundle.

## Failure and rollback

- Verification failure: fix policy distribution or reject the artifact. No target
  should have been created by the CLI.
- Receipt conflict: preserve both stores and investigate lineage/supersession
  disagreement. The batch is rolled back.
- Publication failure after import: keep the new state and repair through the durable
  publication worker. Do not re-import to force a write.
- Wrong but uncompromised transfer key: correct the transfer policy or re-export with
  an authorized key.
- Suspected transfer-key compromise: mark it `REVOKED`, reject affected bundles, and
  re-export from the verified source with a new authority.
- Unsupported old database: run the exporter from the last release that supports
  that schema. Do not patch the metadata version or bypass startup verification.

Retain the bundle ID, source/target versions, counts, signer fingerprints, verification
result, import result, and source/target backup identifiers. Do not retain private
keys, DSNs, tokens, or raw receipt bodies in migration logs.
