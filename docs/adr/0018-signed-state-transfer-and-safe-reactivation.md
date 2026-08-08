# ADR-0018: Transfer trusted receipt state without reviving operational side effects

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0010](0010-postgresql-multi-worker-invalidation-state.md),
  [ADR-0016](0016-durable-receipt-publication-and-otlp-acknowledgement.md), and
  [ADR-0017](0017-operator-trusted-receipt-signers-and-rotation.md)

## Context

SQLite and PostgreSQL intentionally reject unknown state schema versions. That
prevents a runtime from interpreting old bytes with new semantics, but the earlier
rebuild-only answer is not enough for a durable ecosystem component. Operators need
to move authoritative receipt history between engines and across future schema
changes without copying implementation-specific tables or trusting a database dump
as a portable contract.

A naive full-database restore is unsafe. Publication, campaign, and owner-routing
outboxes contain leases, retry counters, completed remote-side-effect evidence, and
worker identities. Replaying those rows in another authority could repeat DataHub
writes, incident mutations, or notifications. A bundle signature alone also cannot
turn an unknown or retired receipt signer into an authorized producer.

## Decision

- Publish the closed State Transfer 0.1 JSON contract under
  `schemas/state-transfer/0.1.0/`. Its canonical payload is RFC 8785 JSON, committed
  by a domain-separated SHA-256 digest and a
  `gbx:state-transfer:sha256:<digest>` content address.
- Require one or more Ed25519 signatures from a separate operator-controlled
  state-transfer trust policy. The existing signer-policy format supplies key-ID and
  public-key-fingerprint binding, active windows, lifecycle states, and configurable
  signature thresholds. Transfer authority is not receipt authority.
- Export only after the source store passes database, checksum, reverse-index,
  receipt-integrity, and historical signer-trust verification.
- Transfer the exact signed receipt, externally established field-lineage proof,
  and supersession pointer. Include campaign, audit, publication, and routing state
  as a signed operational archive for investigation, with
  `activated_on_import=false` fixed by schema.
- Verify every embedded receipt again using current-time `ADMISSION` under the
  destination receipt-signer policy. Retirement, revocation, unknown keys, threshold
  failure, or receipt tampering rejects the entire transfer before target creation in
  the operator CLI. A valid transfer authority cannot launder receipt trust.
- Activate all receipts in one database transaction. Any conflict or failed
  admission rolls back the complete batch in SQLite and PostgreSQL.
- Create a fresh `READY` receipt-publication obligation only when a receipt is newly
  inserted. Exact existing receipts remain idempotent. Never import old lease owners,
  expiration times, retry counters, campaign tasks, routing tasks, audit rows, or
  completed publication evidence into live target tables.
- Bound files to 128 MiB and contract arrays to explicit maxima. Read only regular
  files, refuse symbolic links and changed-during-read files, create outputs with
  mode `0600`, and refuse overwrites. CLI results contain bounded identities,
  fingerprints, counts, and reason codes, never private keys or receipt bodies.
- Support SQLite-to-SQLite, SQLite-to-PostgreSQL, PostgreSQL-to-SQLite, and
  PostgreSQL-to-PostgreSQL through the same semantic contract. Physical table and
  database dumps remain engine-specific backup mechanisms, not migration contracts.
- Keep import scope `RECEIPTS_ONLY` in version 0.1. Campaign restoration would need
  a separately authorized recovery protocol that reasons about every remote side
  effect; it must not be smuggled into state migration.

The source runtime must still understand its database schema to export it. Therefore,
before shipping a future incompatible schema, maintainers must preserve an exporter
in the old supported release and prove old-export/new-import compatibility. This
decision does not retroactively teach the current runtime to open unsupported
pre-policy schemas.

## Alternatives considered

- Copy SQLite or PostgreSQL tables directly: rejected because checksums, schema
  meanings, and binary encodings are implementation details and cross-engine copying
  is not a trust decision.
- Import every outbox and audit row as live state: rejected because stale leases and
  uncertain remote effects could repeat mutations.
- Trust the bundle signature instead of receipt signatures: rejected because a
  migration operator is not automatically authorized to author decision history.
- Verify receipt signers at their signed run time: rejected because a retired signer
  could backdate newly imported material. Import is new admission.
- Insert receipts one at a time and report partial success: rejected because a
  portable state unit must have an unambiguous all-or-nothing activation result.
- Encrypt bundles in the application format: deferred. Storage and transport
  encryption belong to the operator's secret-management and backup boundary. The
  bundle already excludes raw prompts, outputs, and tool bodies by DBOM design, but
  its metadata can still be sensitive and must be protected.

## Consequences and limits

- Operators gain a deterministic, offline-verifiable, cross-engine migration path
  without weakening signer admission or repeating completed work.
- Transfer-authority policy and private-key custody become additional operational
  responsibilities. Threshold signing is supported by repeating the CLI key option.
- The signed operational archive proves what the exporter observed; it is not a
  runnable backup and does not claim that remote systems still match old evidence.
- Import can intentionally schedule a DataHub receipt projection again in the new
  environment. The existing idempotent double-write and direct-readback worker owns
  that remote boundary.
- Version 0.1 loads a bounded bundle in memory and caps it at 10,000 receipts. Larger
  estates need a future chunked manifest with atomic cohort semantics.
- The current integration suite proves cross-engine equivalence and transactional
  rollback against PostgreSQL 16. Managed failover and concurrent migration while
  writers remain active require deployment-specific testing.

## Reversal conditions

Replace this format if DataHub or a standard provenance supply-chain format provides
equivalent content addressing, separate migration authority, current receipt
admission, field-lineage and supersession fidelity, atomic cross-engine activation,
and an explicit non-reactivation rule for operational side effects. Never replace it
with an opaque database dump alone.
