# ADR-0010: Add a PostgreSQL invalidation-state profile for distributed workers

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers
- **Amended by:** [ADR-0016](0016-durable-receipt-publication-and-otlp-acknowledgement.md),
  which adds the third outbox and defines current schema versions.

## Context

ADRs 0008 and 0009 define the signed receipt index, campaign outbox, verification
audit, and owner-routing outbox. Their first implementation uses SQLite WAL and is
correct for multiple processes on one host. SQLite files must not be shared over a
network filesystem, so that profile cannot coordinate DataHub Actions workers that
run on different hosts.

The state adapter is also part of the acknowledgement boundary. A server-database
implementation must preserve the existing atomic transitions and application-level
integrity checks. Merely replacing SQL syntax or using a process mutex would not
establish a distributed claim protocol.

## Decision

- Provide `PostgresInvalidationStore` through the optional `postgres` package extra,
  using psycopg 3 and PostgreSQL 14 or newer.
- Preserve one behavioral protocol across SQLite and PostgreSQL: signed receipt
  registration, reverse lookup, campaign leases, sealed DataHub evidence, durable
  owner-routing obligations, append-only audit, and full integrity verification.
- Use `SELECT ... FOR UPDATE` on exact outbox rows for campaign and routing claims.
  Concurrent workers therefore serialize the state transition in PostgreSQL rather
  than trusting a process-local lock.
- Use PostgreSQL `clock_timestamp()` for lease acquisition, renewal, and expiration.
  The caller timestamp remains validated for API parity but is not authoritative, so
  skewed worker clocks cannot prematurely steal a live lease.
- Initialize a named, identifier-validated schema under a transaction-scoped advisory
  lock. PostgreSQL schema version 1 is independent from SQLite schema version 2.
- Separate bootstrap from runtime. `postgres-init` may issue DDL; the DataHub Actions
  plugin opens with `initialize_schema=False`, verifies an existing schema, and never
  creates tables. Operators can therefore give runtime workers DML-only privileges.
- Load the DSN only from a named environment variable in the plugin and operator CLI.
  Configuration, status output, audit records, and committed evidence never contain
  the DSN.
- Keep one short-lived connection per operation in the initial reference adapter.
  This favors an explicit transaction boundary; deployments may put PgBouncer in
  front until a measured in-process pool is justified.
- Reuse the canonical codecs and domain-separated checksum rules implemented by the
  transactional package. These helpers are currently internal to the SQLite module;
  extracting a public codec module is a future cleanup, not a semantic fork.
- Do not automatically migrate SQLite state into PostgreSQL. Operators re-register
  signed receipts from their authoritative artifacts, and pending campaigns require
  an explicit future migration tool.

## Evidence

The real PostgreSQL 16 integration suite proves:

- atomic receipt-plus-dependency rollback under a trigger-injected failure;
- idempotent receipt registration and reverse candidate lookup, with exact
  reconstruction of every index row from verified receipt material;
- eight independent connections racing for one campaign row produce one claim
  winner;
- a future-skewed caller clock cannot steal a live lease, while a genuinely expired
  lease recovers;
- campaign completion and owner-routing obligation creation remain atomic;
- routing failure recovers without another DataHub mutation;
- completed redelivery performs zero writes while repeating verification;
- schema-version, checksum-corruption, missing-bootstrap, unsafe-schema, and secret
  exposure checks fail closed;
- the installed DataHub Actions factory opens the initialized PostgreSQL profile.

The guarded `examples.postgres_invalidation_proof` run records PostgreSQL 16.14,
eight connections, one winner, server-clock recovery, completed dual outboxes, and
verified redelivery in the committed sanitized report. The proof uses one local
Docker server and a deterministic stand-in for DataHub mutation because the database
coordination boundary is the subject of this run. The separate Kafka proof remains
the evidence for real DataHub writeback and broker delivery.

## Alternatives considered

- Share SQLite over NFS: rejected because SQLite locking and durability guarantees do
  not make that a safe distributed-worker contract.
- Use application mutexes: rejected because processes on separate hosts do not share
  memory and crash recovery still belongs in durable state.
- Trust each worker's wall clock: rejected because clock skew can create overlapping
  leases.
- Claim exactly-once processing: rejected because PostgreSQL, DataHub, Kafka, and a
  webhook do not share one transaction. GlassBox provides durable obligations,
  idempotent identities, direct verification, and at-least-once recovery.
- Run DDL from every production worker: rejected as an unnecessary privilege and
  deployment race. Bootstrap is an operator action.

## Consequences and limits

- The profile is suitable for workers that connect to the same PostgreSQL authority
  from different hosts, but the committed proof does not claim a physical multi-host
  deployment.
- Managed failover, network partitions, transaction-pooler modes, TLS policy, backup
  restoration, and online upgrades are not yet live-proven.
- Bootstrap credentials need schema-creation rights. Runtime roles need the
  documented table and sequence privileges; a turnkey grant generator is future
  work.
- Per-operation connections are intentionally simple but can be expensive at high
  throughput. External pooling and bounded connection limits remain deployment
  responsibilities.
- A crash after a remote side effect and before PostgreSQL completion can repeat that
  side effect. Deterministic DataHub writes and the webhook idempotency key remain
  required.

## Reversal conditions

Replace this adapter if DataHub exposes a native transactional work queue that can
preserve the signed receipt, dual-outbox, direct-verification, and recovery
invariants. Supersede this ADR when an explicit migration framework or a different
server database proves equal semantics under concurrency and failure injection.
