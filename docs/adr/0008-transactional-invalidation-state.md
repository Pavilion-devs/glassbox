# ADR-0008: Add a transactional single-host invalidation state profile

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers

## Context

The original checksummed JSONL receipt store and audit log are intentionally
single-process. They make corruption and conflicting receipt metadata visible, but
they cannot atomically maintain a receipt plus its reverse index, coordinate two
action workers, recover abandoned work, or bind campaign completion to its audit
checkpoint. Those gaps matter under Kafka's at-least-once delivery model: a worker
can crash after DataHub writeback but before broker acknowledgement, and another
worker must safely determine whether to execute, wait, recover, or only re-verify.

A multi-host database is ultimately required for a horizontally distributed Actions
deployment. Introducing one without a reproducible local correctness profile would
hide the hardest state-machine decisions behind infrastructure. Python already ships
SQLite, whose WAL and locking behavior can prove transactional and competing-process
semantics on one local host without adding a runtime dependency.

## Decision

- Add `SQLiteInvalidationStore` as the recommended local and single-host
  multi-process profile. Retain the JSONL profile for compatibility and simple
  inspection, but label it single-process.
- Store each full signed DBOM receipt and all of its dependency-index rows in one
  `BEGIN IMMEDIATE` transaction. Verify the receipt before opening the transaction.
- Re-verify receipt signatures and domain-separated record checksums whenever rows
  are read. Run SQLite `quick_check` and `foreign_key_check` during initialization
  and explicit integrity verification.
- Stage the canonical campaign and its deterministic `CLASSIFIED` audit record in
  one transaction. A positively unaffected campaign is immediately `COMPLETED`; a
  material campaign enters `READY`.
- Claim work through a closed `READY -> LEASED -> COMPLETED` state machine. A live
  lease blocks every worker, including another process using the same configured
  worker label. An expired lease can be claimed and increments the attempt count.
- Renew the lease between the two idempotency writes and before direct verification.
  Failure returns owned work to `READY` and atomically records only the exception
  type, never the exception message.
- Seal authoritative `InvalidationWriteEvidence` and the deterministic
  `DATAHUB_VERIFIED` audit record in the same completion transaction.
- On broker redelivery of an already completed campaign, perform zero DataHub
  mutations. Re-read DataHub authoritatively and require the result to equal the
  sealed evidence before returning success.
- Keep broker acknowledgement outside the database transaction. The Actions plugin
  returns success only after the synchronous executor has either completed and
  verified the task or freshly verified an existing completion.
- Provide `glassbox-invalidation-state` for initialization, signed-receipt
  registration, integrity verification, and bounded status output.
- Configure the profile with `state_database_path`. It is mutually exclusive with
  the legacy `receipt_store_path` and `audit_log_path` pair.

## Evidence

The offline suite proves:

- forced dependency-index failure rolls back the receipt row;
- identical registration is a no-op and conflicting metadata fails;
- exactly one of two spawned operating-system processes claims a live lease;
- another worker cannot claim before expiry and can recover after expiry;
- failed DataHub writes release work without persisting sensitive exception text;
- completion and verification audit are atomic and idempotent;
- a second worker performs zero writes for completed material work and only succeeds
  after fresh direct readback;
- application-level record corruption fails initialization and integrity checks;
- invalid mixed state configuration is rejected.

The live Kafka report
`docs/compatibility/datahub-1.6.0-kafka-invalidation.live.json` additionally proves
that the installed plugin uses this profile during genuine MCL delivery, action
retry, synchronous Kafka commit, and same-group restart. The original ADR-0008 run
contained one verified receipt, one dependency, five deterministic campaigns, and
six audit records. A separate material redelivery reused the completed campaign with
zero emissions and fresh DataHub readback. The later ADR-0009 proof extended the
current committed run to seven audit records and one completed owner-routing task.

## Alternatives considered

- Add file locking around JSONL: rejected because multiple append-only files still
  cannot provide atomic receipt/index or campaign/audit transitions.
- Acknowledge Kafka after durable enqueue and process later: rejected for the current
  profile because GlassBox's contract requires verified DataHub state before
  acknowledgement.
- Claim exactly-once processing: rejected. The database and DataHub are not one
  transaction. Effects remain at-least-once and idempotent.
- Implement PostgreSQL first: deferred, not rejected. PostgreSQL is the intended
  multi-host adapter, but it should implement this now-tested state machine rather
  than inventing semantics inside deployment code.
- Persist exception messages for diagnostics: rejected because upstream clients and
  drivers may include tokens, hosts, or sensitive query material.

## Consequences and limits

- One shared local database safely coordinates multiple processes on one host.
- SQLite files must live on a local filesystem. Network filesystems, Kubernetes
  multi-node mounts, and multiple independent copies are unsupported.
- Checksums detect accidental corruption and unauthorized edits that do not recompute
  them. They are not a cryptographic defense against a database administrator; signed
  receipts retain their separate authenticity boundary.
- Lease duration must exceed ordinary writeback latency and be monitored. Steal after
  expiry can duplicate DataHub calls, which remain deterministic and idempotent.
- Owner notification was not part of the original version-1 schema. ADR-0009 adds a
  version-2 owner-routing outbox with an atomic completion-to-obligation boundary;
  remote delivery remains at-least-once and idempotency-keyed.
- Database schema migration is currently bootstrap-only and the version is checked
  exactly. Online migration machinery is required before changing the schema in a
  released deployment.

## Reversal conditions

Use PostgreSQL or another transactional multi-host adapter when workers span hosts,
when local-disk durability is insufficient, or when operational tooling requires
server-side backups and migrations. Any replacement must preserve the tested atomic
boundaries, lease takeover rules, checksums, signature re-verification, deterministic
campaign identity, sealed write evidence, and acknowledgement-after-verification
contract.
