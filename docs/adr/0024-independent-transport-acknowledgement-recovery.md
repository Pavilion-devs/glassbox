# ADR-0024: Prove transport acknowledgement recovery independently

- **Status:** Accepted
- **Date:** 2026-08-08
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0007](0007-kafka-delivery-and-acknowledgement.md) and
  [ADR-0008](0008-transactional-invalidation-state.md)

## Context

An action can finish its DataHub writes and still fail before its event source
records acknowledgement. That boundary is where an at-least-once system proves
whether idempotency is real. A normal successful commit does not demonstrate
recovery, and an in-process replay does not demonstrate broker or queue state.

DataHub Actions 1.6.0.15 has two materially different sources in scope. Kafka
commits a next offset through a retried synchronous client call. PostgreSQL Queue
leases a message per consumer group, withholds it until visibility expiry, and
advances a contiguous `enqueue_seq` watermark transactionally on acknowledgement.
Combining their evidence would hide different failure modes.

## Decision

- Keep Kafka and pgQueue reports separate. A success in one transport never marks
  the other transport proven.
- For Kafka, use `async_commit_enabled=false` and fail every client commit attempt
  in one configured acknowledgement retry window before any call reaches the
  broker. Confirm through an independent consumer that the committed offset did not
  pass the target event. Start a fresh Actions pipeline with the same group and
  require the exact topic, partition, and offset to return.
- For pgQueue, use the official `pg_queue` Actions source, `DatahubPgQueueConsumer`,
  and `PgQueueRepository` against PostgreSQL 16. Fail one acknowledgement before
  its database transaction. Require the persisted offset to remain behind the
  target, the lease to remain active, a fresh same-group process to be blocked
  before expiry, and the exact message handle to return after expiry.
- In both proofs, the first delivery must complete verified DataHub writeback. The
  recovered delivery must reuse the same completed campaign, perform zero DataHub
  emissions, repeat fresh direct readback, and reuse completed owner routing.
- After recovery acknowledgement, verify the source authority directly: Kafka's
  committed offset must advance past the event; pgQueue's ack marker and contiguous
  offset must persist. A third restart must not return the recovered event.
- Use a genuine GMS-produced MCL. The pgQueue proof captures its Avro MCL from the
  real GMS-to-Kafka path, then stores those official schema bytes through the
  pgQueue repository because the pinned GMS deployment is Kafka-backed.
- Label fault origin precisely. These are deterministic test-harness failures at
  the client boundary before commit. They prove real uncommitted broker/database
  state and recovery, but not a physical Kafka outage, PostgreSQL outage, network
  partition, or ambiguous commit response.
- Initialize the proof database from DataHub's canonical V001 pgQueue schema pinned
  at commit `93336230f49c27eed0c07d3d2d4350781a256ba5`. Stock PostgreSQL uses one
  proof-only default message partition. Production `pg_partman` creation and
  maintenance remain explicitly unverified.

## Evidence

The Kafka report records three exhausted commit attempts, one failed Actions
acknowledgement, an unchanged committed offset at the target, exact same-offset
redelivery, zero emissions, fresh readback, and a successful recovery commit:
[`datahub-1.6.0-kafka-invalidation.live.json`](../compatibility/datahub-1.6.0-kafka-invalidation.live.json).

The pgQueue report records offset `0` after failed acknowledgement, an active lease,
pre-expiry restart exclusion, exact handle redelivery, zero emissions, fresh
readback, persisted ack marker, contiguous offset `1`, and an empty third restart:
[`datahub-1.6.0-pgqueue-invalidation.live.json`](../compatibility/datahub-1.6.0-pgqueue-invalidation.live.json).

## Alternatives considered

- Invoke the Action twice in-process: rejected because it proves application
  idempotency but not transport redelivery or persisted acknowledgement state.
- Stop Kafka after a successful commit and call that restart recovery: rejected
  because the material event cannot return after its offset advances.
- Pause or kill the shared Kafka container during commit: rejected for this proof
  because it introduces unrelated group/session behavior and is less deterministic.
  A physical outage remains a separate operational exercise.
- Treat pgQueue as Kafka-compatible by inference: rejected because visibility,
  leases, ack markers, and contiguous watermarks are distinct contracts.
- Claim full DataHub pgQueue production parity from a default PostgreSQL partition:
  rejected because `pg_partman` lifecycle and retention maintenance were not run.

## Consequences and limits

GlassBox now has real source-authority evidence for the most dangerous normal
redelivery boundary: remote work completed, acknowledgement failed, and a fresh
process recovered without duplicate effects. The harnesses are reusable against
future pinned DataHub versions and will fail if source metadata, retry, lease, or
offset semantics drift.

This does not prove exactly-once delivery, ambiguous-response recovery, database or
broker failover, network partitions, physical multi-host deployment, or
`pg_partman` maintenance. Remote adapters still need stable idempotency keys because
a process can die after remote acceptance but before local completion.

## Reversal conditions

Replace these harnesses if DataHub exposes a first-class source conformance suite
that proves the same persisted failure boundaries for external Actions. Keep the
two transport claims separate unless DataHub adopts one shared acknowledgement
authority with identical observable semantics.
