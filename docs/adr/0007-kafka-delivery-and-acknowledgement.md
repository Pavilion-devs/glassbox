# ADR-0007: Use acknowledged at-least-once Kafka delivery for invalidation

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers

## Context

The invalidation action is useful only if the DataHub metadata change reaches the
plugin and is not acknowledged before the resulting campaign is durably verified.
An in-process `EventEnvelope` proves the action contract, but not broker routing,
schema-registry decoding, framework retry, consumer offset commits, or restart
position. The pinned DataHub Actions `1.6.0.15` Kafka source defaults to a consumer
group named after the pipeline and supports stored asynchronous offsets or explicit
synchronous commits.

The Actions pipeline retries action exceptions, then calls the source's `ack` method
with the action result. Its Kafka source advances the offset only when that result is
successful. A crash after DataHub writeback but before the Kafka commit can therefore
redeliver an event. This is ordinary at-least-once behavior and must not create a new
campaign or corrupt existing metadata.

## Decision

- Deploy the invalidation plugin through the pinned Actions `kafka` source on
  `MetadataChangeLog_Versioned_v1`.
- Use a stable, unique pipeline name as the Kafka consumer-group identity. Never run
  two logically different actions under the same name.
- Set `async_commit_enabled: false` in the reference configuration. The event offset
  is committed synchronously only after the plugin returns success.
- Return success only after every affected campaign has completed deterministic
  double-write and authoritative DataHub readback. Normal no-op classifications are
  also successful and acknowledged.
- Let malformed supported events and failed writeback raise. Configure bounded
  framework retries and a failed-event directory; do not swallow these failures in
  the plugin.
- Make all mutation identities content-addressed and every write idempotent so a
  pre-commit crash or group rebalance can safely redeliver the event.
- Filter at the Kafka source to the MCL aspects the normalizer understands. The
  normalizer still owns semantic validation and feedback-loop protection.
- Treat `auto.offset.reset` as an operator decision. `latest` is acceptable for a new
  forward-only deployment only after the consumer group is established. Recovery or
  backfill may require `earliest` with explicit operational review.
- Keep PGQueue as an unverified alternative until its visibility-timeout,
  acknowledgement, and restart path is exercised independently.

## Live evidence

`examples.end_to_end_broker_invalidation` creates a new consumer group, establishes
same-partition readiness with policy-safe schema changes, then asks GMS to publish a
real used-field type change. A proof-only wrapper throws once before invoking the
production plugin. The pinned Actions pipeline records one exception, retries the
same broker envelope, completes verified GlassBox writeback, and commits the next
Kafka offset synchronously.

The proof then constructs a new pipeline instance with the same group, emits an
unrelated-field negative control, and records every delivered schema offset. The
restart begins after the committed material event, does not replay it, classifies the
new event `UNAFFECTED`, and commits its offset. The sanitized result is
`docs/compatibility/datahub-1.6.0-kafka-invalidation.live.json`.

This proves successful delivery, action retry, synchronous acknowledgement, and
same-group restart. It does not inject a broker-side commit failure, kill the process
inside the commit call, prove PGQueue behavior, or prove clustered receipt-store
coordination. Those claims remain `UNVERIFIED`.

## Alternatives considered

- Acknowledge before DataHub writeback: rejected because a process failure could
  permanently lose the invalidation.
- Use asynchronous offset commits by default: rejected for the reference profile
  because a small throughput gain weakens the clearest reproducible durability
  boundary.
- Claim exactly-once processing: rejected. Kafka delivery and DataHub writes are not
  one transaction; GlassBox provides at-least-once delivery plus deterministic,
  idempotent effects.
- Seek every new group to `earliest`: rejected as a universal default because it can
  trigger an uncontrolled historical invalidation campaign.
- Treat a successful action call as transport proof: rejected because it bypasses
  broker serialization, group coordination, and offset acknowledgement.

## Consequences

- Operators can explain the durability boundary with broker coordinates and
  committed offsets.
- Synchronous commits reduce maximum throughput relative to stored asynchronous
  offsets; invalidation correctness is favored over peak event rate.
- Stable consumer-group identity and offset retention become production state that
  must be monitored and backed by a restart runbook.
- A crash in the writeback-to-commit window can repeat verified writes. This is safe
  only while campaign IDs, incident writes, receipt merge semantics, and audit
  records remain idempotent.
- The pinned pipeline logs acknowledgement exceptions but does not run the action
  retry loop for an `ack` exception. Broker redelivery after restart is the recovery
  mechanism; that exact fault path still needs a destructive integration test.

## Reversal conditions

This profile may change if DataHub Actions provides a transactional source/writeback
boundary, a durable outbox integrated with source acknowledgement, or a stronger
documented delivery primitive. Any replacement must retain honest at-least-once
semantics, direct write verification, deterministic redelivery, and explicit offset
recovery evidence.
