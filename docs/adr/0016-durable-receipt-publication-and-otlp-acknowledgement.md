# ADR-0016: Make receipt publication a durable acknowledged obligation

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers
- **Supersedes in part:** [ADR-0015](0015-register-receipts-before-datahub-publication.md)
- **Extends:** [ADR-0010](0010-postgresql-multi-worker-invalidation-state.md)

## Context

ADR-0015 made receipt registration precede DataHub publication and required callers
to withhold acknowledgement until direct readback succeeded. Its remaining repair
mechanism was upstream redelivery of the same run. A process could crash after state
registration while the telemetry sender was no longer available, leaving a valid
receipt with no durable worker obligation to finish publication.

PostgreSQL and DataHub cannot share a transaction. The system therefore needs an
explicit, recoverable state machine rather than an exactly-once claim.

## Decision

- Atomically insert one `READY` receipt-publication row with every new signed receipt
  and dependency projection. Registration rolls back if any of those writes fail.
- Use `READY`, `LEASED`, and `COMPLETED` states, attempt counters, bounded error types,
  worker ownership, and expiring leases. SQLite uses the caller clock for its
  single-host profile. PostgreSQL locks the exact row with `SELECT ... FOR UPDATE`
  and uses the database server clock.
- A publisher claims the obligation, rereads and verifies the stored receipt,
  performs two deterministic DataHub upserts, directly reads the persisted aspects,
  and atomically seals checksummed publication evidence.
- Publication evidence contains only the deterministic Document URN, sorted aspect
  names, and the required emission count. It contains no telemetry body, receipt
  body, server response, token, or driver message.
- A completed delivery is never reclaimed. Redelivery directly verifies that every
  sealed aspect is still present and performs zero DataHub writes. Additional
  DataHub aspects are allowed because other governed workflows may add them later.
- A failed DataHub operation returns the owned task to `READY` with only the
  exception type. If the completion transaction itself is uncertain, the task stays
  leased until expiry rather than risking concurrent repair.
- Provide a bounded `drain` worker that repairs non-completed obligations without
  requiring the original OTLP sender.
- Provide a deployable OTLP/HTTP JSON receiver at `POST /v1/traces`. It accepts only
  a single content-length-delimited `application/json` body, enforces body/span/time
  limits, optionally authenticates a bearer token with constant-time comparison,
  compiles with a fresh direct-read DataHub URN resolver, and returns HTTP 200 only
  after the publication obligation is sealed.
- Return 400 for invalid OTLP, 401 for failed authentication, 413 for an oversized
  body, 415 for the wrong media type, and 503 for a live publication failure. Error
  responses expose only closed stages and exception types.
- Refuse an unauthenticated non-loopback bind unless the operator supplies an
  explicit unsafe override. Tokens, signing keys, DataHub credentials, and
  PostgreSQL DSNs are loaded through named environment variables.
- Keep the reference server single-flight with a bounded accept queue. Horizontal
  replicas coordinate through PostgreSQL. TLS termination, rate limiting, and
  tenant authentication remain deployment responsibilities.
- Bump SQLite state from version 2 to 3 and PostgreSQL state from version 1 to 2.
  Runtime workers reject every other version and issue no DDL. This pre-release
  change intentionally has no implicit migration; operators must bootstrap a fresh
  schema and re-register authoritative signed receipts.

## Crash semantics

| Failure point | Durable state | Recovery |
| --- | --- | --- |
| Before registration commits | No receipt or obligation | Sender retries |
| After registration, before claim | `READY` | Sender or drain worker claims |
| During DataHub mutation/readback | Returned to `READY` when ownership is known | Idempotent double-write retry |
| After DataHub succeeds, before completion commits | `LEASED` until expiry | Retry deterministic writes, then seal |
| After completion commits, before HTTP response | `COMPLETED` | Sender retry performs zero-write readback |

This is at-least-once repair with deterministic remote identity, not a claim of an
exactly-once distributed transaction.

## Evidence

- SQLite tests prove atomic receipt-plus-obligation rollback, competing leases,
  failure release, recovery, evidence checksums, missing-obligation detection, and
  completed zero-write verification.
- Real HTTP tests prove bearer rejection, media/body bounds, 200-after-seal, 503 with
  durable `READY` state, independent recovery, and zero-write identical redelivery.
- PostgreSQL integration tests prove exact-row publication locks, one winner across
  eight connections, database-clock lease behavior, atomic rollback, completion,
  and full integrity reconstruction.
- The combined DataHub/PostgreSQL proof remains responsible for establishing real
  DataHub double-write and direct-readback behavior; in-memory transports are not
  treated as proof of DataHub compatibility.

Sanitized evidence is committed in
[`postgresql-16-receipt-publication-outbox.live.json`](../compatibility/postgresql-16-receipt-publication-outbox.live.json)
and
[`datahub-1.6.0-postgresql-otlp-receiver.live.json`](../compatibility/datahub-1.6.0-postgresql-otlp-receiver.live.json).

## Alternatives considered

- Depend permanently on OTLP redelivery: rejected because the sender may disappear
  after state registration.
- A memory queue: rejected because process death loses the repair obligation.
- A transaction spanning PostgreSQL and DataHub: unavailable and therefore not
  claimed.
- Mark complete immediately after upsert: rejected because a successful client call
  is not direct persistence evidence.
- Re-upsert completed work: rejected because completed retry must be a read-only
  verification path.
- Store raw DataHub responses for debugging: rejected because it expands the secret
  and metadata exposure surface without strengthening the proof.

## Consequences and limits

- Receipt publication is now recoverable without the telemetry producer.
- HTTP acknowledgement has an executable durability meaning rather than signaling
  only request acceptance.
- DataHub can still receive repeated deterministic writes after an uncertain crash.
  Its stable receipt URN and merge-safe projection remain mandatory.
- A single reference receiver process serializes requests. Production throughput
  should use multiple authenticated replicas behind a bounded proxy and the shared
  PostgreSQL authority.
- Lease expiry determines repair latency after an uncertain completion failure.
- The receiver supports OTLP protobuf JSON, not protobuf binary or OTLP gRPC.
- TLS, per-tenant policy, managed failover, online state migration, and admission
  rate limiting are not yet live-proven.

## Reversal conditions

Replace this protocol if DataHub exposes a native transactional receipt ingestion
API that durably acknowledges the same signed artifact and provides equivalent
direct verification. Add an explicit migration ADR before accepting an existing
state version in place.
