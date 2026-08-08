# ADR-0009: Make DataHub owner routing a durable, idempotent obligation

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers

## Context

ADR-0008 made incident and quarantine writeback recoverable, but owner routing still
ran after campaign completion without durable state. A crash in that gap could lose
the notification, while blind broker redelivery could repeat it. The original
`OwnerRouter` accepted the deterministic campaign ID, but local state did not record
whether routing was pending, leased, failed, or accepted.

DataHub ownership is the governed source for routing identity. Notification systems
are still separate services, so GlassBox cannot atomically commit SQLite and a
remote webhook. The honest contract is durable local obligation plus at-least-once
dispatch with a stable remote idempotency key, not exactly-once human delivery.

## Decision

- Bump the transactional state schema to version 2. Refuse older or unknown schema
  versions; do not mutate them opportunistically.
- When verified DataHub writeback completes, create an owner-routing obligation in
  that same SQLite transaction. If either transition fails, neither is committed.
- Give routing its own `READY -> LEASED -> COMPLETED` state machine, attempt count,
  expiry recovery, bounded failure type, and deterministic audit phases.
- Resolve owners from the changed entity's native DataHub `ownership` aspect. Never
  infer an owner from receipt content or an LLM.
- Provide `DataHubOwnershipWebhookRouter`. It sends a bounded manifest containing
  campaign/change identity, aggregate impact counts, quarantine count, and sorted
  owner URNs. It excludes receipt bodies, prompts, tool arguments, and evidence
  content.
- Use the campaign ID as the HTTP `Idempotency-Key`. Require HTTPS by default;
  insecure HTTP is an explicit option intended for loopback testing. Reject embedded
  URL credentials, query strings, and fragments.
- Do not follow webhook redirects, so credentials and owner identifiers remain bound
  to the configured endpoint.
- Load an optional bearer token from a named environment variable. Do not place the
  token itself in the Actions configuration or persisted state.
- Seal only the accepted destination count and domain-separated destination hashes
  in SQLite. Exact owner identifiers remain in the outbound request and in-memory
  action report, not the database.
- Treat any 2xx response as adapter acceptance. This does not prove that a human read
  or acted on the notification.
- On campaign redelivery, re-verify DataHub first. If routing already completed, do
  not call the webhook again.

## Evidence

The offline suite proves:

- campaign completion and routing-obligation creation roll back together;
- exactly one of two spawned operating-system processes claims a live routing lease;
- expired routing leases recover and increment their attempt count;
- a routing failure leaves DataHub completion sealed, returns routing to `READY`,
  and stores no sensitive exception message;
- recovery performs no additional DataHub mutation and finishes the pending route;
- completed broker redelivery performs no second route;
- the crash window after remote acceptance retries with the identical idempotency
  key, making the at-least-once boundary explicit;
- destination identifiers do not appear in the SQLite file; checksum corruption and
  missing or premature obligations fail integrity verification;
- webhook URL, identity, cardinality, native ownership shape, response status, and
  secret-loading rules fail closed.

The committed Kafka live report additionally proves genuine
GMS-to-Kafka-to-Actions delivery followed by native DataHub ownership resolution and
one accepted loopback webhook. The material redelivery performed zero DataHub writes
and made no second webhook request.

## Alternatives considered

- Route without durable state: rejected because a post-writeback crash can lose the
  obligation.
- Persist raw owner identifiers: rejected because operational recovery requires
  equality evidence and counts, not a second PII directory.
- Claim exactly-once notification: rejected because SQLite and the remote receiver
  do not share a transaction. The receiver must honor the idempotency key.
- Put a webhook URL or token into each receipt: rejected because routing policy and
  credentials belong to governed deployment configuration, not provenance content.
- Treat webhook acceptance as human acknowledgement: rejected because the transport
  cannot prove attention or remediation.

## Consequences and limits

- Operators can distinguish pending DataHub mutation from pending owner routing and
  recover either after a process crash.
- A remote service that ignores `Idempotency-Key` can observe duplicates if the
  process dies after remote acceptance but before local completion.
- The built-in no-delivery router settles the obligation with zero destinations when
  no webhook is configured. Status output makes that count visible; it must not be
  described as an owner notification.
- Owner URNs are transmitted to the configured webhook. TLS protects transport, but
  receiver retention and access control remain deployment responsibilities.
- Destination hashes reduce routine exposure but are pseudonymous integrity material,
  not anonymization; an attacker with a candidate owner directory can test guesses.
- Schema version 1 databases require deliberate replacement or an explicit future
  migration tool. This pre-release implementation does not perform an online
  migration.
- SQLite remains single-host. PostgreSQL is still required for multi-host workers.

## Reversal conditions

Replace the webhook adapter with a queue, Slack, email, or incident-management sink
when that adapter can preserve the campaign idempotency key and return bounded
acceptance evidence. Replace SQLite with the planned PostgreSQL adapter for
multi-host deployment, preserving the same two outbox state machines and atomic
DataHub-completion-to-routing-obligation boundary.
