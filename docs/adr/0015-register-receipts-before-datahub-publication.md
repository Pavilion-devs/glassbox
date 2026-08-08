# ADR-0015: Register compiled receipts before governed DataHub publication

- **Status:** Superseded in part by
  [ADR-0016](0016-durable-receipt-publication-and-otlp-acknowledgement.md)
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0005](0005-compiler-and-receipt-publication.md) and
  [ADR-0014](0014-shared-live-decision-state.md)

## Context

The compiler produced signed receipts, the DataHub adapter published their governed
Document projections, and the invalidation state could index the same artifacts.
Those capabilities were previously composed by examples and operator commands. A
receipt could therefore appear in DataHub without being registered for
invalidation, or be registered later with an unjustified field-completeness claim.
That manual gap prevented the runtime-to-Action path from being a reliable ecosystem
integration.

PostgreSQL and DataHub do not share a transaction. The publication boundary must
choose an ordering, expose incomplete stages, and make retry safe without pretending
to provide exactly-once cross-system effects.

## Decision

- Keep `compile_events` and `compile_otlp_json` deterministic and side-effect free.
  Add `LiveReceiptPipeline` as the explicit composition boundary for compilation,
  shared state, and DataHub publication.
- Provide both normalized-event and strict OTLP entry points. A successful call
  performs this closed sequence:
  1. compile and seal one DBOM;
  2. verify and transactionally register the full signed receipt plus dependency
     index in the configured shared state;
  3. directly reread the stored artifact and require canonical equality;
  4. publish the governed DataHub Document twice with its deterministic identity;
  5. directly read DataHub aspects and return a raw-free completion report.
- Register shared state before DataHub. A registration conflict or integrity failure
  produces zero DataHub writes. A DataHub failure leaves the receipt durably
  registered, and retrying the same compiled receipt reuses that exact record before
  idempotent publication.
- Treat a pipeline exception as a failed delivery. An OTLP receiver or caller must
  not acknowledge the run as publication-complete until the returned report is
  valid. An identical input retry repairs a crash or transport failure after state
  registration.
- Load PostgreSQL DSNs only through a named environment variable. Open only an
  existing initialized Action schema with `initialize_schema=false`; compiler
  workers never issue DDL.
- Default field-lineage coverage to `NONE`. `COMPLETE` is accepted only when the
  caller supplies a non-empty deterministic rule identifier and explicit wildcard
  state. The compiler does not infer completeness from the presence of a field URN.
- Expose only bounded failure stage and exception type. Database DSNs, server text,
  receipt bodies, and raw telemetry are not copied into publication reports.
- Keep replay outside this path. A newly compiled original receipt is registered and
  published; no recovery action is inferred or executed.

## Evidence

Unit tests execute real runtime events and strict OTLP protobuf-JSON through the
pipeline into SQLite transactional state and the verified DataHub emitter boundary.
They prove signed insertion, canonical state readback, conservative lineage,
double-write/direct-readback publication, idempotent retry after a failed DataHub
read, unsigned refusal, conflicting-lineage refusal, and bounded secret-free errors.

The PostgreSQL integration suite opens an already initialized randomized schema
through `PostgresReceiptStateConfig`, publishes the same receipt twice, and requires
`INSERTED` followed by `REUSED`, verified state readback, exact lineage recovery, and
four deterministic DataHub upserts. The real Kafka proof now uses
`LiveReceiptPipeline` instead of a separate manual `store.register` call.

## Alternatives considered

- Put registration inside `compile_events`: rejected because deterministic
  compilation must remain independently testable and free of transport effects.
- Publish DataHub before state registration: rejected because a governed receipt
  could become visible while being absent from the invalidation index.
- Treat state registration as complete publication: rejected because it says
  nothing about the DataHub projection or its direct readback.
- Use an in-memory retry queue: rejected because a process crash would lose the only
  repair obligation.
- Add a database publication outbox immediately: deferred. It can remove reliance on
  upstream redelivery, but requires a schema migration, worker leases, and a separate
  DataHub projection evidence contract. The synchronous fail-closed path already
  makes retry identity and acknowledgement semantics explicit.
- Infer complete field lineage from observed evidence: rejected because observing
  one field does not prove that all relevant fields were captured.

## Consequences and limits

- Operators no longer need to export and re-import every compiler receipt before the
  Action or MCP can see it.
- The returned report distinguishes `INSERTED` from `REUSED`, state readback from
  DataHub readback, and configured lineage proof from recorded dependencies.
- A crash after state registration but before DataHub completion leaves a repairable
  partial state. Correct deployments must redeliver the same normalized run or OTLP
  envelope until the pipeline succeeds. A future durable publication outbox can
  provide independent recovery when upstream redelivery is unavailable.
- A metadata event arriving before receipt registration cannot invalidate that
  receipt retroactively under the current streaming Action. Consequential output
  release must therefore be gated on successful pipeline completion; historical
  backfill requires a separate bounded workflow.
- Direct readback proves persistence and identity, not factual correctness of the
  agent output.

## Reversal conditions

Supersede this ordering if DataHub adopts a native receipt mutation that can share a
transaction or durable ingestion acknowledgement with the decision-state authority.
Add a publication outbox through a new schema-versioned ADR when deployments require
repair independent of upstream OTLP redelivery.
