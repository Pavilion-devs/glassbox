# ADR-0005: Compile strict provenance receipts before DataHub publication

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

Runtime telemetry is untrusted, incomplete by nature, and too high-cardinality for
DataHub. GlassBox needs a deterministic boundary that converts a single completed
agent run into portable evidence without upgrading claims, hiding uncertain tool
outcomes, or making DataHub the raw trace store.

The pinned DataHub server also constrains how receipts can appear in the graph.
Agent Registry types are unavailable in stable Core 1.6.0, and live emission proved
that `document.relatedAssets` rejects a compatibility Document URN.

## Decision

- Accept normalized `RuntimeEvent` records, completed exporter-neutral OpenTelemetry
  spans, or strict OTLP/HTTP protobuf-JSON trace envelopes.
- Pin the supported GenAI semantic schema URL. Reject dropped attributes, dropped
  events, duplicate span identities, ambiguous agent-span selection, complex OTLP
  values in the closed GlassBox profile, and malformed correlation IDs.
- Compile exactly one run lifecycle. Preserve observed, declared, inferred, and
  unknown evidence states without promotion.
- Require a committed consequential output digest. Missing output evidence is a
  compilation error; no placeholder digest is manufactured.
- Preserve an attempted action without a terminal observation as `ATTEMPTED` and
  classify the run as unreplayable because the external outcome is uncertain.
- Resolve exact DataHub URN candidates in a fixed hierarchy. A URN enters the DBOM
  graph identity only after direct non-empty entity readback. Unverified claims are
  retained as evidence with a null URN and an explicit resolution diagnostic.
- Produce deterministic evidence/action IDs, canonicalize with RFC 8785, compute a
  SHA-256 payload address and Merkle root, and optionally sign with Ed25519.
- Verify the sealed receipt before any DataHub mutation. Production-oriented
  publication requires at least one valid signature by default.
- Publish a digest-only receipt summary as a deterministic hidden DataHub Document,
  emit it twice, and verify it through direct entity readback rather than search.
- Use native dataset URNs in `relatedAssets`. Preserve compatibility agent and model
  references in explicit custom properties because they are not valid destinations
  for that field on Core 1.6.0.
- Keep operational runtime records outside DataHub. The development profile uses a
  permission-restricted append-only JSONL log with per-record checksums, visible
  truncation/tamper failures, and optional `fsync`.

## Alternatives considered

- Store complete traces in DataHub: rejected because of graph cardinality, privacy,
  retention, and search-noise costs.
- Fill missing output/action metadata with deterministic placeholders: rejected
  because cryptographic integrity would then authenticate invented evidence.
- Trust syntactically valid DataHub URNs: rejected because a plausible URN does not
  prove that an entity exists.
- Put compatibility Documents in `relatedAssets`: rejected by the live Core contract
  with HTTP 422.
- Treat a successful first write as idempotency proof: rejected; the emitter performs
  a second deterministic write and a direct read.

## Consequences

- A failed or incomplete run may remain in operational persistence without producing
  a DBOM until it has the minimum evidence required by the schema.
- OTLP input containing dropped provenance fails closed. Deployments must size their
  collectors and exporters accordingly.
- The development event log is a single-process durability profile, not a replacement
  for a production collector, object store, or database-backed outbox.
- Receipt signatures prove integrity and signer possession; direct DataHub reads prove
  persistence and entity existence. Neither proves that a model conclusion is true.
- Stable Core receives a useful governed receipt today without pretending that
  compatibility Documents are native Agent Registry entities.

## Reversal conditions

This decision may be superseded when stable DataHub Core provides native agent-run,
decision-receipt, and typed evidence relationships with verified mutation semantics.
The canonical DBOM and evidence-honesty requirements remain portable.
