# ADR-0006: Separate deterministic materiality from DataHub invalidation writeback

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers

## Context

An upstream metadata change must identify outputs that actually depended on the
changed evidence without creating alert storms or laundering missing provenance into
an `UNAFFECTED` verdict. DataHub Core 1.6.0 supplies MetadataChangeLog events,
incidents, incident summaries, and Documents, but its stable Python SDK does not
provide a high-level incident client. A live capability spike also found that an
incident can target datasets and schema fields, but not the compatibility Document
used for a GlassBox receipt. Direct incident aspect writes do not synthesize the
target asset's inverse `incidentsSummary` aspect.

## Decision

- Normalize supported `MetadataChangeLogEvent_v1` payloads into a closed change
  model before policy evaluation. Unsupported aspects are acknowledged as no-ops;
  malformed supported events raise so the Actions framework can retry them.
- Keep materiality pure, deterministic, and versioned as
  `glassbox.materiality.v1`. DataHub transport cannot select or alter a verdict.
- Return `UNAFFECTED` only from positive evidence: complete non-wildcard field
  lineage proves a changed field was unused, or every dependency is resolved and
  the changed asset is absent from the influence set.
- Classify an exact observed material dependency as `STALE`, an exact declared or
  inferred dependency as `AT_RISK`, and unresolved provenance as `UNKNOWN`.
  `STALE`, `AT_RISK`, and `UNKNOWN` require quarantine. `AT_RISK` and `UNKNOWN`
  are never auto-cleared.
- Build campaign and incident IDs from canonical event material. Redelivery produces
  the same campaign, incident, classification, and receipt properties.
- Store signed DBOMs in a checksummed append-only dependency store outside DataHub.
  Re-verify signatures when the index is loaded. Traverse actual receipt evidence,
  never generic agent availability or unrelated graph lineage.
- Implement the consumer as a real DataHub Actions entry-point plugin named
  `glassbox_invalidation`, pinned to `acryl-datahub-actions==1.6.0.15`.
- Write the incident's key and info aspects directly. Fetch, merge, and upsert the
  target asset's `incidentsSummary`, preserving all unrelated active and resolved
  incidents. Refuse to reactivate a resolved incident.
- Quarantine affected receipt Documents through SDK fetch-modify-update, preserving
  their existing contents and properties. Receipt republication likewise preserves
  quarantine and third-party custom properties.
- Perform every campaign write twice, then verify incident identity, inverse summary,
  and all receipt quarantine properties through authoritative reads before the
  Actions event is acknowledged or owner routing begins.
- Ignore GlassBox's own `GLASSBOX_INVALIDATION` incident writes and quarantine-only
  Document changes so the action cannot create a feedback loop.

## Alternatives considered

- Treat every dataset schema change as material: rejected because it creates alert
  storms and fails the unrelated-field exit criterion.
- Treat a missing field match as unaffected: rejected because incomplete lineage and
  wildcard queries do not prove non-use.
- Put the incident on the receipt Document: rejected because the pinned incident
  relationship contract excludes Documents.
- Use the GraphQL `raiseIncident` mutation: rejected for the core idempotent path
  because it generates an incident identity instead of accepting the campaign's
  deterministic URN.
- Assume DataHub creates `incidentsSummary`: rejected by live direct readback.
- Store full traces in DataHub to power traversal: rejected by ADR-0001 and the
  graph-cardinality/privacy boundary.

## Consequences

- Stable Core receives native incident UX on the changed governed asset while the
  exact receipt quarantine remains visible on the receipt Document.
- The legacy append-only JSONL receipt store is a single-process compatibility
  profile. [ADR-0008](0008-transactional-invalidation-state.md) adds the proven
  single-host, multi-process SQLite receipt index and campaign outbox. Multi-host
  deployment still needs a server database with equivalent verification,
  uniqueness, leasing, and audit guarantees.
- Field renames appear as remove-plus-add unless a trusted producer supplies a rename
  identity. The policy never invents one from similar names.
- Incident resolution and replay are intentionally outside Gate 5. Resolving source
  quality makes an output eligible for review or replay; it does not prove the old
  output correct.
- Plugin discovery, in-process `EventEnvelope` handling, and the Kafka
  delivery/retry/commit/restart path are proven. See ADR-0007. Broker-side commit
  failure and PGQueue behavior remain unverified.

## Reversal conditions

This compatibility writeback may be replaced when stable DataHub offers native
decision-receipt entities, typed influence relationships, deterministic incident
creation, and atomic inverse-summary maintenance. The evidence-honesty and pure
policy boundaries remain mandatory.
