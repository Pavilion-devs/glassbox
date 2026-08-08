# ADR-0001: Separate raw traces from governed DataHub provenance

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

Agent traces contain high-cardinality spans, token measurements, transient errors,
and potentially sensitive tool payloads. DataHub is an organizational metadata
graph designed for durable entities, relationships, governance, incidents, and
discovery. Writing every span into DataHub would create excessive cardinality,
weaken access boundaries, and make ordinary lineage misleading.

GlassBox still needs DataHub to answer durable questions: which governed evidence
influenced a consequential output, whether that evidence remains valid, who owns the
affected assets, and where the complete execution trace can be inspected.

## Decision

GlassBox is a compiler from runtime telemetry to governed metadata.

- An operational trace store owns raw OpenTelemetry spans and optional encrypted or
  redacted payloads.
- A portable artifact store owns canonical DBOM documents, signatures, and replay
  bundles.
- DataHub owns curated entities and relationships: registered agents and skills,
  exact evidence assets, receipt summaries, provenance classifications, incidents,
  quarantine status, approvals, evaluations, supersession, and trace/artifact links.
- Only consequential runs are compiled into durable DataHub receipt summaries.
- Every DataHub influence edge retains whether it is `OBSERVED`, `DECLARED`,
  `INFERRED`, or `UNKNOWN` and how that classification was produced.

## Alternatives considered

### Store every span in DataHub

Rejected because span cardinality and payload sensitivity conflict with DataHub's
governed-graph role. This would also turn incidental tool availability into apparent
business lineage.

### Keep all provenance in a tracing product

Rejected because trace backends do not own DataHub's governance, ownership,
incidents, glossary, schema-field, or impact graph. It would create a disconnected
provenance silo.

### Store only a receipt URL in DataHub

Rejected as insufficient. DataHub needs curated evidence relationships and state to
perform reverse impact analysis without downloading every external artifact.

## Consequences

- GlassBox must define an explicit compiler and retention boundary.
- Raw-trace outages and DataHub outages have different failure behavior.
- Receipt digests allow the portable artifact and DataHub summary to be correlated.
- The DataHub adapter must cap write amplification and never emit raw span payloads.
- Access control for traces can remain stricter than access to receipt summaries.

## Reversal conditions

Revisit only if DataHub introduces a purpose-built, access-controlled,
high-cardinality execution store with documented retention and query guarantees.
Even then, the portable DBOM remains independently verifiable.
