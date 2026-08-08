# ADR-0002: Use a typed Document compatibility layer for receipt summaries

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

DataHub 1.6.0 documentation describes `aiAgent`, `agentSkill`, API tools, datasets,
ML models, and documents. Local package inspection found that the stable
`acryl-datahub==1.6.0.15` wheel does not contain the documented Agent Registry entity
modules or generated schemas; they first appear in the inspected `1.6.0.16rc3`
wheel. The isolated preview probe then found that Core `v1.6.0` rejects the first
`api` proposal because the entity type is absent from its EntityRegistry. The live
stable and preview probes both proved deterministic write-twice/direct-read behavior
for `DataProcessInstance`, Dataset, MLModel, and Document.

GlassBox requires an OSS-compatible representation now, while leaving room for a
native `agentRun` / `agentDecision` proposal backed by implementation evidence.

## Decision

For compatibility mode:

- use native Agent Registry entities for agents, skills, and tools only when the
  installed server and SDK capability probe proves them;
- on the stable baseline, represent the execution as a standalone
  `DataProcessInstance` and keep absent registry identity explicit;
- project the unavailable agent, skill, and API tool registrations as typed
  Documents with deterministic compatibility URNs, explicit intended native type,
  canonical ID, and the reason native emission is unavailable;
- use datasets, schema fields, ML models, and documents for governed evidence;
- represent each consequential decision receipt summary as an immutable, typed
  DataHub Document;
- relate the Document to supported governed assets and carry the associated run URN
  as a custom property, because Core rejects `dataProcessInstance` in
  `document.relatedAssets`;
- place only digest-safe summary fields in searchable custom properties;
- link the document to relevant governed assets;
- keep the complete canonical DBOM in the artifact store;
- avoid claiming ordinary dataset lineage can encode `OBSERVED` versus `INFERRED`
  runtime influence until a provenance-bearing relationship contract is proven;
- evaluate `DataProcessInstance` experimentally, but do not depend on it in DBOM 0.1.

The capability probe must emit each synthetic entity twice and verify it through a
direct entity read. Search results are not read-after-write evidence.

## Alternatives considered

### Avoid `DataProcessInstance` until a native agent-run entity exists

Rejected for compatibility mode. The live probe proves stable persistence,
deterministic identity, inlet relationships, subtype, and custom properties. The
representation remains explicitly labeled compatibility mode rather than native
Agent Registry semantics.

### Add custom entities before the first vertical slice

Rejected for the compatibility implementation. It would increase deployment and
review burden before evidence shows the native model's exact requirements.

### Encode receipts only as structured properties on `aiAgent`

Rejected because repeated runs require independent, immutable identity and lifecycle
relationships. A mutable bag on an agent cannot preserve append-only history.

## Consequences

- Compatibility-mode receipt UX can be delivered by the GlassBox console even when
  Agent Registry screens are not enabled.
- Compatibility Documents remain visibly distinguishable from native Agent Registry
  entities and can be migrated by canonical ID once the server model is available.
- Agent, skill, and tool projections are published to DataHub's global Context
  surface; receipt summaries stay hidden there by default to avoid catalog noise.
- Documents are searchable, so plaintext prompts, outputs, secrets, and raw tool
  payloads must never be included.
- Typed runtime relationships remain an upstream metadata-model gap.
- Native Agent Registry registration requires both a newer client and matching
  server metadata model; client-side class availability is never treated as proof.
- `document.relatedAssets` cannot provide a typed Document-to-run edge; the custom
  property is a resolvable reference, not native relationship semantics.
- The accepted evidence is recorded in `docs/compatibility/datahub-1.6.0.live.json`,
  `docs/compatibility/datahub-1.6.0-agent-registry-rc.live.json`, and
  `docs/compatibility/datahub-1.6.0-compatibility.live.json`.

## Reversal conditions

Accept a native run/decision model when DataHub exposes an OSS-supported entity or
aspect contract with appropriate cardinality, privacy, lineage semantics, event
delivery, and direct-read behavior. Migration must preserve receipt IDs and digests.
