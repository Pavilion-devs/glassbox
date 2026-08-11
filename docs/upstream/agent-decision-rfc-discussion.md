# Agent decision metadata pre-RFC discussion packet

**Target:** DataHub Agent Registry RFC #16012 discussion
**Proposed title:** `Pre-RFC: immutable agent decisions and qualified runtime influence`

This is a focused request for maintainer direction, not a request to accept the full
GlassBox schema. The detailed proposal is in
[`../rfcs/000-agent-decision-receipts-and-runtime-influence.md`](../rfcs/000-agent-decision-receipts-and-runtime-influence.md).

## Ready-to-post discussion body

Agent Registry gives DataHub a governed model for an agent and its declared skills,
tools, models, and dependencies. We have implemented a complementary runtime proof
for one unresolved question raised in RFC #16012: how should DataHub represent the
path from an agent invocation through actual tool/evidence use to a consequential
output without turning the catalog into a trace lake?

The working implementation creates an immutable, content-addressed decision receipt
for consequential outputs only. It records qualified influence with four explicit
evidence states (`OBSERVED`, `DECLARED`, `INFERRED`, `UNKNOWN`), field precision and
derivation when available, completeness separately from influence, action effect and
approval commitments, integrity status, invalidation assessments, and append-only
supersession. Raw spans and prompt/output bodies remain outside DataHub.

Our compatibility implementation on DataHub Core 1.6.0 uses typed Documents and a
`DataProcessInstance` where support is semantically safe. That proved the operational
loop—direct readback, material metadata change, deterministic impact, quarantine,
read-only corrected replay, and immutable supersession—but also exposed why the
compatibility model should not become the long-term contract:

- ordinary lineage cannot carry the evidence state, derivation, completeness, role,
  and representation commitment needed for a runtime claim;
- `DataProcessInstance` describes execution but is not a clean identity for a
  consequential output that survives, is invalidated, and is superseded;
- a mutable aspect on `aiAgent` conflates many independently retained decisions;
- raw OpenTelemetry spans answer observability questions but do not provide a
  curated governed object for incidents, ownership, retention, and history.

The smallest native primitive we propose discussing is:

1. an `agentDecision` identity for a consequential output, scoped by namespace,
   stable decision ID, and environment;
2. immutable decision components and integrity commitments;
3. qualified runtime influence records that preserve state, role, derivation,
   field precision, and completeness without asserting model-internal causality;
4. time-series verification/materiality events plus a mutable latest-status
   projection;
5. successor-owned `SUPERSEDES` links so correction never rewrites the predecessor;
6. native incident targeting for decisions that become stale, at risk, or unknown.

This is deliberately not a proposal to store every agent run, span, token, or tool
call as a DataHub entity. Only outputs designated consequential cross the metadata
boundary; operational telemetry remains in the trace backend.

### Questions for maintainers

1. Should this be a focused extension to RFC #16012 or a separate RFC referenced by
   Agent Registry?
2. Is `agentDecision` the right durable identity, or should DataHub extend an
   existing output/entity abstraction and keep run identity separate?
3. Would maintainers prefer qualified influence as an aspect on the decision, an
   intermediate influence entity, or a time-series event plus a projection?
4. Which completeness semantics can DataHub support without users interpreting an
   absent edge as proof of non-use?
5. Should incident targeting and supersession be part of the first primitive, or
   follow after identity and influence land?
6. What cardinality and retention envelope would be acceptable for OSS Core and
   Cloud before PDL implementation begins?

We can provide the normative DBOM schema, deterministic policy tests, live Core
readback reports, and a minimal PDL spike after the preferred ownership boundary is
clear. We would rather converge on the primitive first than send a large speculative
metadata PR.

## Evidence available for review

- canonical JSON receipts with SHA-256 content addresses, Merkle commitments, and
  optional Ed25519 signatures;
- exact field-level observed influence and explicit incomplete/unknown states;
- idempotent DataHub incident and quarantine writeback;
- transactional SQLite and PostgreSQL reverse indexes and outboxes;
- Kafka retry, acknowledgement, and same-consumer-group restart proof;
- approval-bound, capability-pinned read-only replay that emits a new receipt and
  append-only supersession record;
- a read-only seven-tool MCP surface that separates prospective policy analysis from
  actual persisted Action findings, plus a portable DataHub forensic Skill;
- a live dual-MCP proof that cross-binds official DataHub catalog evidence with
  freshly verified receipt influence and persisted Action state while preserving
  the unavailable exact Incident projection;
- an adversarial natural-language forward test whose closed 18-fact ledger requires
  citations and limitations, rejects claim drift and mutation authority, and keeps
  model-based semantic review separate from deterministic validation;
- sanitized live compatibility reports with direct entity readback.

## Claims deliberately excluded

- A signature does not prove that an output is true.
- Recorded influence does not prove faithful model-internal reasoning.
- A complete configured receipt index is not automatically organization-wide.
- DataHub Core 1.6.0 does not natively support the proposed entity.
- The current official Agent Registry RFC remains open; this packet is an
  implementation-backed request for direction, not a claim of accepted semantics.
- No metadata RFC has been submitted or accepted yet.
