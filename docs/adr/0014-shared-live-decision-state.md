# ADR-0014: Read Action findings from one shared live decision-state authority

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0013](0013-read-only-forensics-mcp.md)

## Context

ADR-0013 established a read-only, proof-carrying MCP boundary for receipt
verification and deterministic impact analysis. Its initial JSONL profile could
answer questions about registered receipts, but it could not prove that a running
DataHub Action had created, claimed, written back, or completed an invalidation
campaign. Recomputing impact at query time is useful counterfactual analysis; it is
not evidence of what the operational system actually did.

The PostgreSQL invalidation profile already owns verified receipt artifacts,
reverse dependencies, content-addressed campaigns, worker leases, DataHub writeback
evidence, and owner-routing obligations. Duplicating that state into an MCP-specific
database would introduce synchronization races and two competing accounts of the
same incident.

## Decision

- The DataHub invalidation Action and GlassBox forensics MCP may use the same
  PostgreSQL schema as their live decision-state authority.
- Action workers remain the only writers. The MCP process opens the existing schema
  with `initialize_schema=false` and exposes read-only operations only. A
  least-privilege MCP database identity should have `SELECT` access and no DDL or
  table-mutation privileges.
- The existing receipt tools remain available:
  `verify_decision_receipt`, `get_decision_influence`,
  `classify_decision_impact`, and `list_affected_decisions`.
- Add two persisted-finding tools:
  `get_invalidation_campaign`, which reads one actual Action campaign, and
  `list_decision_findings`, which lists actual persisted campaign findings for one
  receipt.
- Keep prospective and historical claims separate. `classify_decision_impact` and
  `list_affected_decisions` calculate policy outcomes from a supplied normalized
  change. The persisted-finding tools report what Action workers actually stored,
  including workflow status, attempt count, and whether DataHub writeback was
  directly verified.
- Every persisted response names its configured scope and completeness. A
  configured PostgreSQL schema is not described as all organizational history
  unless retention and ingestion completeness are proven separately.
- Receipt artifacts are re-verified on read. Database checksums, receipt identity,
  canonical payload integrity, Merkle commitments, and configured signatures remain
  deterministic gates; MCP transport does not replace them.
- No raw prompts, model outputs, query text, tool payloads, or evidence values cross
  the MCP boundary. No quarantine, incident, approval, replay, resolution, or
  supersession mutation is added.
- JSONL remains a local compatibility profile for the four receipt-analysis tools.
  It explicitly reports that persisted Action findings are not configured.
- Replay is not part of this live-state loop. A later recovery workflow may consume
  completed campaigns through a separately authorized contract, but it cannot
  manufacture or rewrite Action findings.

## Evidence

The shared adapter is exercised through a real transactional store lifecycle:
register a signed receipt, stage an invalidation campaign, claim it, seal directly
verified DataHub writeback evidence, and then query that same state through the
protocol-neutral forensics service and the official MCP client. Tests require the
persisted workflow status, finding verdict, writeback state, scope, completeness,
and raw-free response shape.

The PostgreSQL store implementation uses the same protocol and has an independent
PostgreSQL 16 lifecycle/concurrency proof. A deployment must still execute the
PostgreSQL integration test against its own supported database and credentials.

## Alternatives considered

- Recompute impact and label it as Action history: rejected because policy output
  does not prove delivery, claim, writeback, verification, retry, or completion.
- Mirror campaigns into an MCP-only store: rejected because dual writes would create
  lag and conflicting authorities during failures.
- Query DataHub Documents alone: rejected because the governed projection does not
  contain the Action's complete transactional and checksum evidence.
- Give MCP mutation tools: rejected because a forensic query surface must not gain
  ambient authority to change incidents or receipts.
- Make replay the source of findings: rejected because findings originate from live
  metadata changes and verified receipts; replay is a downstream recovery concern.

## Consequences and limits

- Operators can ask an agent what actually happened without relying on the console
  or a synthetic replay.
- One database authority removes synchronization ambiguity, but database
  availability now affects live forensic queries as well as Action workers.
- A read-only MCP role reduces blast radius; it does not replace network isolation,
  tenant authorization, rate limiting, or remote-transport threat modeling.
- `datahub_writeback_verified: true` proves the configured direct readback matched
  sealed evidence. It does not prove that the underlying agent output is factually
  correct or that a human acknowledged an owner notification.
- Historical completeness still depends on receipt registration, event ingestion,
  retention, and the configured schema scope.

## Reversal conditions

Replace this adapter if DataHub adopts a native immutable decision and invalidation
model that exposes equivalent signed-artifact integrity, workflow state, writeback
verification, completeness, and privacy semantics. Add any MCP mutation only
through a new ADR with scoped authorization, idempotency, audit, and authoritative
readback evidence.
