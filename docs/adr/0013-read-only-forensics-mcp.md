# ADR-0013: Expose decision evidence through a read-only, proof-carrying MCP server

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

The `datahub-agent-forensics` Skill can orchestrate investigation, but a portable
Skill must not contain the integrity and materiality rules it narrates. DataHub's
official MCP server already owns general catalog discovery, entity retrieval, schema,
and lineage. Reimplementing those tools would create an ambiguous second catalog
plane and make the integration harder to maintain.

GlassBox has a separate decision-evidence plane: signed DBOM artifacts, verified
dependency profiles, exact materiality policy, replay plans, approvals, and
supersession records. Agent clients need a stable way to query that plane. MCP is a
useful transport, but exposing action or replay mutation through the same natural-
language surface would broaden authority and weaken the deterministic gates.

## Decision

- Build a protocol-neutral `ForensicsService`; MCP remains a thin adapter that owns
  no verification, lineage, materiality, approval, or replay policy.
- Expose only four read-only tools in version 1:
  `verify_decision_receipt`, `get_decision_influence`,
  `classify_decision_impact`, and `list_affected_decisions`.
- Compose with the official DataHub MCP server. DataHub MCP resolves catalog entities
  and generic lineage; GlassBox MCP answers run-specific decision evidence and
  deterministic impact questions.
- Accept content-addressed receipt IDs and normalized change fields. Do not accept
  arbitrary filesystem paths, raw receipt bodies, prompts, outputs, or executable
  callbacks through tool inputs.
- Return bounded, raw-free projections. Verification failures use closed reason
  codes; they do not echo schema instances, receipt bodies, exception messages, or
  sensitive extension values.
- Mark every response with the contract version, configured index scope, raw-content
  status, and relevant completeness or proof state. A stored profile without an
  artifact reader is `VERIFIED_AT_INGESTION`, never `VERIFIED_NOW`.
- Use the canonical `glassbox.materiality.v1` policy for impact. The MCP transport and
  the calling model may explain its result but cannot change it.
- Scan the complete configured receipt index before truncating returned detail. A
  bounded result therefore reports both `scan_complete` and `truncated` separately.
- Keep quarantine, incident mutation, approval, replay execution, resolution, and
  supersession out of this server. Those remain explicit application workflows with
  their existing verification and authorization boundaries.
- Run locally over stdio first. Remote transport, tenancy, authentication, and
  authorization require a separate decision and threat model.

## Evidence

The service tests cover fresh signed receipt verification, safe influence projection,
defensive artifact copies, tampered artifact failure codes, exact stale classification,
complete-but-bounded reverse scans, missing receipt behavior, path-like identifier
rejection, and invalid result bounds. The same materiality functions used by the
DataHub invalidation Action produce the MCP verdicts.

## Alternatives considered

- Add forensic tools to DataHub's official MCP server immediately: deferred. The
  receipt schema and native metadata RFC need maintainer agreement first; an
  independent server proves the reusable contract without claiming an upstream API.
- Duplicate search and lineage tools: rejected because DataHub already owns that
  catalog surface and its permission model.
- Put all logic in the Skill: rejected because prompt instructions are not a
  deterministic trust boundary and cannot safely establish integrity or materiality.
- Expose `execute_replay` or `quarantine_decision`: rejected because MCP clients and
  models must not gain ambient mutation authority from a forensic query surface.
- Return full DBOM JSON: rejected because DBOM extensions and future fields can hold
  sensitive or high-cardinality material. The server uses an explicit safe projection.

## Consequences and limits

- Operators run two complementary MCP servers when they want both catalog discovery
  and decision forensics. The Skill documents the routing so this is intentional,
  not accidental duplication.
- The current default server reads the append-only JSONL compatibility store. Its
  scope is registered receipts in that file, not every decision in DataHub or an
  organization. SQLite and PostgreSQL adapters can implement the same profile/artifact
  protocols in a later change.
- A valid signature proves artifact integrity and authorship under its key; it does
  not prove that the decision is factually correct.
- `scan_complete` means the configured local index was fully scanned. It does not
  claim organizational or DataHub-global completeness.
- Stdio is suitable for local agent runtimes. A remotely reachable deployment must
  add authenticated principals, tenant isolation, rate limits, audit, and transport
  security before it can be described as production-safe.

## Reversal conditions

Replace the standalone adapter if DataHub adopts native immutable decision-receipt
metadata and official MCP tools with equivalent integrity, completeness, privacy,
and deterministic-policy semantics. Add mutation tools only through a new ADR that
proves scoped authorization, exact approvals, idempotency, audit, and authoritative
readback for every operation.
