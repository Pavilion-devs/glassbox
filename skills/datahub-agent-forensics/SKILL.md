---
name: datahub-agent-forensics
description: Investigate AI-agent decisions, outputs, provenance, DBOM receipts, DataHub incidents, stale-impact campaigns, approvals, and replay safety. Use for questions such as which agent outputs used a changed dataset or column, why a recommendation is stale, what evidence or actions produced a decision, whether approval was valid, which runs an incident affected, how agent versions differ, or whether a read-only replay can be planned safely.
---

# DataHub Agent Forensics

Investigate through direct evidence and deterministic policy. Keep discovery,
integrity, truth, impact, and authorization as separate claims.

## DataHub tool selection

1. Prefer available DataHub MCP tools for structured search, entity retrieval,
   lineage, incidents, and assertions. Inspect their current schemas before calling
   them because server prefixes and argument names can differ.
2. Prefer the read-only GlassBox MCP tools `verify_decision_receipt`,
   `get_decision_influence`, `classify_decision_impact`, and
   `list_affected_decisions` for receipt evidence and prospective impact. When the
   question asks what the running Action actually processed, prefer
   `get_invalidation_campaign` and `list_decision_findings`. Require every tool's
   proof, scope, completeness, workflow, writeback, and `raw_content_returned`
   fields where present. They complement DataHub MCP; they do not replace catalog
   discovery or generic lineage.
3. Otherwise use the DataHub CLI. Check `datahub version` once, use
   `datahub search ... --format json` for discovery, and use
   `datahub get --urn "<validated-URN>"` for the authoritative entity read.
4. If neither DataHub path exists, route connection setup to `datahub-setup`. Do not install,
   authenticate, or invent catalog results inside an investigation.
5. Reject shell metacharacters in names and URNs before using a shell-backed CLI.
   Quote every URN because dataset and schema-field URNs contain punctuation.

## Core workflow

1. Resolve the target to exact identifiers: DataHub URN, receipt ID/Document URN,
   run ID, incident URN, campaign ID, or replay artifact ID.
2. Use search only to discover candidates. Fetch each selected DataHub entity and
   aspect directly before treating it as evidence. Persist only a temporary JSON
   export when a helper script needs a file; remove it after the report unless the
   user requested an artifact.
3. Obtain the signed DBOM when available. Prefer `verify_decision_receipt` when the
   GlassBox MCP server is connected; only `VERIFIED_NOW` establishes a fresh MCP
   integrity claim. Otherwise run:

   ```bash
   python scripts/inspect_receipt.py receipt.json \
     --signer-trust-policy trusted-signers.json \
     --pretty
   ```

   If only a DataHub Document export is available, run the same command on it. Treat
   `PROJECTION_ONLY` as useful metadata, never as cryptographic verification.
   Raw files default to current-time `ADMISSION`. Use `--trust-mode HISTORICAL` only
   when the receipt came from trusted GlassBox state and its checksummed admission
   evidence was verified; a signed timestamp alone does not prove prior admission.
4. Separate dependencies by `OBSERVED`, `DECLARED`, `INFERRED`, and `UNKNOWN`.
   Never promote a weaker state. Read [references/evidence-and-impact.md](references/evidence-and-impact.md)
   when explaining impact or completeness.
5. For one receipt, prefer `get_decision_influence`. For reverse lookup, prefer
   `list_affected_decisions` and preserve `scope`, `scan_complete`, and `truncated`
   exactly. For a normalized metadata change, prefer `classify_decision_impact` or
   use the canonical engine instead of reasoning from prose:

   ```bash
   python scripts/classify_impact.py receipt.json change.json \
     --signer-trust-policy trusted-signers.json \
     --field-coverage COMPLETE \
     --field-rule glassbox.sql-column-lineage.v1 \
     --wildcard-query false \
     --pretty
   ```

   If the engine is unavailable, stop at evidence collection and label impact
   `NOT_CLASSIFIED`; do not guess `UNAFFECTED`.
   If the user asks what happened operationally, query
   `get_invalidation_campaign` or `list_decision_findings` instead. A prospective
   classification is not evidence that the Action received an event, persisted a
   campaign, completed writeback, or verified DataHub state.
6. Explain the causal path in one sentence, then list exact evidence, actions,
   policy reason codes, integrity status, and limitations. Copy
   [assets/forensic-report.md](assets/forensic-report.md) for a full report.
   When an audit or evaluation requests machine-auditable narration over a
   `glassbox.dual-mcp-forensics.v1` report, read
   [references/narration-contract.md](references/narration-contract.md). Preserve
   its closed fact values, cite the required fact IDs in the finding, and return the
   `glassbox.agent-narration.v1` sidecar. Never describe the exact Incident body as
   available or the scan as organization-complete unless those exact facts are
   proven in the brief.
7. Keep the investigation read-only by default. Planning a replay is allowed only
   from a verified receipt and exact inventory. Do not quarantine, approve, execute,
   resolve an incident, or publish supersession unless the user explicitly requests
   that mutation and the applicable policy permits it.
8. Directly read back every requested write. Report transport acceptance separately
   from human acknowledgement and factual correctness.

## Investigation routes

| User intent | Required evidence | Result |
|---|---|---|
| “Why did this output happen?” | Signed DBOM, evidence and action order | Causal report |
| “What used this column?” | Exact field URN plus verified receipt index/influence edges | Receipt set with completeness limits |
| “What became stale?” | Normalized change, signed receipts, field-lineage proof | Deterministic impact assessments |
| “What did the Action actually do?” | Persisted campaign/finding, processing state, sealed DataHub readback | Historical operational report |
| “Was approval valid?” | Action digest, approval artifact, policy/environment/time/trusted signer | Binding report; never infer trust from key possession |
| “Can we replay it?” | Signed receipt/bundle, exact resource inventory, context/input/model pins | Plan or dry-run only |
| “Compare agent versions” | Two verified receipt sets and version pins | Evidence/action/output-digest comparison |

## Non-negotiable boundaries

- A valid signature proves integrity and key possession, not operator authority or
  truth. Require a fingerprint-bound signer policy; never treat the embedded public
  key as its own trust anchor.
- DataHub search results are discovery hints; direct entity/aspect reads are evidence.
- Generic lineage is not recorded agent influence unless the receipt says the agent
  used that entity or field.
- An unavailable or incomplete dependency cannot support `UNAFFECTED`.
- `scan_complete` applies to its stated configured index. It is not organization-wide
  completeness, and an unavailable exact Incident projection cannot support invented
  root-cause or Incident-body details.
- An incident resolution means the upstream signal changed; it does not prove an old
  output is now correct.
- Unknown-effect and irreversible actions are never auto-replayed.
- Approval for one action-set digest never authorizes a changed action or resource.
- Raw prompts, rows, credentials, tool payloads, and model outputs do not belong in
  the report. Use IDs, URNs, states, counts, reason codes, and digests.
- Do not use an LLM judgment inside integrity, materiality, approval, or replay gates.
- MCP is read-only here: never call or invent quarantine, approval, execution,
  resolution, or supersession tools as part of investigation.

## Routing against adjacent skills

- Use `datahub-search` for candidate discovery, then return here for forensic proof.
- Use `datahub-lineage` for upstream/downstream context, but keep generic lineage
  visibly separate from DBOM influence evidence.
- Use `datahub-quality` to obtain the triggering assertion or incident, then let
  deterministic materiality classify receipt impact.
- Use `datahub-enrich` only to add requested metadata after investigation; enrichment
  cannot repair missing historical evidence.
- Use `datahub-setup` when no authenticated MCP or CLI path is available.
- Use memory only for navigation preferences. Never substitute memory for a receipt,
  direct read, approval, or incident record.

## Reference routing

- Read [references/dbom.md](references/dbom.md) for receipt integrity, fields, and
  tamper semantics.
- Read [references/evidence-and-impact.md](references/evidence-and-impact.md) for
  epistemic states, completeness, and impact reason codes.
- Read [references/replay-safety.md](references/replay-safety.md) for replay modes,
  approvals, execution, diff, and supersession.
- Read [references/datahub-core.md](references/datahub-core.md) for the stable-Core
  Document projection and direct-read rules.
- Read [references/evaluation-cases.md](references/evaluation-cases.md) when testing or
  reviewing this skill.
- Read [references/narration-contract.md](references/narration-contract.md) when an
  audit, CI check, or forward test requires a machine-auditable natural-language
  response over dual-MCP evidence.
