# DataHub Skills pull-request packet

**Target:** `datahub-project/datahub-skills`
**Prepared baseline:** commit `f22f930` on 2026-08-07
**Proposed title:** `feat: add agent decision forensics skill`
**Published draft:** [`datahub-project/datahub-skills#120`](https://github.com/datahub-project/datahub-skills/pull/120)
**Published commit:** `fc14058eebafaf50d445a38642059929f218c03c`

This packet was adapted into the published draft after the exact contribution scope,
baseline, fork branch, and local validation were reverified.

## Summary

Add `datahub-agent-forensics`, a read-only investigation Skill for consequential
AI-agent decisions represented in DataHub. It helps an agent keep five different
claims separate: discovery, receipt integrity, run-specific influence, impact of a
later metadata change, and current authorization to replay or mutate.

The Skill answers questions such as:

- Which signed agent decisions actually used this schema field?
- Why did a recommendation become stale after an incident or schema change?
- Does an approval bind the exact recorded action?
- Can a replay be planned without silently reusing authority or overwriting history?

## Why this belongs in DataHub Skills

DataHub already owns catalog discovery, exact entity reads, schema, lineage, quality,
incidents, ownership, and agent registration. Those capabilities are necessary but
do not by themselves prove that one particular agent run used every available or
lineage-adjacent asset.

This Skill provides the missing investigation workflow without inventing new
catalog APIs. It composes with the existing Search, Lineage, Quality, Enrich, and
Setup Skills and routes ordinary metadata questions back to them.

## Safety and evidence boundary

- Search identifies candidates; direct entity/aspect retrieval establishes catalog
  evidence.
- Generic lineage is never promoted to run-specific influence.
- A DataHub Document projection is labeled `PROJECTION_ONLY`; copied digest or
  signature fields are not described as freshly verified.
- `UNAFFECTED` requires positive exclusion evidence. Missing, partial, truncated, or
  wildcard field evidence yields uncertainty instead.
- Integrity, materiality, approval validity, and replay eligibility are
  deterministic gates, not LLM judgments.
- `IRREVERSIBLE` and `UNKNOWN_EFFECT` actions are never automatically replayed.
- Reports use identifiers, states, reason codes, counts, and digests; they exclude
  raw prompts, rows, model outputs, tool payloads, and credentials.

## Optional decision-evidence tools

The Skill works without a GlassBox installation when DataHub contains a governed
receipt projection. Optional helpers provide stronger evidence when available:

- local scripts inspect signed DBOM artifacts and run a versioned impact policy;
- a read-only decision-forensics MCP server may expose receipt verification,
  recorded influence, deterministic impact, and bounded reverse-impact scanning.

These helpers complement DataHub MCP. They do not duplicate catalog search, generic
lineage, schema, or ownership tools, and the Skill exposes no quarantine, approval,
replay-execution, resolution, or supersession tool.

## Repository changes

- add `skills/datahub-agent-forensics/` with progressive references, deterministic
  helper scripts, report template, README, and adversarial evaluations;
- add `/catalog-agent-forensics` for Claude/plugin users;
- route agent-decision questions from `using-datahub`;
- add Skill discovery text to the root README and plugin descriptions;
- include helper-script checks in the target lint workflow;
- add a focused standard-library unit test for raw-free, fail-closed helper output.

## Evaluation cases

The committed evaluations require the agent to:

1. explain an exact used-field stale decision;
2. refuse a false `UNAFFECTED` conclusion when field evidence is incomplete;
3. block automatic replay of an `UNKNOWN_EFFECT` action and reject approval reuse;
4. prefer read-only forensic MCP evidence while preserving scope, proof state,
   completeness, policy version, and reason codes;
5. preserve an unavailable exact Incident projection, configuration-dependent
   organizational scope, and `NONE` mutation authority even when the user explicitly
   pressures the agent to claim otherwise.

## Validation

Run from the target repository:

```bash
prettier --check \
  README.md commands/catalog-agent-forensics.md \
  skills/using-datahub/SKILL.md skills/datahub-agent-forensics
markdownlint-cli2 \
  README.md commands/catalog-agent-forensics.md \
  skills/using-datahub/SKILL.md 'skills/datahub-agent-forensics/**/*.md'
ruff format --check \
  skills/datahub-agent-forensics/scripts tests/test_agent_forensics_scripts.py
ruff check \
  skills/datahub-agent-forensics/scripts tests/test_agent_forensics_scripts.py
python -m unittest tests/test_agent_forensics_scripts.py
git diff --check
```

All component checks pass in the prepared worktree with the repository-pinned
Prettier `4.0.0-alpha.8` and markdownlint-cli2 `0.21.0`. The generated patch also
applies cleanly to a separate clone at exact baseline `f22f930`; the same checks pass
after application there. The packet manifest hashes all 23 changed files and binds
the published draft only when its canonical target-repository PR URL passes strict
validation.

GlassBox also carries a guarded live interoperability proof outside the proposed
Skill-only patch. It runs the official DataHub MCP server `0.6.0` and the optional
GlassBox decision-evidence MCP concurrently against DataHub Core `v1.6.0`, a real
DataHub Action envelope, and PostgreSQL 16 state. The sanitized
[`datahub-1.6.0-dual-mcp-forensics.live.json`](../compatibility/datahub-1.6.0-dual-mcp-forensics.live.json)
report cross-binds the catalog dataset, exact field/type, incident health, receipt,
run-specific influence, persisted `STALE` finding, completed campaign, quarantine,
and verified DataHub writeback. It also records that this official MCP/Core pairing
did not project the exact Incident entity body; the proposed Skill preserves that
state as unavailable instead of filling it with inference.

The companion
[`datahub-1.6.0-dual-mcp-agent-narration.eval.json`](../compatibility/datahub-1.6.0-dual-mcp-agent-narration.eval.json)
report forward-tests the Skill in independent contexts. Both the ordinary forensic
request and a pressure-to-hallucinate request passed the deterministic 18-fact
ledger validator. A separate semantic reviewer found no contradiction, but its
result remains labeled model-based and does not replace the deterministic checks.

## Overlap and non-goals

- This does not replace `datahub-lineage`; it starts where a question names a
  particular agent decision, receipt, approval, or runtime influence claim.
- This does not replace `datahub-quality`; incidents are investigation inputs, and
  the Skill performs no incident mutation.
- This does not add a proprietary trace backend or store raw prompts in DataHub.
- This does not ask DataHub Skills to adopt GlassBox runtime code. Optional helpers
  fail closed when their packages are unavailable.
- A search of the target repository and current DataHub work surfaced the active
  Agent Registry proposal as the material overlap; the PR should link RFC #16012 and
  invite maintainers to refine terminology before merge.

## Reviewer path

1. Read the routing table and five-claim boundary in `SKILL.md`.
2. Inspect the projection allowlist and integrity states in `references/`.
3. Run the one focused helper test.
4. Review the five evaluation fixtures, especially false-unaffected, unsafe replay,
   and the pressure-to-invent evidence-boundary case.
5. Confirm that no new mutation permission or general catalog tool is introduced.
