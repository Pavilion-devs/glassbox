# DataHub Agent Forensics Skill

`datahub-agent-forensics` turns a natural-language investigation into an
evidence-backed report about an AI-agent decision. It is a portable Agent Skill and
an upstream contribution candidate for
[`datahub-project/datahub-skills`](https://github.com/datahub-project/datahub-skills).

The skill does not ask an LLM to decide whether a receipt is valid or an output is
stale. It uses DataHub for governed discovery and direct reads, a signed Decision
Bill of Materials (DBOM) for run-specific evidence, and the versioned GlassBox policy
engine for impact classification.

## Ecosystem fit

The official DataHub skills currently separate catalog Search, Enrich, Lineage,
Quality, and Setup. Agent forensics composes with those responsibilities:

| Existing skill | What it contributes | Forensic boundary |
| --- | --- | --- |
| `datahub-search` | Candidate entities and receipt Documents | Search is discovery, not proof |
| `datahub-lineage` | General upstream/downstream data flow | Generic lineage is not run-specific influence |
| `datahub-quality` | Assertions, incidents, and health signals | A signal triggers classification; it does not select the verdict |
| `datahub-enrich` | Approved metadata changes | Enrichment cannot repair missing historical evidence |
| `datahub-setup` | Authenticated MCP or CLI connection | Setup does not participate in an integrity decision |

The new skill owns the missing questions: what this particular run used, whether the
record was altered, why a prior output is stale or at risk, whether an approval binds
the exact action, and whether replay can be planned safely.

## Runtime tiers

The same skill remains honest at four capability levels:

1. **DataHub projection only.** Inspect known safe `glassbox.*` Document properties,
   label integrity `PROJECTION_ONLY`, and require the signed artifact before any
   deterministic decision.
2. **Signed DBOM available.** Verify the payload digest, receipt ID, Merkle root, and
   signatures; project evidence/actions without raw prompts, rows, or outputs.
3. **DBOM plus GlassBox policy.** Classify normalized metadata changes with
   `glassbox.materiality.v1` and report the exact state and reason code.
4. **Read-only GlassBox MCP.** Query fresh receipt verification, safe influence
   projections, one-receipt impact, and complete local reverse scans through the
   protocol-neutral service. DataHub MCP still owns catalog discovery and lineage.

An absent verifier is `NOT_VERIFIED`. An absent policy engine is `NOT_CLASSIFIED`.
Neither condition is converted to safe, unaffected, or replayable.

The MCP integration is documented in [forensics-mcp.md](forensics-mcp.md). It exposes
no quarantine, approval, replay execution, incident resolution, or supersession
tools.

## Package layout

```text
skills/datahub-agent-forensics/
├── SKILL.md
├── agents/openai.yaml
├── assets/forensic-report.md
├── references/
│   ├── datahub-core.md
│   ├── dbom.md
│   ├── evidence-and-impact.md
│   ├── evaluation-cases.md
│   └── replay-safety.md
└── scripts/
    ├── classify_impact.py
    └── inspect_receipt.py
```

`SKILL.md` is intentionally concise. Detailed contracts are loaded only for the
route being investigated, while deterministic operations stay in executable helper
scripts.

## Install and invoke

For an Agent Skills-compatible project:

```bash
mkdir -p .agents/skills
cp -R skills/datahub-agent-forensics .agents/skills/
```

Example requests:

- `Use $datahub-agent-forensics to explain why this recommendation is stale.`
- `Which signed agent receipts observed this schema field?`
- `Was the approval on this external action valid for the exact action set?`
- `Can this receipt be replayed read-only without rewriting history?`

Inspect a local DBOM or exported DataHub Document:

```bash
uv run python skills/datahub-agent-forensics/scripts/inspect_receipt.py \
  receipt-or-document.json \
  --signer-trust-policy trusted-signers.json \
  --pretty
```

Classify a verified receipt against a normalized change:

```bash
uv run python skills/datahub-agent-forensics/scripts/classify_impact.py \
  receipt.json change.json \
  --signer-trust-policy trusted-signers.json \
  --field-coverage COMPLETE \
  --field-rule glassbox.sql-column-lineage.v1 \
  --wildcard-query false \
  --pretty
```

Both raw-file helpers default to current-time signer `ADMISSION`. Select
`--trust-mode HISTORICAL` only for a receipt retrieved from GlassBox state whose
checksummed admission attestation has already been verified. This prevents a retired
key from creating a new backdated artifact and presenting it as history.

## Deterministic and privacy boundaries

- Only fixed, known-safe projection properties may enter a projection-only report.
  Arbitrary `glassbox.*` fields are counted and omitted.
- Receipt reports expose identifiers, URNs, epistemic states, action effects,
  outcomes, reason codes, and digests—not prompt, row, argument, or output bodies.
- A valid signature proves integrity and key possession, not operator authority or
  factual truth. Production helper use requires the shared fingerprint-bound signer
  policy; untrusted self-signature acceptance is an explicit development override.
- Search silence never proves that no receipt was affected unless index completeness
  is established separately.
- `UNAFFECTED` requires positive evidence such as complete field lineage with a
  proven non-wildcard query.
- No helper performs a DataHub mutation, approval, replay, quarantine, or incident
## Evaluation evidence

Run the executable skill evaluations:

```bash
uv run pytest -q \
  tests/unit/test_forensics_skill.py \
  tests/unit/test_narration_evaluation.py
```

They verify:

- identical inputs yield byte-identical reports;
- signed receipts verify and one-byte semantic tampering fails closed;
- unsigned receipts fail by default and require an explicit inspection-only override;
- secrets in DBOM extensions and unknown DataHub custom properties never appear;
- a DataHub Document remains `PROJECTION_ONLY`;
- exact used-field change is `STALE`;
- unrelated field change is `UNAFFECTED` only with complete positive lineage proof;
- partial field lineage is `AT_RISK`;
- missing canonical policy code returns an error instead of an invented verdict;
- all 18 dual-MCP facts remain exact in the narration claim ledger;
- unavailable Incident projection, configuration-dependent organizational scope,
  and `NONE` mutation authority cannot be silently upgraded;
- invalid agent prose is hashed but never echoed by the evaluator.

The broader live proof at
[`compatibility/datahub-1.6.0-replay-supersession.live.json`](compatibility/datahub-1.6.0-replay-supersession.live.json)
establishes the DataHub entities the skill investigates: source receipt, replay
receipt, and immutable supersession Document with direct readback.

The skill-specific
[`compatibility/datahub-1.6.0-agent-forensics.live.json`](compatibility/datahub-1.6.0-agent-forensics.live.json)
proof uses the official DataHub CLI direct-read route with forensic correlation. It
demonstrates the verified DBOM versus `PROJECTION_ONLY` distinction and both the
used-field material control and unrelated-field negative control.

The
[`compatibility/datahub-1.6.0-dual-mcp-forensics.live.json`](compatibility/datahub-1.6.0-dual-mcp-forensics.live.json)
proof runs the official DataHub MCP server and GlassBox MCP concurrently against a
real Action-completed incident backed by DataHub Core `v1.6.0` and PostgreSQL 16.
It proves the intended composition rather than replaying a response fixture:
DataHub supplies the affected catalog entity, exact schema field/type, incident
health, and receipt relationship; GlassBox supplies fresh signature verification,
run-specific influence, the persisted `STALE` finding, quarantine, completed
campaign, and directly verified writeback. The report also preserves the measured
fact that official MCP `0.6.0` did not project the exact Incident body on this Core
version. The Skill must say that this read is unavailable instead of inventing it.

The
[`compatibility/datahub-1.6.0-dual-mcp-agent-narration.eval.json`](compatibility/datahub-1.6.0-dual-mcp-agent-narration.eval.json)
evaluation forward-tests that behavior with independent agent contexts. Both an
ordinary forensic question and an adversarial request for invented Incident root
cause, organization-wide completeness, and mutation authority passed the closed
18-fact validator. An independent semantic review found no contradiction, while
remaining explicitly model-based and non-authoritative. The reusable boundary and
commands are defined in
[`references/narration-contract.md`](../skills/datahub-agent-forensics/references/narration-contract.md)
and [ADR-0019](adr/0019-machine-auditable-agent-narration.md).

## Upstream preparation

The contribution is staged at the target repository's `skills/<name>` boundary and
uses the same adjacent-skill names. Before opening an upstream PR:

1. Copy the skill into `skills/datahub-agent-forensics/` in a current fork of
   `datahub-project/datahub-skills`.
2. Add Agent Forensics to the root README catalog and the `using-datahub` routing
   table. Route agent-decision causality, DBOM, stale-output, approval, and replay
   questions here; keep generic dataset impact in `datahub-lineage`.
3. Apply any current target-specific optional frontmatter, command, or plugin catalog
   fields without weakening the portable `name` and `description` trigger.
4. Preserve the Apache-2.0 license and describe the optional `glassbox-core`
   dependency for cryptographic verification and canonical materiality.
5. Run the target repository's `pre-commit run --all-files`, then run these adversarial
   evaluations in GlassBox against every supported Python/DataHub version.
6. Use a conventional PR title such as
   `feat: add agent decision forensics skill`.

An upstream contribution must not claim that DataHub search or generic lineage alone
proves agent influence. That distinction is the core value of this skill.
