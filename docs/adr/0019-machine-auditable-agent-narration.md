# ADR-0019: Bind agent narration to a closed evidence ledger

- **Status:** Accepted
- **Date:** 2026-08-07
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0013](0013-read-only-forensics-mcp.md) and
  [ADR-0014](0014-shared-live-decision-state.md)

## Context

The official DataHub MCP and GlassBox MCP can now produce a cross-bound, raw-free
forensic proof. A natural-language agent can still weaken that proof after retrieval
by turning `UNAVAILABLE` into a guessed Incident body, `scan_complete` into an
organization-wide claim, or a read-only investigation into implied mutation
authority. Prompt instructions alone are not a deterministic boundary.

An LLM-as-judge can catch semantic contradictions, but it is nondeterministic and
cannot become the integrity, materiality, or authorization gate. Requiring one fixed
sentence would be deterministic but would eliminate the useful explanatory role of
the Skill.

## Decision

- Project a valid `glassbox.dual-mcp-forensics.v1` report into a closed,
  raw-free `glassbox.agent-narration-brief.v1` fact ledger.
- Reject source evidence unless its cross-plane identities are exact, the DataHub
  catalog and incident-health evidence is proven, the GlassBox receipt/finding/
  campaign/writeback chain is complete, and both MCP surfaces remain read-only.
- Require a `glassbox.agent-narration.v1` response sidecar. It contains natural
  language plus every required fact ID and exact typed value, mandatory limitations,
  fixed `NONE` mutation authority, and a raw-content boundary.
- Require the finding to cite its core receipt, field, verification, observed
  influence, stale finding, completed campaign, and verified writeback facts.
- Include unavailable Incident projection and non-proven organizational scope as
  mandatory limitations only while those states remain unproven. Never encode a
  permanent limitation that future evidence could legitimately close.
- Validate the sidecar deterministically. Reject missing, duplicated, reordered,
  unsupported, or value-altered claims; missing citations or limitations; raw
  content; and inflated mutation authority.
- Hash but never echo agent prose in the evaluation report. The evaluator returns
  bounded reason codes, counts, preservation booleans, and the response digest.
- Report free-prose semantics as `NOT_DETERMINISTICALLY_PROVEN`. Use independent
  model review to forward-test contradictions, and label that result as model-based
  rather than an integrity or policy proof.
- Keep ordinary human-readable forensic reports available. Require the structured
  sidecar only for audit, CI, or explicit machine-auditable evaluation workflows.

## Alternatives considered

- Trust Skill instructions alone: rejected because prompt adherence is not a
  deterministic evidence boundary.
- Use only an LLM judge: rejected because model judgment is nondeterministic and
  cannot authorize or establish forensic facts.
- Ban natural language and return only evidence JSON: rejected because explanation
  is a core Skill responsibility and the fact ledger already bounds its claims.
- Require an exact canned sentence: rejected because it proves template matching,
  not that an agent can explain the evidence usefully.
- Search prose for a few forbidden phrases: rejected as the primary mechanism
  because paraphrases make denylist-only evaluation brittle. Phrase-level model
  review remains a secondary forward-test surface.

## Consequences and limits

- CI and auditors gain a deterministic answer boundary without moving policy into
  the model.
- Agent clients must preserve a structured sidecar alongside free prose when the
  machine-auditable mode is requested.
- A valid evaluation proves the structured claims, citations, limitations, and
  authority match the brief. It does not prove that arbitrary prose is factually
  correct or free of contradiction.
- The fact vocabulary is intentionally closed. Adding a new narrated fact requires
  versioned contract work and tests rather than an unreviewed prompt change.
- The evaluator is raw-free but its response digest can still correlate repeated
  answers; operators should apply ordinary audit-retention controls.

## Reversal conditions

Replace the sidecar if a broadly adopted agent protocol provides equivalent typed
claim binding, exact evidence citations, closed limitations, raw-free validation,
and explicit separation between deterministic checks and model-based prose review.
Do not remove the boundary merely because a newer model appears less likely to
hallucinate.
