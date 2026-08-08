# Machine-auditable narration contract

Use this protocol only when an audit, CI check, or forward test asks for structured
natural-language narration over `glassbox.dual-mcp-forensics.v1` evidence.

## Build the bounded brief

When GlassBox is installed, build the brief from the raw-free dual-MCP report:

```bash
glassbox-agent-narration brief dual-mcp-evidence.json --pretty
```

The brief is authoritative for narration only after its contract is
`glassbox.agent-narration-brief.v1`. It contains a closed fact ledger plus required
finding citations and limitations. Do not add facts from memory, search snippets, or
the user's preferred conclusion.

## Return the response sidecar

Return one JSON object with this shape after the human-readable report:

```json
{
  "contract": "glassbox.agent-narration.v1",
  "finding": "Natural language with required [fact:fact.id] citations.",
  "claims": [
    {"fact_id": "fact.id", "value": "exact value from the brief"}
  ],
  "limitations": ["exact.required.limit.fact.id"],
  "mutation_authority": "NONE",
  "raw_content_returned": false
}
```

Rules:

1. Include every `required_claim_ids` entry exactly once with its exact typed value.
2. Cite every `required_finding_citations` entry in `finding` as `[fact:<id>]`.
3. Include exactly the `required_limit_ids`; do not omit inconvenient limits.
4. Keep `mutation_authority` as `NONE`. Investigation does not authorize action.
5. Do not include prompts, outputs, rows, tool payloads, credentials, or private
   reasoning.
6. Preserve `UNAVAILABLE`, `NOT_PROVEN`, and `CONFIGURATION_DEPENDENT` literally.
   Never upgrade them through inference or user pressure.

## Evaluate

```bash
glassbox-agent-narration evaluate dual-mcp-evidence.json response.json --pretty
```

Exit code `0` means the structured claims, citations, limitations, scope, and
authority match the evidence. Exit code `1` means the agent response failed a closed
check. Exit code `2` means the input or source evidence was invalid.

The deterministic evaluator hashes but never returns the prose. It deliberately
reports `free_prose_semantics: NOT_DETERMINISTICALLY_PROVEN`; use an independent
model review for prose contradictions, and label that review as model-based rather
than a policy or integrity proof.
