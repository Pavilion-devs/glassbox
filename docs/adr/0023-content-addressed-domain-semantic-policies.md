# ADR-0023: Require trusted content-addressed policies for domain equivalence

- **Status:** Accepted
- **Date:** 2026-08-08
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0012](0012-capability-scoped-read-only-replay-and-supersession.md),
  [ADR-0021](0021-oci-isolated-replay-and-verified-incident-closure.md), and
  [ADR-0022](0022-postgresql-durable-recovery-orchestration.md)

## Context

Exact output equality is safe and deterministic, but it is too narrow for many real
agent outputs. A pricing recommendation can move by a contractually acceptable
amount, and an array can be semantically unchanged when only its order changes. If
GlassBox labels every such replay `CHANGED`, operators receive false-positive
recovery findings. If it delegates equivalence to prose, an LLM, or application code
loaded at runtime, the result cannot be reproduced or governed reliably.

A content hash proves that a policy document has not changed. It does not prove that
the policy is appropriate or authorized. Domain equivalence therefore needs both a
closed deterministic evaluator and a separate operator trust decision.

## Decision

- Exact equality remains the default. A domain policy is used only when the caller
  supplies its exact content-addressed `policy_id` and an operator-configured
  `SemanticPolicyRegistry` that trusts that same ID.
- Define the closed `glassbox.semantic-policy.v1` document contract at schema
  version `0.1.0`. Each pack binds its name, semantic version, output kind, ordered
  rules, and content-derived ID. The pack contains no executable code and no output
  values.
- Version 0.1.0 supports only two primitives:
  `NUMERIC_TOLERANCE` over one exact JSON Pointer, using decimal absolute and/or
  relative bounds; and `UNORDERED_COLLECTION`, which compares canonical array
  multisets while preserving duplicate counts.
- Do not add arbitrary ignore-path, regex, callback, expression, or model-judgment
  rules. A field may be treated as equivalent only through a positive closed proof.
- Require complete coverage. Every structural change path must be covered by a
  passing declared rule before the assessment can be `EQUIVALENT`. Missing paths,
  type mismatches, non-finite numbers, exceeded tolerances, failed rules, and
  unmatched structural changes yield `CHANGED`.
- Bind each pack to one exact receipt `output.kind`. Source and replay receipt kinds
  must match each other and the trusted pack. A trusted pricing policy cannot be
  reused silently for another output domain.
- Keep source and replay values transient. Persist only policy identity, rule
  identity and version, result, exact-match flag, structural and matched counts,
  reason codes, rule kinds, JSON Pointer paths, and covered change paths.
- Carry the complete raw-free assessment inside the replay diff and durable recovery
  artifacts. Cross-bind its identity and result into the immutable supersession
  record. Project policy ID, rule ID, rule version, method, result, and exact-match
  flag into the separate DataHub supersession Document without editing either
  receipt Document.
- Version the changed durable envelope as `glassbox.recovery-artifacts.v2`, change
  its content-address domain, and bump PostgreSQL recovery schema from 1 to 2.
  Runtime workers refuse v1 state rather than misreading older artifact bytes; this
  pre-release boundary requires deliberate rebuild and reauthorization, not a
  metadata-marker edit.
- Ship `glassbox.pricing-recommendation` version `1.0.0` as the reference pack. It
  proves `/recommended_price` equivalent when either the absolute difference is at
  most `0.50` or the relative difference is at most `0.005`.

## Trust and update model

Policy integrity and policy authority are separate:

1. JSON Schema and the content address prove the bytes form a valid, unchanged pack.
2. The trusted registry proves that an operator selected that exact pack for use.
3. The output-kind binding proves that the selected pack applies to this receipt
   domain.
4. The assessment proves how the selected policy covered this exact structural diff.

Changing a tolerance, path, rule, name, version, or output kind creates a different
`policy_id`. Deployment must review and trust that new ID explicitly. Historical
assessments continue to identify the exact old policy and are not reinterpreted by a
new registry entry.

## Evidence

Unit tests cover content-address verification, schema closure, registry authority,
output-kind binding, exact-default behavior, numeric bounds, multiset reordering,
duplicate sensitivity, missing paths, type mismatches, failed rules, unmatched
changes, overlapping rules, and raw-value exclusion.

The guarded Core 1.6.0 proof compared transient prices `100.0` and `100.4`. It
recorded one structural change, one passing tolerance rule, `EQUIVALENT`, and
`exact_match=false`; wrote and directly read back the source receipt, replay receipt,
and supersession; verified all 19 managed relation properties; and proved that both
receipt Documents remained unchanged. Neither price nor the synthetic customer ID
appears in the committed report:
[`datahub-1.6.0-semantic-policy.live.json`](../compatibility/datahub-1.6.0-semantic-policy.live.json).

## Alternatives considered

- Keep exact equality only: rejected as the sole option because it cannot represent
  deterministic domain contracts and creates avoidable false-positive changes.
- Let each application provide a Python comparator: rejected because arbitrary code
  weakens portability, auditability, and the trust boundary.
- Ask a model whether outputs mean the same thing: rejected because the answer is
  nondeterministic and cannot authorize incident closure.
- Add ignore-path rules: rejected because they can silently erase meaningful
  changes and do not positively prove equivalence.
- Trust any valid content-addressed pack: rejected because integrity is not
  authorization.
- Store raw before/after values as evaluation evidence: rejected because the replay
  artifacts and DataHub graph are not payload stores.

## Consequences and limits

GlassBox can now distinguish exact equality, policy-proven domain equivalence, and a
real change without introducing model judgment or raw-value retention. Operators
gain an explicit review and rollout obligation for policy IDs. The first contract is
deliberately small: it does not support string normalization, unit conversion,
nested keyed-set comparison, statistical distributions, or application callbacks.
Those require new closed primitives and contract-version review, not configuration
workarounds.

The policy proves conformance to declared comparison rules; it does not prove that
the output is factually correct, that the tolerance is appropriate, or that the
operator's trust configuration is well governed. Recovery authorization and
incident closure remain separate controls.

## Reversal conditions

Replace this contract if DataHub adopts a native, immutable semantic-evaluation
entity with equivalent content addressing, operator authority, complete structural
coverage, raw-free evidence, and history-preserving supersession. Extend the
primitive set only when a new operation has deterministic cross-language semantics,
a closed schema, adversarial tests, and an explicit versioning path.
