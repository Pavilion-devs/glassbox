# ADR-0011: Use content-addressed replay bundles and exact approval binding

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

A DBOM records what happened. It is append-only and cannot also serve as a mutable
replay request. Replaying directly from a receipt would leave several unsafe choices
implicit: which historical resources are available, whether input and model
parameters are recoverable, which context is being corrected, and whether an
approval still covers the action that will execute.

DBOM 0.1 intentionally does not retain raw inputs, model parameters, feature flags,
or full evidence representations. A replay design must preserve that privacy
boundary without pretending that missing material can be reconstructed.

## Decision

- Derive a separate Replay Bundle 0.1 artifact from a verified source receipt. The
  bundle commits the source receipt ID and payload digest and never mutates history.
- Content-address the bundle using RFC 8785, SHA-256, and domain separation. Sign its
  payload with Ed25519 independently from the source DBOM.
- Pin exact agent, workflow, model, skill, tool, tool-schema, query, action, context,
  original-output, input, feature-flag, and model-parameter digest material.
- Supply material absent from DBOM 0.1 through an explicit digest-only replay
  supplement with verification-authority labels. Missing material is never replaced
  by a current or “compatible” version.
- Keep replay modes closed: pinned, corrected, counterfactual, and dry. Context
  replacements name one existing evidence item and preserve its epistemic state.
- Make the planner deterministic and content-addressed. Invalid signatures,
  unavailable exact resources, or unsafe failed states block execution. Incomplete
  context or model material produces dry-run only.
- Never authorize irreversible actions. Unknown effects and uncertain outcomes are
  non-executing. Read-only actions may be allowed; reversible actions require a
  rollback contract, idempotency key, and human approval.
- Bind approval to the exact bundle ID, action-set digest, environment, policy
  version, reason digest, issuer, expiry, and scope. Require both a valid embedded
  signature and an operator-configured trusted key ID. Changing an action or matched
  resource invalidates the approval.
- Keep dry-run structurally incapable of execution: its API accepts no tool or
  network backend and reports zero external calls and history mutations.
- Require a future real executor to emit a new replay DBOM and supersession record;
  it may never overwrite the source receipt.

## Evidence

The unit and contract suites prove deterministic bundle identity, source binding,
one-byte tamper detection, strict signature decoding, closed replacement modes,
resource-substitution refusal, irreversible-action blocking, model-pin degradation,
approval trust/expiry/revocation, action-change invalidation, and a content-addressed
dry-run report with no invocation capability. The `glassbox-replay dry-run` command
executes the same policy path and does not emit the signing secret.

## Alternatives considered

- Add replay fields to the original DBOM: rejected because it would conflate an
  immutable historical record with a later execution request.
- Resolve missing versions to the latest compatible resource: rejected because
  compatibility is not equivalence and would hide non-reproducibility.
- Treat any valid self-contained approval signature as trusted: rejected because a
  self-asserted public key proves possession, not organizational authority.
- Let dry-run call tools with a flag: rejected because configuration mistakes could
  turn inspection into side effects.
- Automatically replay reversible actions: rejected because “reversible” does not
  mean harmless and rollback can fail.

## Consequences and limits

- The current executor renders and validates only. It does not yet run even
  read-only tools, compare new output structurally or semantically, publish a new
  replay DBOM, or write supersession metadata to DataHub.
- Verification-authority strings are boundary claims. A remote artifact resolver and
  organizational identity binding remain required before production execution.
- Model nondeterminism is disclosed. Exact parameters improve reproducibility but do
  not make a nondeterministic provider deterministic.
- A bundle signature proves integrity and key possession, not truth. A source receipt
  can faithfully record false declared context.
- Approval revocation is represented in the approval object today; a production
  verifier still needs a durable revocation authority and freshness contract.

## Reversal conditions

Supersede this ADR if a future DBOM version safely commits all replay inputs without
breaking the privacy model, or if DataHub provides a native immutable replay-request
and approval primitive with equal content binding, trust separation, and audit
semantics. Do not weaken irreversible-action or history-preservation rules.
