# ADR-0012: Execute read-only replay through exact capabilities and separate supersession

- **Status:** Accepted
- **Date:** 2026-08-06
- **Owners:** GlassBox maintainers

## Context

ADR-0011 establishes signed replay bundles, fresh deterministic planning, exact
approval binding, and a dry-run renderer with no execution backend. The next step
must perform useful work without turning an `ALLOW` string into ambient authority.
It must also compare outputs and represent supersession without rewriting either
historical DBOM.

Python callbacks cannot prove OS-level process or network isolation. A design that
described an injected callback as sandboxed would overstate its guarantees.

## Decision

- Re-run deterministic planning at the execution boundary with the supplied exact
  resource inventory. Reject stale, modified, non-`ALLOW`, or cross-bundle plans.
- Limit this executor to `READ_ONLY` actions. It does not execute reversible actions,
  even if a different planner path can authorize them with approval.
- Resolve tools only through an explicit capability registry. A capability must
  match tool ID, version, source digest, and schema digest. There is no ambient name
  lookup or current-version fallback.
- Resolve global and per-action inputs outside the receipt, pass transient values to
  the executor, and recompute runtime-domain digests before any invocation. Deep-copy
  values at handler and projector boundaries.
- Treat injected handlers as trusted application code, not as an OS sandbox. Record
  the capability authority in the execution artifact. Production deployment must
  add process, network, filesystem, time, and resource isolation.
- Convert handler and projector exceptions into bounded error-type commitments.
  Do not retain messages or raw values. Stop after the first failed action and mark
  later actions blocked.
- Content-address the execution outcome and commit action inputs/outputs, context
  observations, final output, run identity, timing, and zero source-history
  mutations. Raw values are excluded from projections.
- Emit a new signed DBOM for every attempted replay, including failed replay. Link it
  through `replay.prior_receipt_digest` and explicit replay artifact IDs. Never copy
  original evaluations onto a new output.
- For corrected context, require a runtime observation matching the replacement
  digest and verification authority. Commit its span, time, and runtime capture
  method before labeling the evidence observed in the new DBOM.
- Produce a content-addressed structural diff containing JSON Pointer paths, change
  kinds, types, and domain-separated value digests only. The built-in semantic rule
  means exact content equivalence only; it does not claim business equivalence.
- Represent supersession as another immutable content-addressed record linking both
  receipts, bundle, plan, execution, and diff.
- Project supersession into DataHub Core as a separate deterministic Document. Write
  it twice, require the same URN, and directly read back every managed property and
  persisted aspect. Do not mutate either receipt Document to create the relation.

## Evidence

The focused replay suite proves exact successful execution, bounded handler and
projector failure, fresh-policy drift rejection, capability mismatch, action/global
input mismatch, corrected-context observation binding, source-mutation detection,
new signed replay DBOM validation, exact and changed outputs, array/object/type
diffs, raw-value exclusion, cross-artifact rejection, supersession content
addressing, double-write idempotency, and direct-read mismatch failure.

The offline `examples.replay_read_only` scenario reproduces the complete artifact
chain without a network service. The guarded live proof then used Core 1.6.0 and SDK
1.6.0.15 to double-write both receipt Documents and the separate supersession
Document, directly read back five aspects and all 14 managed relation properties,
and confirm that both receipt entity hashes were identical before and after the
supersession write.

## Alternatives considered

- Import a handler by arbitrary CLI module path: rejected because it broadens code
  execution authority and makes provenance of the loaded capability ambiguous.
- Trust the caller-supplied plan without recomputation: rejected because a content
  address proves integrity, not that current resources and policy still match.
- Store raw outputs to make diffing easy: rejected because it breaks the DBOM privacy
  boundary. Raw values remain transient and callers retain their authoritative
  artifact-store responsibilities.
- Use a model to judge semantic equivalence by default: rejected because that would
  put a nondeterministic judgment inside an authorization and supersession path.
- Update the original receipt Document with `superseded_by`: rejected for the first
  implementation because a separate relation record gives stronger history
  preservation and idempotency.

## Consequences and limits

- The executor is capability-scoped but in-process. A malicious or defective handler
  can still use ambient Python/network authority; this implementation detects source
  mutation but cannot roll back arbitrary external behavior.
- The generic executor intentionally has no arbitrary-code CLI. Applications inject
  reviewed capabilities programmatically.
- Exact semantic equality is useful and reproducible but narrower than domain
  equivalence. Versioned deterministic business rules are future extensions.
- The DataHub Document is a stable-Core compatibility projection, not a new native
  metadata entity or typed relationship. A metadata RFC can supersede it.
- A process-level isolation profile remains required before production execution
  claims. The Core 1.6.0 Document projection is live-proven.

## Reversal conditions

Supersede the in-process capability adapter when a portable worker sandbox can prove
network/filesystem denial and bounded resources while preserving exact input/output
commitments. Replace the Document projection when DataHub supports a native immutable
decision-supersession entity or typed edge with equal direct-verification semantics.
