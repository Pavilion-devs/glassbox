# ADR-0025: Pin the flagship estate and ablate evidence capabilities through one policy

- **Status:** Accepted
- **Date:** 2026-08-09
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0020](0020-signed-invalidation-to-recovery-handoff.md),
  [ADR-0021](0021-oci-isolated-replay-and-verified-incident-closure.md), and
  [ADR-0023](0023-content-addressed-domain-semantic-policies.md)

## Context

The causal flagship already proved the complete GlassBox recovery chain against
DataHub Core, PostgreSQL, both MCP servers, and an OCI-isolated capability. It still
required an operator to start DataHub and PostgreSQL, build the replay image, copy
its digest, and invoke the scenario. That was reproducible by a maintainer, but not
one command from a fresh checkout.

The evaluation plan also required five ablations. Implementing five unrelated
classifiers would make the result easy to game: a baseline could be weakened by
code rather than by the evidence it lacks. Correctness, live integration evidence,
and timing measurements also have different authorities and must not be blended
into one flattering score.

## Decision

- `examples.flagship_demo` owns the entire reference estate after the user passes
  the explicit `--allow-live` gate. It checks Docker and `uvx`, fetches DataHub's
  official quickstart compose from exact upstream commit
  `059a36c0b035a6057de00114ccac0ea9003d6bc2`, and records the downloaded bytes'
  SHA-256 digest.
- A committed Compose overlay replaces every upstream host port and every explicit
  network or volume name. The project is always `glassbox-flagship`, adds a
  PostgreSQL 16 state service, uses an isolated runtime home, and can coexist with a
  normal DataHub quickstart.
- The launcher validates the merged Compose model, waits for service health, builds
  and inspects the source/schema-bound replay sandbox, invokes the existing real
  causal flagship, and accepts success only when the report proves the exact Core
  version and commit, both MCP planes, real DataHub writes/readback, PostgreSQL,
  isolation, recovery, closure, privacy, and zero-write redelivery.
- Cleanup targets only the exact Compose project and its disposable volumes. It is
  the default even on failure. `--keep-estate` is an explicit inspection mode.
- `--compose-file` is an explicit local-development override. Its bytes are still
  validated and hashed, but its report is labeled `LOCAL_OVERRIDE` and cannot be
  presented as the pinned fresh-checkout path.
- The benchmark runs all five required variants through the same production
  `glassbox.materiality.v1` classifier. Each variant is a deterministic projection
  that removes named evidence capabilities: runtime observation authority, field
  identity, or metadata snapshot time/digest. The full variant removes nothing.
- Ground truth, declared assets, raw-trace asset hints, runtime dependencies,
  field-lineage state, snapshots, and changes are public synthetic fixtures. The
  report includes every per-case state and reason code, resolution failures, false
  invalidations, missed invalidations, and dishonest uncertainty outcomes.
- Selection is an exact rule, not a model judge: minimize missed invalidation, then
  false invalidation, while requiring perfect honesty on indeterminate cases.
- Deterministic fixture correctness, offline single-process timing, and metrics
  derived from the committed live DataHub report remain separately labeled. A
  mixed adapter write unit is described precisely and never called a storage row.
- A fresh-host success rate remains `NOT_MEASURED_ON_A_FRESH_HOST` until independent
  clean-host repetitions exist. The presence of a one-command launcher is not used
  to invent that measurement.

## Evidence

Unit tests exercise the full launcher lifecycle through its process boundary,
including compose validation, exact project scoping, sandbox/report acceptance,
failure on Core drift, cleanup, and credential exclusion. The merged overlay also
passes Docker Compose validation against an official quickstart file.

A real one-command run started all eight isolated services, completed the causal
proof in 56.728 seconds, directly received Core `v1.6.0` and commit
`059a36c0b035a6057de00114ccac0ea9003d6bc2`, and removed every project container,
network, and volume. The raw-free report is
[`datahub-1.6.0-one-command-flagship.live.json`](../compatibility/datahub-1.6.0-one-command-flagship.live.json).
The execution environment could not resolve GitHub, so this measured run used its
locally cached official quickstart file and is correctly labeled `LOCAL_OVERRIDE`;
it proves the orchestration and Core target, not the default download path on a
fresh host.

The benchmark has 12 public cases: exact used-field change, unrelated-field
negative control, post-change snapshot, other-asset change, trace alias collision,
semantic constraint and reference changes, absent freshness requirement, wildcard
ambiguity, unresolved runtime context, declared-but-unobserved assets, and a safe
new-field addition. Its schema-valid report is
[`agent-invalidation-ablation.v1.json`](../benchmarks/agent-invalidation-ablation.v1.json).

On those fixtures, full GlassBox records zero false invalidations across six clean
cases, zero misses across three contaminated cases, and honest uncertainty across
all three indeterminate cases. The unresolved case is published as a field- and
asset-resolution failure and remains `UNKNOWN`; it is not rewritten as success.

## Alternatives considered

- Keep the four manual setup steps: rejected because they violate Gate 9's fresh
  checkout and one-command exit criteria.
- Depend on an already-running DataHub: rejected because hidden state, versions,
  and port ownership make a flagship irreproducible.
- Copy DataHub's generated compose into this repository: rejected because a
  commit-addressed primary upstream artifact plus a small auditable overlay keeps
  ownership and drift clearer.
- Reimplement simplified baseline classifiers: rejected because implementation
  differences would confound the evidence ablation.
- Collapse `AT_RISK` into either correct or incorrect contamination: rejected
  because uncertainty is a first-class product result and needs its own honesty
  denominator.
- Publish only an aggregate score: rejected because failed cases and exact
  denominators are required for skeptical review.

## Consequences and limits

The pinned path requires Docker Compose with `!override` support, `uv`, internet
access for missing official artifacts and images, available configured host ports,
and enough memory for DataHub quickstart. It proves a disposable single-host estate,
not production topology, failover, or organization-wide retention.

The correctness fixture distribution is not an estimate of production prevalence.
The timing section measures deterministic local Python work and deliberately
excludes DataHub, MCP, PostgreSQL, Docker startup, model providers, and networks.
Raw OpenTelemetry in this benchmark means spans without GlassBox-qualified,
authority-verified DataHub field and snapshot attributes; instrumented OTel carrying
those attributes is GlassBox evidence, not the raw-trace ablation.

## Reversal conditions

Replace the quickstart orchestration if DataHub publishes a content-addressed,
project-isolated reference-estate contract with equivalent version, health, and
cleanup guarantees. Add an ablation implementation only when it can be expressed as
another explicit evidence-capability projection or a separately justified competing
system; never silently change a baseline's decision rules.
