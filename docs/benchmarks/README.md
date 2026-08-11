# Agent invalidation benchmark

This benchmark answers one narrow question with exact denominators:

> Which previously emitted agent decisions can each evidence contract correctly
> quarantine or release after governed context changes?

It is not a model-judge leaderboard. All five required variants execute the same
production `glassbox.materiality.v1` classifier. An ablation removes evidence from a
normalized receipt profile; it does not replace the policy with hand-written
baseline logic.

## Run it

From a fresh checkout with `uv` installed:

```bash
uv run --all-extras python -m benchmarks.agent_invalidation \
  --performance-samples 500 \
  --compilation-samples 50 \
  --output .glassbox/agent-invalidation-ablation.json
```

The command validates the closed report schema and content address before writing.
Use `--without-live-report` to exclude metrics derived from the committed DataHub
Core flagship proof. Correctness output and `benchmark_id` remain deterministic;
timings are environment-specific and are not part of that correctness identity.

## Compared evidence contracts

| Variant | Evidence deliberately removed |
| --- | --- |
| Static declared lineage | Runtime observation, fields, snapshots |
| Raw OpenTelemetry traces | Verified DataHub resolution, fields, snapshots |
| GlassBox without fields | Field identity and complete field-lineage proof |
| GlassBox without snapshots | Observation time and representation digest |
| Full GlassBox | Nothing |

“Raw OpenTelemetry” means ordinary spans without GlassBox-qualified DataHub field
and snapshot attributes. Once an instrumented trace carries those authority-bound
attributes, it is GlassBox evidence and belongs in the full path.

## Current proof

The committed [schema-valid report](agent-invalidation-ablation.v1.json) contains 12
public synthetic cases and every per-case state/reason. Its primary exact results
are:

| Variant | False invalidations | Missed invalidations | Honest uncertain cases | Field recall |
| --- | ---: | ---: | ---: | ---: |
| Static declared lineage | 5/6 | 0/3 | 3/3 | 0/9 |
| Raw OpenTelemetry traces | 4/6 | 0/3 | 3/3 | 0/9 |
| GlassBox without fields | 3/6 | 0/3 | 3/3 | 0/9 |
| GlassBox without snapshots | 1/6 | 0/3 | 3/3 | 8/9 |
| Full GlassBox | 0/6 | 0/3 | 3/3 | 8/9 |

The missing ninth field is deliberate: `unresolved-runtime-context` has ground truth
known to the fixture author but cannot be resolved by the runtime contract. Full
GlassBox returns `UNKNOWN` and quarantines it. The report publishes the resolution
failure rather than promoting it to observed or safe.

The same report records:

- 4/4 deterministic replay allow/refusal decisions;
- 0/10 secret-redaction escapes;
- 3/3 zero-write completed redeliveries from the live DataHub report;
- one successful corrected replay and one verified incident closure;
- the exact DataHub adapter write breakdown, labeled as emissions/aspect writes,
  not database rows;
- local p50/p95 agent instrumentation, receipt compilation, and policy-suite
  timings with environment and sample counts.

## What is not claimed

The 12 cases are a closed correctness corpus, not a claim about production incident
frequency. Local microbenchmarks exclude service and model latency. The one-command
estate is separately executable, but a statistically meaningful fresh-host setup
success rate still requires repeated independent clean hosts; the report marks that
metric unmeasured.

See [ADR-0025](../adr/0025-pinned-flagship-estate-and-evidence-ablation.md) for the
orchestration, baseline, and measurement decisions.
