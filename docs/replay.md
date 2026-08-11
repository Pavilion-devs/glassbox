# Replay bundles, approvals, and dry-run policy

GlassBox replay is a controlled derivation from a signed DBOM, not a retry button.
The current vertical slice builds a signed, content-addressed replay bundle; matches
the exact historical recipe against an explicit resource inventory; evaluates a
deterministic policy; renders a no-side-effect report; and can execute an exact
read-only recipe through explicitly injected capabilities.

## What is implemented

The replay bundle binds:

- the source receipt ID and payload digest;
- exact agent, workflow, model, skill, tool, and tool-schema pins;
- action inputs, outputs, effects, outcomes, idempotency keys, and tool bindings;
- input, feature-flag, and model-parameter digests supplied by a verified artifact
  boundary when DBOM 0.1 does not contain them;
- original or explicitly replaced context representations; and
- the original output digest.

The planner then makes one of five closed decisions: `ALLOW`,
`ALLOW_WITH_RECEIPT`, `REQUIRE_HUMAN_APPROVAL`, `DRY_RUN_ONLY`, or `BLOCK`.
Unknown or incomplete material never becomes an implicit substitution.

## Policy summary

| Condition | Result |
|---|---|
| Exact, complete read-only recipe | `ALLOW` |
| Reversible action with rollback and idempotency, no approval | `REQUIRE_HUMAN_APPROVAL` |
| Same reversible action with fresh trusted exact approval | `ALLOW_WITH_RECEIPT` |
| Unknown effect, missing execution material, incomplete context | `DRY_RUN_ONLY` or `BLOCK`, depending on hard safety failures |
| Irreversible action, invalid artifact, unavailable exact resource, failed action | `BLOCK` |
| Explicit `DRY` mode | `DRY_RUN_ONLY` |

Approval is not a free-form “yes.” It commits the bundle ID, action-set digest,
environment, policy version, scope, reason digest, issuer, issue time, expiry, and
revocation state. The verifier also requires a trusted signer identifier. Any action
or resource change produces a different digest and invalidates the approval.

## CLI

The CLI loads an Ed25519 private key only from the named environment variable. The
value is raw 32-byte private-key material encoded as unpadded base64url; it is never
written to the result.

```bash
export GLASSBOX_REPLAY_SIGNING_KEY='<base64url-private-key>'

uv run glassbox-replay bundle receipt.json \
  --mode PINNED \
  --supplement replay-supplement.json \
  > replay-bundle.json

uv run glassbox-replay verify-bundle replay-bundle.json receipt.json

uv run glassbox-replay dry-run receipt.json \
  --mode PINNED \
  --supplement replay-supplement.json \
  --inventory resource-inventory.json \
  --evaluated-at 2026-08-06T12:30:00Z
```

`dry-run` accepts no execution adapter. Its output is a content-addressed description
with `external_calls: 0`, `history_mutations: 0`, and
`would_invoke_actions: false`.

For a self-contained local demonstration that generates an ephemeral signing key,
run:

```bash
uv run python -m examples.replay_dry_run
```

Run the complete offline chain—read-only execution, new signed DBOM, structural and
deterministic semantic diff, and immutable supersession record—with:

```bash
uv run python -m examples.replay_read_only
```

The generic CLI deliberately does not import arbitrary handler modules. Real
execution is a programmatic boundary where the application registers reviewed
`ReadOnlyCapability` instances with exact tool ID, version, source digest, and schema
digest. The executor performs a fresh policy evaluation and recomputes all resolved
input digests before invoking a handler.

Handler and projector values are transient. Successful and failed executions produce
digest-only content-addressed outcomes; bounded failure material includes the error
type, never the exception message. A replay attempt becomes a new signed DBOM linked
to the source payload digest. Corrected context additionally requires a matching
runtime observation before the new receipt may retain an `OBSERVED` label.

Corrected `INPUT` evidence must also propagate into execution. The bundle commits
the source and active action-input digests, the exact evidence IDs, and the same
verification authority used by the context replacement. Omitting that propagation,
reusing the old digest, or supplying a runtime value with a different digest fails
closed before the capability is invoked.

The structural diff contains paths, change kinds, types, and value digests but no raw
values. Exact output equivalence remains the default. It is deterministic, not a
model judgment.

## Domain semantic policy packs

When exact equality is too narrow, a caller may explicitly select a declarative
`glassbox.semantic-policy.v1` pack. The pack is closed JSON, validated against
schema version `0.1.0`, bound to one receipt output kind, and identified by a content
address. A separate `SemanticPolicyRegistry` must trust that exact ID; a valid hash
alone grants no authority.

Version 0.1.0 permits only:

- `NUMERIC_TOLERANCE` at one exact JSON Pointer, with decimal absolute and/or
  relative bounds; and
- `UNORDERED_COLLECTION`, which compares canonical multisets and preserves
  duplicate counts.

There is no ignore-path rule and no arbitrary comparator. Every structural change
must be covered by a passing declared rule before the result can be `EQUIVALENT`.
Missing paths, wrong types, non-finite numbers, failed rules, and unmatched changes
produce `CHANGED`. The assessment persists identities, paths, coverage, and bounded
reason codes, never the compared values.

```python
from glassbox_policy import SemanticPolicyRegistry, pricing_recommendation_policy_v1
from glassbox_replay import build_replay_diff

policy = pricing_recommendation_policy_v1()
registry = SemanticPolicyRegistry.trust((policy,))
diff = build_replay_diff(
    source_receipt,
    replay_receipt,
    source_output=source_output,  # transient
    replay_output=replay_output,  # transient
    semantic_policy_id=policy.policy_id,
    semantic_registry=registry,
)
```

The reference
[`pricing-recommendation-v1.json`](../examples/semantic-policies/pricing-recommendation-v1.json)
accepts `/recommended_price` when the absolute difference is at most `0.50` or the
relative difference is at most `0.005`. Changing any rule or bound changes the
policy ID and requires an explicit trust-registry rollout. See the
[Semantic Policy 0.1 contract](../schemas/semantic-policy/0.1.0/README.md) and
[ADR-0023](adr/0023-content-addressed-domain-semantic-policies.md).

Supersession is another immutable artifact linking the source and replay receipts,
bundle, plan, execution, and diff. The DataHub Core adapter projects that relation as
a separate deterministic Document, writes it twice, and directly verifies all
managed properties. It does not rewrite either receipt Document.

The guarded live proof against pinned DataHub Core 1.6.0 is:

```bash
uv run python -m examples.end_to_end_replay_supersession --allow-live
```

Its original committed sanitized report records two emissions each for the source
receipt, replay receipt, and supersession relation; direct readback of five persisted
aspects; exact verification of the then-current 14 managed properties; and identical
direct entity hashes for both receipt Documents before and after the relation write.

Exercise the real non-exact domain policy path with:

```bash
uv run python -m examples.end_to_end_replay_supersession \
  --pricing-semantic-policy \
  --allow-live
```

The committed
[semantic-policy report](compatibility/datahub-1.6.0-semantic-policy.live.json)
proves one changed path as policy-equivalent but not exact, directly verifies the
expanded 19-property supersession projection, excludes the transient output values,
and again proves both receipt Documents unchanged.

## Completed invalidation to corrected recovery

`RecoveryAuthorization` is the separate authority boundary between the Action and
replay worker. It can be issued only for an actual `COMPLETED` campaign with an
exact `STALE` finding, directly verified DataHub writeback, and verified quarantine
of the same source receipt. It binds one corrected bundle and expires. Verification
requires both a valid Ed25519 signature and an operator-configured public-key
fingerprint; an embedded key ID alone is insufficient.

Run the complete live causal scenario and its isolated service estate from a fresh
checkout:

```bash
uv run --all-extras python -m examples.flagship_demo \
  --allow-live \
  --output .glassbox/flagship/one-command-report.json
```

The command executes a real synthetic agent, publishes its signed receipt, proves
an unrelated field is `UNAFFECTED` with zero writes, applies a material field change,
verifies the `STALE` campaign through DataHub and both MCP planes, authorizes and
executes corrected read-only input inside the exact inspected OCI image, publishes a
new receipt, directly verifies the separate supersession, resolves the exact
DataHub incident, and proves both receipt Documents remain unchanged.

See [ADR-0020](adr/0020-signed-invalidation-to-recovery-handoff.md),
[ADR-0021](adr/0021-oci-isolated-replay-and-verified-incident-closure.md), and the
[sanitized flagship report](compatibility/datahub-1.6.0-flagship-causal-recovery.live.json).
The estate and acceptance contract are in
[ADR-0025](adr/0025-pinned-flagship-estate-and-evidence-ablation.md). The separate
[benchmark guide](benchmarks/README.md) documents the five production-policy
ablations and their published failed cases.
The [one-command live report](compatibility/datahub-1.6.0-one-command-flagship.live.json)
records the exact service images, nested causal proof, and successful estate cleanup.
Its compose source is visibly `LOCAL_OVERRIDE` because the measured host reused a
locally cached official quickstart file; Core still directly reported the required
`v1.6.0` build commit.

## Durable recovery orchestration

The replay worker now has a restart-safe PostgreSQL conductor in addition to the
domain contracts above. `PostgresRecoveryStore` extends the same initialized schema
used by the invalidation Action without changing its source receipt or campaign
rows. It verifies one exact `RecoveryAuthorization`, then advances through:

```text
AUTHORIZED
  -> ISOLATED_EXECUTION_SUCCEEDED
  -> REPLAY_RECEIPT_PUBLISHED
  -> SUPERSESSION_VERIFIED
  -> INCIDENT_CLOSED
```

An active operation is represented by a server-clock lease and an explicit claimed
state. Eight-connection PostgreSQL tests prove one claim winner, expired-lease
takeover, runtime reopen without DDL, ordered transitions, and an append-only event
ledger. Replay receipt, supersession, and closure IDs are persisted as a separate
recovery relation; the immutable source receipt index entry is not rewritten.

Immediately before execution, `RecoveryOrchestrator` rereads the completed campaign
and source receipt and rechecks the authorization signature, trusted fingerprint,
exact bundle binding, expiry, and revocation. The executor must return one
`RecoveryArtifacts` set built from the actual successful isolated execution, signed
replay DBOM, raw-free diff, supersession, and closure record. PostgreSQL commits this
set before any DataHub publication effect, so a later worker resumes publication
without rerunning the capability.

`DataHubRecoveryEffects` composes the existing durable receipt pipeline,
supersession emitter, and incident-closure emitter. Each stage persists
content-addressed direct-readback evidence, including whether that specific attempt
physically wrote. If DataHub resolved the incident with the exact closure before a
worker died, retry now verifies the same closure and unchanged receipt hashes with
zero new writes. A different resolution is still an error.

Run the guarded combined proof against an initialized PostgreSQL server, local
DataHub Core, and an exact image ID produced by `scripts/build_replay_sandbox.py`:

```bash
export GLASSBOX_STATE_POSTGRES_DSN='postgresql://...'
uv run python -m examples.end_to_end_durable_recovery run \
  --server http://localhost:8080 \
  --sandbox-image-digest 'sha256:...' \
  --allow-live
```

The parent stages one signed authorization, then starts five distinct worker
processes. Four workers each commit exactly one checkpoint and terminate through an
abrupt interpreter exit; the fifth freshly opens runtime state and proves closed
redelivery performs no claim or remote effect. The live Core 1.6.0 result is the
[raw-free crash report](compatibility/datahub-1.6.0-durable-recovery-crash.live.json).

Exercise the harder uncertain-completion boundary with the same live dependencies:

```bash
uv run python -m examples.end_to_end_durable_recovery run-uncertain \
  --server http://localhost:8080 \
  --sandbox-image-digest 'sha256:...' \
  --fault-lease-duration-ms 1000 \
  --allow-live
```

This campaign uses nine distinct processes. Four fault workers each complete and
directly verify one real OCI/DataHub operation, then terminate before calling the
PostgreSQL completion method. Four recovery workers wait for the database-clock
lease to expire and commit the exact deterministic result; a ninth proves closed
redelivery. The report explicitly shows the execution artifact identity and each
effect's physical-write behavior, rather than inferring it from emission counts.
See the
[raw-free uncertain-completion report](compatibility/datahub-1.6.0-durable-recovery-uncertain-crash.live.json).

Bootstrap recovery tables once with a role that can issue DDL, after the
invalidation schema exists:

```python
from glassbox_invalidation.postgres_store import PostgresInvalidationStore
from glassbox_replay.postgres_recovery import PostgresRecoveryStore

invalidation = PostgresInvalidationStore(dsn, schema="glassbox")
PostgresRecoveryStore(dsn, invalidation, schema="glassbox")

# Runtime workers verify only; they do not create or migrate tables.
runtime_state = PostgresRecoveryStore(
    dsn,
    invalidation,
    schema="glassbox",
    initialize_schema=False,
)
```

The DSN must come from a named environment variable in a deployment; it must not be
placed in a report, DataHub property, or committed configuration. The state stores
only signed/digest-bound operational artifacts and direct-readback evidence, not raw
corrected inputs, outputs, prompts, credentials, or exception messages.

This is exactly-once logical recovery identity with idempotent at-least-once remote
effects—not an exactly-once distributed transaction. If the parent process dies
after a read-only container finishes but before PostgreSQL commits its artifact set,
the capability may physically run again after lease expiry. That path is live-proven
to produce the same content-addressed artifact set. The stable workflow ID is its
idempotency key, and non-read-only work remains outside automatic recovery.
See [ADR-0022](adr/0022-postgresql-durable-recovery-orchestration.md).

## Input files

The supplement and inventory are deliberately digest-only. A production artifact
resolver will need to verify those digests and authorities before supplying actual
input bytes to an isolated executor.

```json
{
  "input_digest": "<64 lowercase hex characters>",
  "input_reference": "artifact://authority/object",
  "feature_flags_digest": "<64 lowercase hex characters>",
  "model_configs": [{
    "model_id": "model-id-from-receipt",
    "provider_id": "provider-id",
    "parameters_digest": "<64 lowercase hex characters>",
    "determinism": "DETERMINISTIC",
    "verification_authority": "artifact-store:production"
  }]
}
```

Each inventory resource has `kind`, `resource_id`, and `version`, plus the exact
`source_digest` required for agents, models, skills, and tools. Tools also require
`schema_digest`; reversible tools require `rollback_contract_digest`.

## Honest boundary

The base executor still permits explicitly trusted in-process handlers for offline
use. Automated recovery closure requires the OCI profile: exact image ID and tool
labels, no child network, read-only root, dropped capabilities, no-new-privileges,
resource and transport bounds, and successful denial probes. This does not protect
against a compromised host kernel or container runtime. The DataHub supersession
projection is live-proven on Core 1.6.0, but a native typed supersession entity does
not yet exist. PostgreSQL now persists the separate source, replay, supersession,
and closure identities without mutating source admission material; the legacy
`ReceiptDependencyProfile.superseded_by` field remains unchanged. Domain equivalence
is limited to explicitly trusted Semantic Policy 0.1 packs and the two closed v1
primitives; exact equality remains the default. Signatures prove integrity and key
possession; factual truth and operator identity still require an external trust
policy. Both committed-checkpoint restart and process death after successful
OCI/DataHub work but before PostgreSQL completion are live-proven on one host.
Physical multi-host failover, network partition recovery, and managed PostgreSQL
promotion are not exercised by these reports.
