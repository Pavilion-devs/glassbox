# GlassBox

GlassBox is a DataHub-native execution-provenance and control layer for AI agents.
It records a verifiable **Decision Bill of Materials (DBOM)** for consequential
agent outputs, connects curated runtime evidence to DataHub's governed metadata
graph, and provides the foundation for deterministic invalidation and safe replay.

> Data lineage tells you where data went. GlassBox tells you what your agents
> believed and did because of it.

## Current status

GlassBox is in the live vertical-slice implementation phase. The repository
currently contains:

- the DBOM 0.1 specification, canonicalizer, verifier, and tamper tests;
- a guarded DataHub Core capability probe;
- a framework-neutral Python runtime with nested-run correlation, evidence capture,
  risk-typed tool execution, privacy-safe callback tokens, and direct MCP middleware;
- OpenTelemetry GenAI span mapping plus tested LangChain/LangGraph and Google ADK
  adapters;
- a strict OTLP/HTTP JSON provenance compiler with verified DataHub URN resolution,
  append-only operational event persistence, signed DBOM generation, and fail-safe
  replay classification;
- a fail-closed live receipt pipeline that automatically registers each compiled
  signed DBOM and a durable publication obligation in the same transactional state
  used by the Action and MCP, verifies canonical state readback, then publishes and
  directly verifies its governed DataHub projection;
- an authenticated, bounded OTLP/HTTP JSON receiver that returns 200 only after
  publication evidence is sealed, plus an independent recovery worker and
  zero-write direct verification for completed redelivery;
- an idempotent DataHub receipt publisher proven through double-write and direct
  entity readback against Core 1.6.0;
- a deterministic materiality engine and installable DataHub Actions plugin with
  signed-receipt reverse indexing, content-addressed campaigns, native incident
  writeback, receipt quarantine, append-only audit, feedback-loop protection, and a
  live-proven Kafka retry/commit-failure/restart path plus an independently proven
  PostgreSQL Queue lease/visibility/acknowledgement path;
- a transactional SQLite WAL profile with atomic receipt indexing, competing-process
  campaign leases, expired-work recovery, sealed verification evidence, and
  zero-write verified redelivery on one host;
- a PostgreSQL 14+ profile with the same receipt and three-outbox contract, row-locked
  multi-worker claims, database-clock leases, operator-only bootstrap, and a real
  eight-connection PostgreSQL 16 concurrency proof;
- a signed, content-addressed State Transfer 0.1 contract that moves trusted receipt,
  field-lineage, and supersession state atomically between SQLite and PostgreSQL
  while refusing to reactivate old leases, campaigns, or notification side effects;
- a second durable owner-routing outbox plus a native DataHub ownership webhook
  adapter with environment-loaded credentials, stable idempotency keys, and
  privacy-minimized acceptance evidence;
- a signed, content-addressed Replay Bundle 0.1 contract with exact historical
  resource matching, deterministic policy decisions, digest-bound expiring
  approvals, and a structurally non-executing dry-run renderer;
- a policy-rechecked read-only replay executor plus a digest-pinned OCI profile with
  network denial, read-only root, dropped capabilities, resource ceilings, bounded
  transport, host-created attestations, and exact tool source/schema label checks;
- a new signed receipt, raw-free structural diff, history-preserving supersession,
  and verified idempotent DataHub incident closure that leaves both receipt
  Documents unchanged;
- a closed Semantic Policy 0.1 contract with content-addressed declarative rule
  packs, an explicit operator trust registry, complete change coverage, numeric
  tolerance and unordered-multiset primitives, raw-free durable assessments, and a
  live Core 1.6.0 non-exact-equivalence proof;
- a separately versioned PostgreSQL recovery state machine linked to the exact
  completed invalidation campaign and source receipt, with server-clock leases,
  atomic raw-free artifact sealing, persisted replay/supersession/closure IDs,
  append-only checkpoint events, per-attempt physical-write evidence, restart-safe
  DataHub effects, and exact prior closure recovery with zero writes, now live-proven
  across both committed-checkpoint and nine-process uncertain-completion campaigns
  against DataHub Core 1.6.0, PostgreSQL 16.14, and the exact digest-pinned OCI
  capability;
- the portable `datahub-agent-forensics` Skill with signed-DBOM inspection,
  projection-only safeguards, canonical impact classification, report templates, and
  adversarial evaluations;
- a protocol-neutral read-only forensics service plus an MCP v2 adapter with six
  proof-carrying tools for receipt verification, recorded influence, deterministic
  prospective impact, complete reverse scans, and actual persisted Action findings
  from the same PostgreSQL state authority;
- a responsive, judge-facing forensic console that explains receipt integrity,
  exact field influence, stale/unaffected outcomes, governed response, and replay
  boundaries without exposing raw agent content;
- architecture and compatibility decision records;
- a maintainer-facing native metadata RFC for immutable agent decisions, qualified
  runtime influence, verification, incidents, and append-only supersession, grounded
  in the working compatibility implementation;
- a release-evidence gate that verifies archive safety, wheel RECORD integrity,
  entry points, packaged contracts, byte-identical rebuilds, SHA-256 checksums, a
  CycloneDX lockfile SBOM, and clean Python 3.11–3.13 installs;
- the complete product and delivery plan in [`plan.md`](plan.md).

No UI screenshot or mock response is considered proof of integration. DataHub
capabilities are marked proven only after a live probe writes metadata and reads it
back directly from the configured server.

## Development

Requirements:

- Python 3.11–3.13 (3.12 recommended);
- [`uv`](https://docs.astral.sh/uv/);
- Docker Desktop only for disposable live DataHub Core and PostgreSQL checks.

```bash
uv sync --all-extras
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

Before publishing or handing off a source tree, run the repository preflight. It
evaluates the exact tracked and prospective source set, rejects generated files,
unsafe links, oversized files, private-key material, common credential formats,
personal machine paths, malformed JSON, and non-canonical project URLs, then emits
a content-addressed raw-free inventory:

```bash
uv run python -m scripts.repository_preflight --root .
```

Validate a receipt without DataHub:

```bash
uv run glassbox-dbom verify tests/fixtures/dbom/valid-read-only.json
```

For production authority, validate the operator registry and verify a signed receipt
against it. A self-contained signature without this policy proves key possession,
not authorization:

```bash
uv run glassbox-dbom verify-policy /etc/glassbox/trusted-signers.json
uv run glassbox-dbom verify receipt.json \
  --signer-trust-policy /etc/glassbox/trusted-signers.json \
  --json
```

Raw receipt files default to current-time `ADMISSION`. Use `--trust-mode HISTORICAL`
only when checksummed state or equivalent independent evidence proves the receipt was
admitted before the signer retired; a signer-authored timestamp is not that proof.

Use `glassbox-dbom signer-entry` to derive a policy entry from an
environment-indirect private key without returning its private bytes. The complete
procedure is the [signer rotation runbook](docs/operations/signing-key-rotation.md).

Inspect the DataHub probe without performing network writes:

```bash
uv run glassbox-datahub-probe plan
```

A live probe is deliberately gated. See
[`docs/compatibility/datahub-1.6.0.md`](docs/compatibility/datahub-1.6.0.md)
before running it.

Compile, sign, emit, and directly verify the deterministic live receipt proof:

```bash
export GLASSBOX_STATE_POSTGRES_DSN='postgresql://...'
uv run python -m examples.end_to_end_receipt --allow-live
```

When `GLASSBOX_STATE_POSTGRES_DSN` is present, the proof automatically opens the
already initialized `glassbox` Action schema in runtime mode, registers and rereads
the signed receipt, and only then publishes DataHub. Without that environment
variable, it runs the legacy DataHub-only compatibility proof. See the
[provenance compiler contract](docs/provenance-compiler.md) for explicit schema and
DSN-environment-name options, and the committed
[combined DataHub/PostgreSQL live report](docs/compatibility/datahub-1.6.0-postgresql-live-receipt-pipeline.live.json).

Run the used-field invalidation proof plus unrelated-field negative control:

```bash
uv run python -m examples.end_to_end_invalidation --allow-live
```

See the [invalidation action contract](docs/invalidation-action.md) and its
[live evidence report](docs/compatibility/datahub-1.6.0-invalidation.live.json).

Run the genuine GMS-to-Kafka-to-Actions transport proof, including one injected
action failure, exhaustion of the synchronous commit retry window, exact
same-offset redelivery, and a same-group recovery commit:

```bash
uv run python -m examples.end_to_end_broker_invalidation --allow-live
```

Its sanitized [Kafka evidence report](docs/compatibility/datahub-1.6.0-kafka-invalidation.live.json)
records the broker partition, unchanged failed-ack offset, exact recovered delivery,
recovery commit, retry counts, and all schema offsets observed on the third-process
negative control. The same proof exercises the transactional state profile after
automatic signed-receipt registration and canonical readback, resolves the native
DataHub owner, accepts exactly one loopback webhook, and re-verifies a completed
material campaign without another DataHub write or webhook call.

Run the separate PostgreSQL Queue source proof against a fresh disposable
PostgreSQL 16 database:

```bash
export GLASSBOX_PGQUEUE_PASSWORD='a-disposable-local-password'
uv run python -m examples.end_to_end_pgqueue_invalidation \
  --server http://localhost:18080 \
  --schema-registry-url http://localhost:18080/schema-registry/api/ \
  --pg-host-port 127.0.0.1:55434 \
  --initialize-schema \
  --allow-live
```

Its sanitized
[pgQueue evidence report](docs/compatibility/datahub-1.6.0-pgqueue-invalidation.live.json)
proves the official Actions source against real PostgreSQL leases and contiguous
offsets: the offset stays behind after failed acknowledgement, a restart cannot
steal the live lease, the exact handle returns after visibility expiry, completed
work is freshly verified with zero duplicate emissions, the ack marker advances the
offset, and a third restart is empty. Kafka and pgQueue claims remain deliberately
independent.

Initialize the SQLite state database before starting the reference Actions pipeline.
`register-receipt` remains available for historical imports or explicit repair; live
compiler paths register automatically:

```bash
mkdir -p .glassbox
export GLASSBOX_SIGNER_TRUST_POLICY_PATH=/etc/glassbox/trusted-signers.json
uv run glassbox-datahub-action inspect-install
uv run glassbox-datahub-action validate-config examples/datahub-actions-invalidation.yml
uv run glassbox-invalidation-state init .glassbox/invalidation.sqlite3
uv run glassbox-invalidation-state register-receipt \
  .glassbox/invalidation.sqlite3 receipt.json \
  --field-coverage COMPLETE \
  --field-rule glassbox.sql-column-lineage.v1 \
  --wildcard-query false
```

This SQLite profile coordinates processes on one host. It is deliberately not
presented as a multi-node or network-filesystem deployment.

The [ecosystem packaging note](docs/upstream/datahub-actions-contribution.md)
documents why this ships through DataHub's public external-plugin contract before
seeking core inclusion, along with the clean-wheel and release checklist.
The complete maintainer-facing submission sequence and ready-to-adapt discussion
text live in the [upstream contribution packet](docs/upstream/README.md).

For workers that may run on different hosts, initialize the PostgreSQL profile once
with a privileged bootstrap identity, then run compilers and Action workers with an
environment-injected DSN and narrower runtime privileges. The explicit registration
shown here is the manual import/repair path:

```bash
uv sync --extra actions --extra datahub --extra postgres
export GLASSBOX_STATE_POSTGRES_DSN='postgresql://...'
export GLASSBOX_SIGNER_TRUST_POLICY_PATH=/etc/glassbox/trusted-signers.json
uv run glassbox-invalidation-state postgres-init \
  --dsn-env GLASSBOX_STATE_POSTGRES_DSN \
  --schema glassbox
uv run glassbox-invalidation-state postgres-register-receipt receipt.json \
  --dsn-env GLASSBOX_STATE_POSTGRES_DSN \
  --schema glassbox \
  --field-coverage COMPLETE \
  --field-rule glassbox.sql-column-lineage.v1 \
  --wildcard-query false
```

The DSN value is never placed in Actions configuration or status output. See the
[PostgreSQL pipeline example](examples/datahub-actions-invalidation-postgres.yml),
[ADR-0010](docs/adr/0010-postgresql-multi-worker-invalidation-state.md), and the
sanitized [PostgreSQL 16 trusted-signer proof report](docs/compatibility/postgresql-16-trusted-signer-state.live.json).
That proof establishes real server, multi-connection coordination; it deliberately
does not claim a physical multi-host deployment, managed failover, or network-partition
recovery.

The combined
[trusted receipt publication report](docs/compatibility/datahub-1.6.0-postgresql-trusted-receipt-pipeline.live.json)
proves current-time signer admission, checksummed PostgreSQL admission evidence, two
real DataHub upserts plus direct aspect readback, and completed redelivery with zero
additional DataHub writes.

Run the live OTLP receiver after bootstrapping the PostgreSQL state schema. Inject a
base64url-encoded 32-byte Ed25519 private key and receiver bearer token through your
secret manager; never place either value on the command line:

```bash
export GLASSBOX_STATE_POSTGRES_DSN='postgresql://...'
export GLASSBOX_RECEIPT_SIGNING_KEY='...'
export GLASSBOX_OTLP_BEARER_TOKEN='...'
export GLASSBOX_SIGNER_TRUST_POLICY_PATH=/etc/glassbox/trusted-signers.json
export DATAHUB_GMS_TOKEN='...'
uv run glassbox-otlp-receiver serve \
  --signing-key-id glassbox-prod-2026-08 \
  --environment PROD \
  --output-kind agent-decision \
  --output-mime-type application/json
```

Exporters send OTLP protobuf JSON to `POST /v1/traces` with
`Authorization: Bearer …`. HTTP 200 means the signed receipt, dependency index, and
publication obligation exist and DataHub direct-read evidence has been sealed. A
503 means the sender should retry; the durable obligation can also be repaired after
the sender disappears:

```bash
uv run glassbox-otlp-receiver drain --limit 100
```

Completed redelivery performs a fresh DataHub readback with zero writes. The
reference server is single-flight and expects TLS termination and rate limiting in a
production proxy. Non-loopback binds require bearer authentication unless the
operator supplies the explicit unsafe override. See
[ADR-0016](docs/adr/0016-durable-receipt-publication-and-otlp-acknowledgement.md) and
the combined
[DataHub/PostgreSQL/HTTP live report](docs/compatibility/datahub-1.6.0-postgresql-otlp-receiver.live.json).

The newer
[trusted OTLP live report](docs/compatibility/datahub-1.6.0-postgresql-trusted-otlp-receiver.live.json)
also proves that the receiver signer passed the active policy gate before binding,
that PostgreSQL verified its sealed admission evidence, and that authenticated 200
redelivery performed fresh DataHub reads with zero writes.

Trusted-signer admission evidence uses SQLite schema version 4 and PostgreSQL schema
version 3. Runtime processes do not perform implicit migration. The explicit
[state-transfer runbook](docs/operations/state-transfer.md) exports only from a
runtime that understands the source schema, independently verifies migration and
receipt authority, and atomically activates receipts under the destination's current
trust policy. Unsupported pre-policy schemas still require the last compatible
exporter or deliberate rebuild; changing a schema-version marker is never safe.

Build and inspect a complete read-only replay plan without calling any tool or
external service:

```bash
uv run python -m examples.replay_dry_run
```

The report commits the exact bundle and action set while asserting zero external
calls and history mutations. See the [replay contract](docs/replay.md),
[Replay Bundle 0.1 integrity profile](schemas/replay-bundle/0.1.0/README.md), and
[ADR-0011](docs/adr/0011-content-addressed-replay-and-approval-binding.md).

Execute the complete offline read-only chain and produce a new signed receipt, a
raw-free diff, and a history-preserving supersession record:

```bash
uv run python -m examples.replay_read_only
```

The in-process capability boundary is intentionally not described as an OS sandbox;
see [ADR-0012](docs/adr/0012-capability-scoped-read-only-replay-and-supersession.md).

Run the guarded live DataHub Core proof:

```bash
uv run python -m examples.end_to_end_replay_supersession --allow-live
```

The sanitized [live evidence report](docs/compatibility/datahub-1.6.0-replay-supersession.live.json)
records exact double-write/readback and unchanged before/after hashes for both receipt
Documents.

Run the same live boundary with the versioned pricing semantic policy:

```bash
uv run python -m examples.end_to_end_replay_supersession \
  --pricing-semantic-policy \
  --allow-live
```

The [semantic-policy evidence](docs/compatibility/datahub-1.6.0-semantic-policy.live.json)
records a real structural price change as policy-proven `EQUIVALENT` while retaining
`exact_match=false`, verifies all 19 DataHub relation properties, stores no compared
values, and leaves both receipt Documents unchanged. Exact equality is still the
default; domain policy use requires the exact content ID in an operator-trusted
registry. See [ADR-0023](docs/adr/0023-content-addressed-domain-semantic-policies.md).

Run the guarded one-command causal flagship against initialized PostgreSQL state and
local DataHub Core:

```bash
export GLASSBOX_STATE_POSTGRES_DSN='postgresql://...'
uv run python -m scripts.build_replay_sandbox
# Copy the printed image_digest into this environment variable.
export GLASSBOX_REPLAY_SANDBOX_IMAGE='sha256:...'
uv run python -m examples.end_to_end_flagship \
  --server http://localhost:8080 \
  --sandbox-image-digest "$GLASSBOX_REPLAY_SANDBOX_IMAGE" \
  --allow-live
```

This is one connected chain, not a replay fixture: the exact receipt quarantined by
the live Action becomes the source of a fingerprint-authorized corrected bundle;
the corrected evidence digest replaces the affected action input; the new decision
changes inside a source/schema-bound hardened container; and DataHub directly reads
back both receipts plus their immutable supersession relation before resolving the
exact incident. The command proves the receipt Documents did not change, runs the
unrelated-field zero-write control, and cross-checks the incident through official
DataHub MCP and GlassBox MCP. See
[ADR-0020](docs/adr/0020-signed-invalidation-to-recovery-handoff.md),
[ADR-0021](docs/adr/0021-oci-isolated-replay-and-verified-incident-closure.md), and the
[raw-free live report](docs/compatibility/datahub-1.6.0-flagship-causal-recovery.live.json).
[ADR-0022](docs/adr/0022-postgresql-durable-recovery-orchestration.md) defines the
new durable coordinator. The guarded crash proof then runs that causal chain through
four fresh checkpoint workers plus one closed-redelivery worker; every process exits
abruptly with the configured fault code after PostgreSQL readback. The committed
[raw-free crash report](docs/compatibility/datahub-1.6.0-durable-recovery-crash.live.json)
proves ordered restart recovery, real OCI isolation, DataHub direct readback, exact
zero-write closure reuse, and unchanged source and receipt history.

The complementary
[uncertain-completion crash report](docs/compatibility/datahub-1.6.0-durable-recovery-uncertain-crash.live.json)
injects process death after each successful OCI or DataHub operation but before its
PostgreSQL completion call. Four fresh workers recover only after the server-clock
lease expires, and a ninth proves closed redelivery. The report distinguishes
historical emission evidence from physical writes on the retry: replay-receipt and
exact-closure retries perform zero writes, while immutable supersession safely
repeats its verified double-write.

Install the forensic skill in an Agent Skills-compatible project:

```bash
mkdir -p .agents/skills
cp -R skills/datahub-agent-forensics .agents/skills/
```

Then ask: `Use $datahub-agent-forensics to explain why this agent decision is
stale.` The skill composes with DataHub Search, Lineage, and Quality for discovery,
but keeps integrity and impact decisions deterministic. See the
[skill contribution guide](docs/datahub-agent-forensics-skill.md).

Run the decision-evidence MCP companion over stdio against the same PostgreSQL
schema as the DataHub Action:

```bash
uv sync --extra mcp --extra postgres
export GLASSBOX_STATE_POSTGRES_DSN='postgresql://...'
export GLASSBOX_SIGNER_TRUST_POLICY_PATH=/etc/glassbox/trusted-signers.json
uv run glassbox-forensics-mcp \
  --state-postgres-dsn-env GLASSBOX_STATE_POSTGRES_DSN \
  --state-postgres-schema glassbox \
  --signer-trust-policy "$GLASSBOX_SIGNER_TRUST_POLICY_PATH"
```

It complements DataHub's official MCP server: DataHub owns catalog discovery and
generic lineage, while GlassBox owns signed run-specific decision evidence. All six
tools are read-only. Prospective classifications remain visibly separate from
campaigns actually persisted and writeback-verified by the Action. There is no
quarantine, approval, replay-execution, resolution, or supersession tool. See the
[MCP contract](docs/forensics-mcp.md),
[ADR-0013](docs/adr/0013-read-only-forensics-mcp.md), and
[ADR-0014](docs/adr/0014-shared-live-decision-state.md). Signer authority and key
rotation are defined by
[ADR-0017](docs/adr/0017-operator-trusted-receipt-signers-and-rotation.md).

This boundary is now live-proven, not fixture-replayed. The guarded
[dual-MCP evidence report](docs/compatibility/datahub-1.6.0-dual-mcp-forensics.live.json)
runs the official DataHub MCP server `0.6.0` beside GlassBox MCP against one real
Action-completed incident on Core `v1.6.0` with PostgreSQL-backed state. It
cross-binds the catalog dataset, exact field type, incident health, receipt,
observed influence, `STALE` finding, quarantine, completed campaign, and verified
DataHub writeback. It also records the measured official-server limitation that the
exact Incident entity body was unavailable through `get_entities`; no missing
evidence is fabricated.

For audit or CI, bind natural-language answers to that proof with the installable
claim-ledger evaluator:

```bash
glassbox-agent-narration brief dual-mcp-evidence.json --pretty
glassbox-agent-narration evaluate dual-mcp-evidence.json agent-response.json --pretty
```

The committed
[agent narration evaluation](docs/compatibility/datahub-1.6.0-dual-mcp-agent-narration.eval.json)
records both an ordinary independent agent run and a pressure case demanding
invented Incident details, global scope, and mutation authority. Both preserved all
18 evidence facts and required limitations. Free-prose review remains visibly
model-based rather than being promoted to deterministic proof; see
[ADR-0019](docs/adr/0019-machine-auditable-agent-narration.md).

Read the proposed native model in
[Agent decision receipts and runtime influence](docs/rfcs/000-agent-decision-receipts-and-runtime-influence.md).
The draft directly extends DataHub Agent Registry RFC #16012 and is explicitly not
claimed as submitted or accepted.

Run its guarded live Core proof:

```bash
uv run python -m examples.end_to_end_forensics_skill --allow-live
```

The sanitized [forensics evidence report](docs/compatibility/datahub-1.6.0-agent-forensics.live.json)
records the official CLI direct read, verified signed artifact, projection-only
boundary, and used-field/unrelated-field policy controls.

Open the local forensic console:

```bash
cd apps/console
npm install
npm run dev
```

The console's default investigation is backed by the same guarded Core proof and
includes a material `revenue` change plus an `internal_note` negative control. Its
own build, rendered-content tests, lint, and strict type-check commands are documented
in [`apps/console/README.md`](apps/console/README.md). It is not described as hosted
until a separate public deployment is explicitly performed.

Production owner routing is optional and requires an HTTPS receiver that honors the
campaign `Idempotency-Key`; see the
[invalidation action contract](docs/invalidation-action.md). Webhook acceptance is
not presented as proof that a human read the notification.

Install only the framework adapter you need:

```bash
uv sync --extra langchain
uv sync --extra google-adk
uv sync --extra mcp
uv sync --extra actions --extra datahub
uv sync --extra actions --extra datahub --extra postgres
```

Instrument a minimal run:

```python
from glassbox import ActionEffect, EvidenceRole, EvidenceState, GlassBox

runtime = GlassBox()

@runtime.consequential(agent_id="pricing-agent", workflow_id="recommend-price")
def recommend_price(customer_id: str) -> dict[str, int]:
    runtime.observe_evidence(
        entity_type="dataset",
        datahub_urn="urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)",
        state=EvidenceState.OBSERVED,
        role=EvidenceRole.INPUT,
        representation={"customer_id": customer_id},
    )
    return runtime.call_tool(
        "pricing.lookup",
        lambda: {"recommended_price": 42},
        effect=ActionEffect.READ_ONLY,
    )
```

Arguments, results, and evidence representations are committed by digest; they are
not retained in runtime events. See the
[`runtime instrumentation contract`](docs/runtime-instrumentation.md) for correlation,
redaction, callback, and action-policy semantics.

## Trust model

- Evidence is always `OBSERVED`, `DECLARED`, `INFERRED`, or `UNKNOWN`.
- Raw high-cardinality traces remain outside DataHub.
- Receipts are append-only; replays create new receipts.
- A signature proves integrity and key possession, not operator trust or factual
  truth. Production admission also requires an operator policy bound to the key ID
  and public-key fingerprint.
- Unknown-effect and irreversible actions are never automatically replayed.

See [`AGENTS.md`](AGENTS.md) for binding engineering rules and
[`SECURITY.md`](SECURITY.md) for vulnerability reporting and data-handling rules.
See the [signer rotation runbook](docs/operations/signing-key-rotation.md) for
enrollment, overlap, retirement, revocation, and rollback.

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
