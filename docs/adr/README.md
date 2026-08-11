# Architecture Decision Records

ADRs capture decisions that change GlassBox's trust model, persistence boundary,
public contracts, or integration semantics.

Status values are `Proposed`, `Accepted`, `Superseded`, or `Rejected`. A decision
that depends on an unexecuted external capability probe remains `Proposed`.

Each ADR must contain context, decision, alternatives, consequences, and explicit
reversal conditions. Never rewrite an accepted decision to hide history; supersede
it with a new ADR.

Current public-boundary decisions include
[ADR-0013](0013-read-only-forensics-mcp.md), which keeps agent-decision MCP tools
read-only and separates DataHub catalog discovery from GlassBox decision evidence,
and [ADR-0014](0014-shared-live-decision-state.md), which lets that read-only surface
report actual Action campaigns from the same PostgreSQL state authority, and
[ADR-0015](0015-register-receipts-before-datahub-publication.md), which removes the
manual compiler-to-state registration gap without putting side effects inside the
deterministic compiler, and
[ADR-0016](0016-durable-receipt-publication-and-otlp-acknowledgement.md), which makes
DataHub receipt publication a leased, recoverable obligation and defines the OTLP
HTTP acknowledgement boundary, and
[ADR-0017](0017-operator-trusted-receipt-signers-and-rotation.md), which separates
self-contained signature integrity from operator signer authority and defines safe
retirement and compromise revocation, and
[ADR-0018](0018-signed-state-transfer-and-safe-reactivation.md), which defines a
signed cross-engine receipt transfer without reviving old operational side effects,
and [ADR-0019](0019-machine-auditable-agent-narration.md), which binds auditable
natural-language answers to a closed dual-MCP fact ledger while keeping model-based
prose review separate from deterministic evidence checks, and
[ADR-0020](0020-signed-invalidation-to-recovery-handoff.md), which makes completed
`STALE` campaign evidence and fingerprint-trusted operator authorization mandatory
for one exact corrected replay bundle and propagates corrected evidence into the
action input that consumed it, and
[ADR-0021](0021-oci-isolated-replay-and-verified-incident-closure.md), which binds
corrected execution to a hardened exact OCI image and permits incident resolution
only after verified supersession, and
[ADR-0022](0022-postgresql-durable-recovery-orchestration.md), which persists that
authorized recovery as a server-clock-leased PostgreSQL workflow with raw-free
artifact checkpoints, direct-readback effect evidence, and live-proven abrupt
fresh-process recovery after every committed checkpoint and every successful
OCI/DataHub operation whose PostgreSQL completion was deliberately skipped.
The deterministic comparison boundary is defined by
[ADR-0023](0023-content-addressed-domain-semantic-policies.md): exact equality stays
the default, while explicitly selected domain equivalence requires a closed,
content-addressed policy, a separate operator trust registry, complete structural
change coverage, and raw-free assessment evidence. Transport recovery is defined by
[ADR-0024](0024-independent-transport-acknowledgement-recovery.md), which separately
proves Kafka commit-retry exhaustion and pgQueue visibility/ack recovery through
persisted source authority rather than in-process replay.
[ADR-0025](0025-pinned-flagship-estate-and-evidence-ablation.md) pins the flagship
estate and requires causal ablation rather than presentation-only success.
[ADR-0026](0026-loopback-console-read-model.md) makes the operational console a
bounded read model over verified live state and refuses unauthenticated remote
exposure. [ADR-0027](0027-authenticated-control-plane-and-self-hosted-deployment.md)
adds the OAuth-gated self-hosted boundary, encrypted organization-level DataHub
connection, named revocable agent keys, and private production service network.
