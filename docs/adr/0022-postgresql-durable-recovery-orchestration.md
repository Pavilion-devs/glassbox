# ADR-0022: Persist authorized recovery as a leased PostgreSQL state machine

- **Status:** Accepted
- **Date:** 2026-08-08
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0010](0010-postgresql-multi-worker-invalidation-state.md),
  [ADR-0020](0020-signed-invalidation-to-recovery-handoff.md), and
  [ADR-0021](0021-oci-isolated-replay-and-verified-incident-closure.md)

## Context

The causal flagship proved completed invalidation, signed recovery authorization,
isolated corrected execution, replay-receipt publication, supersession, and incident
closure in one process. Those domain and DataHub contracts were real, but process
memory still connected the stages. A worker crash after execution or a remote write
could force an operator to reconstruct which artifacts existed and which effect was
safe to resume.

PostgreSQL, the OCI runtime, and DataHub do not share one transaction. Recovery
therefore needs explicit checkpoints, leases, raw-free durable artifacts, and
idempotent remote effects. It must not claim that a physical container invocation is
exactly once across the unavoidable boundary between child completion and the
PostgreSQL commit.

## Decision

- Add a separately versioned PostgreSQL recovery extension inside the same schema
  authority as invalidation state. `recovery_jobs` references the exact completed
  `campaign_outbox` row and source `receipt_records` row through foreign keys; it
  does not rewrite either record.
- Keep recovery schema version 1 in `recovery_state_metadata`. Bootstrap is an
  explicit operator action. Runtime workers open with `initialize_schema=False` and
  issue no DDL. No implicit migration is provided.
- Persist these ordered checkpoints:
  `AUTHORIZED`, `ISOLATED_EXECUTION_SUCCEEDED`,
  `REPLAY_RECEIPT_PUBLISHED`, `SUPERSESSION_VERIFIED`, and `INCIDENT_CLOSED`.
  An active lease exposes the corresponding claimed workflow state without
  pretending that the checkpoint is complete.
- Lock the exact workflow row with `SELECT ... FOR UPDATE`. Use PostgreSQL
  `clock_timestamp()` for lease acquisition, renewal, and expiry so worker clock
  skew cannot steal live work.
- Re-verify the signed authorization against the current completed campaign,
  source receipt, corrected bundle, expiry, revocation state, and trusted signer
  fingerprint immediately before execution.
- After isolated execution, build the replay receipt, raw-free diff, supersession,
  and closure record while transient outputs are still available. Atomically store
  their content-addressed, raw-free projections as one `RecoveryArtifacts` set
  before any DataHub publication stage begins.
- Store replay receipt, supersession, and closure IDs natively on the recovery row.
  This is the durable source-to-successor recovery relation. The immutable source
  receipt index entry is not edited and its legacy `superseded_by` field is not
  retrofitted.
- Use the existing durable receipt-publication pipeline for the replay DBOM, the
  verified supersession emitter for the relation Document, and the verified closure
  emitter for the exact incident. Persist a content-addressed direct-readback
  evidence object after each effect. The evidence records both the verified emission
  count and whether that attempt physically wrote, so historical outbox evidence is
  not mistaken for a retry write.
- If a remote operation fails while ownership is known, release the lease with only
  its exception type. If the remote operation succeeded but the PostgreSQL
  completion outcome is uncertain, keep the lease until expiry before takeover.
- Permit exact prior incident closure to recover with zero writes. Fresh readback
  must prove the same closure ID, `RESOLVED/FIXED`, resolved target summary,
  supersession, both receipt Documents, and unchanged receipt hashes. A different
  resolution still fails closed.
- Record every committed checkpoint in an append-only, checksummed recovery event
  ledger. Integrity verification reconstructs every job and artifact, checks the
  event sequence, and requires the linked invalidation campaign to remain
  `COMPLETED`.
- Describe the execution guarantee precisely: one content-addressed logical
  recovery result and idempotent at-least-once effects. A read-only OCI capability
  may physically execute again if the parent dies after child completion but before
  the artifact-set commit. The stable workflow ID is the execution idempotency key,
  and irreversible or unknown-effect work remains ineligible.

## Crash semantics

| Failure point | Durable state | Recovery |
|---|---|---|
| Before authorization commit | No recovery job | Operator or approval service restages the exact authorization |
| After authorization, before execution claim | `AUTHORIZED` | Any worker may claim |
| After child completion, before artifact commit | Expiring execution lease | A worker may repeat only the read-only deterministic capability and must produce the same logical artifacts |
| After artifact commit | `ISOLATED_EXECUTION_SUCCEEDED` | Restart skips execution and begins replay publication |
| After a DataHub effect, before checkpoint commit | Prior checkpoint plus expiring effect lease | Retry the deterministic effect after expiry and seal direct-readback evidence |
| After exact incident resolution, before checkpoint commit | `SUPERSESSION_VERIFIED` plus closure lease | Detect the same closure through read-only verification and record `INCIDENT_CLOSED` with zero writes |
| After `INCIDENT_CLOSED` | Closed workflow and five audit events | Redelivery reuses the closed state and performs no orchestration mutation |

## Evidence

Unit tests use the actual signed authorization, isolated-execution projection,
signed replay DBOM, diff, supersession, and closure types. They prove artifact
round trips exclude transient output values, restart after artifact commit does not
execute again, uncertain effect completion waits for lease expiry, authorization is
freshly rechecked, and malformed or cross-bound artifacts fail closed.

The real PostgreSQL 16 integration suite proves one winner across eight independent
connections, server-clock lease recovery, runtime reopen without DDL, all five
ordered checkpoints, idempotent uncertain-completion sealing, persisted replay,
supersession, and closure IDs, source receipt preservation, event-ledger integrity,
and refusal on checksum corruption, incomplete history, wrong ownership, wrong
artifact identity, missing bootstrap, and schema-version drift.

The guarded combined proof then staged one real completed `STALE` campaign and
signed authorization in PostgreSQL 16.14, executed the exact digest-pinned OCI
capability, and advanced receipt publication, supersession, and incident closure
against DataHub Core 1.6.0. Each checkpoint ran in a distinct worker process that
terminated through an abrupt interpreter exit after durable readback. A fifth fresh
process reused `INCIDENT_CLOSED` without claiming work, and exact closure recovery
performed zero writes. Five checksummed events remained, both receipt Documents and
the PostgreSQL source receipt were unchanged, and no raw value or credential entered
the report. The evidence is
[`datahub-1.6.0-durable-recovery-crash.live.json`](../compatibility/datahub-1.6.0-durable-recovery-crash.live.json).

A complementary guarded campaign exercised the uncertain side of every distributed
boundary. For each ordered operation, one fresh process completed and directly
verified the real OCI/DataHub work, emitted a bounded raw-free marker, and terminated
through `os._exit(87)` before calling PostgreSQL completion. The parent proved the
prior stage and event count remained durable while the lease was active, waited for
server-clock expiry, and launched another process to recover. The execution produced
the identical artifact-set ID; replay-receipt retry reused its completed inner
publication outbox with zero physical writes; immutable supersession repeated its
two verified writes; exact closure retry used zero writes. Nine distinct processes,
eight claims, five events, unchanged source/receipt history, and closed redelivery
all verified against PostgreSQL 16.14, DataHub Core 1.6.0, and the digest-pinned OCI
image. The raw-free evidence is
[`datahub-1.6.0-durable-recovery-uncertain-crash.live.json`](../compatibility/datahub-1.6.0-durable-recovery-uncertain-crash.live.json).

## Alternatives considered

- Keep orchestration in process memory: rejected because a restart loses the only
  account of completed execution and pending effects.
- Put raw corrected inputs or outputs in PostgreSQL: rejected because the durable
  recovery contract needs commitments and governed artifacts, not a second payload
  store.
- Mark the source receipt's indexed profile as superseded in place: rejected because
  it changes immutable admission material and conflates authorization, execution,
  and verified publication.
- Use one transaction across PostgreSQL, Docker, and DataHub: unavailable and
  therefore not claimed.
- Re-execute after every restart: rejected after the artifact-set checkpoint; only
  the pre-commit execution crash window may repeat a read-only capability.
- Treat any resolved incident as completion: rejected because another operator or
  closure may have resolved it for a different reason.

## Consequences and limits

Recovery workers can now resume safely from durable state and forensic services can
read native successor and closure identities without scraping DataHub Documents.
The extra PostgreSQL tables and leases add an operator bootstrap and monitoring
surface. The current adapter uses short-lived connections and assumes one
PostgreSQL authority; managed failover, partitions, online migration, and transaction
poolers remain deployment responsibilities.

The coordinator does not create raw artifact storage, choose corrected values,
grant authorization, or weaken replay policy. Domain-specific semantic equivalence
beyond exact output comparison remains separate work. Both the committed-checkpoint
restart path and process death after successful child/DataHub work but before the
corresponding PostgreSQL completion call are live-proven on one host. Physical
multi-host failover, network partitions, and managed PostgreSQL promotion remain
unexercised deployment boundaries.

## Reversal conditions

Replace the PostgreSQL extension if DataHub adopts a native recovery workflow with
equivalent immutable authorization binding, leases, raw-free artifacts, ordered
direct-readback evidence, append-only events, and exact closure recovery. Replace
the at-least-once execution boundary only if a future sandbox can durably commit its
result to the same authority before acknowledging completion without gaining
forbidden ambient credentials or network access.
