# Durable recovery orchestration runbook

## Purpose

This runbook operates the PostgreSQL-backed workflow that resumes one separately
authorized corrected replay after process failure. It does not choose corrected
evidence, issue authorization, bypass replay policy, store raw artifacts, or make an
irreversible action replayable.

The state authority is the same PostgreSQL schema used by the invalidation Action.
Recovery tables have their own version and foreign-key the exact completed campaign
and source receipt. DataHub remains the governed projection; PostgreSQL remains the
operational checkpoint authority.

## Trust and data boundary

Before staging, the store directly reads the source receipt and completed campaign
from invalidation state and verifies the signed authorization against a configured
key fingerprint. Before execution, the worker repeats that verification with the
current time. The OCI executor and DataHub adapters keep their existing independent
trust checks.

PostgreSQL retains:

- authorization and corrected-bundle commitments;
- the raw-free execution, replay DBOM, diff, supersession, and closure artifact set;
- direct-readback evidence for each DataHub effect, including whether that attempt
  physically wrote;
- replay receipt, supersession, closure, campaign, and source receipt IDs; and
- an append-only checkpoint event ledger.

It does not retain resolved corrected input values, transient capability outputs,
prompts, credentials, private keys, DataHub response bodies, or exception messages.

## Bootstrap and runtime roles

Initialize the invalidation schema first. Then create recovery schema version 2
once with a bootstrap role:

```python
import os

from glassbox_invalidation.postgres_store import PostgresInvalidationStore
from glassbox_replay.postgres_recovery import PostgresRecoveryStore

dsn = os.environ["GLASSBOX_STATE_POSTGRES_DSN"]
invalidation = PostgresInvalidationStore(dsn, schema="glassbox")
PostgresRecoveryStore(dsn, invalidation, schema="glassbox")
```

Runtime workers must reopen both stores with schema initialization disabled. Their
database identity needs `SELECT`, `INSERT`, and `UPDATE` on the recovery tables and
sequence use for the event identity. It does not need `CREATE`, `ALTER`, or `DROP`.
Use a separate read-only identity for forensic inspection.

Never put the DSN in command output, DataHub custom properties, audit events, or a
committed configuration. Load it through the named environment variable.

Recovery schema v2 stores the versioned `glassbox.recovery-artifacts.v2` envelope,
which adds complete semantic-policy evidence to the replay diff and supersession.
Runtime workers reject recovery schema v1 because its persisted artifact bytes do
not carry that contract. This pre-release repository provides no in-place migration:
preserve any required v1 forensic export, create v2 through the bootstrap path, and
restage only through a new authorization. Never change the metadata marker by hand.

## Expected state sequence

| Durable stage | Next leased operation | Required completion evidence |
|---|---|---|
| `AUTHORIZED` | `EXECUTE_ISOLATED_REPLAY` | One valid `RecoveryArtifacts` set |
| `ISOLATED_EXECUTION_SUCCEEDED` | `PUBLISH_REPLAY_RECEIPT` | State registration plus DataHub direct readback |
| `REPLAY_RECEIPT_PUBLISHED` | `PUBLISH_SUPERSESSION` | Exact managed properties plus DataHub direct readback |
| `SUPERSESSION_VERIFIED` | `CLOSE_INCIDENT` | Exact resolution, target summary, supersession, and unchanged receipt hashes |
| `INCIDENT_CLOSED` | None | Closed workflow and complete event sequence |

`attempt_count` counts claims, not successful executions. An active claim is
represented by `lease_operation`, `lease_owner`, and a server-clock expiry.

## Failure response

### Worker died before artifact-set commit

Wait for the database-clock lease to expire. A new worker may claim the exact
workflow. The capability is read-only and uses the stable workflow ID as its logical
idempotency identity. It may physically run again because no transaction spans the
container and PostgreSQL. Compare the resulting content addresses; do not label the
physical invocation exactly once.

### Worker died after artifact-set commit

Restart normally. The next claim is replay-receipt publication; isolated execution
must not run again. If the stored artifact set fails verification, quarantine the
worker and investigate storage corruption rather than rebuilding history in place.

### DataHub effect may have succeeded

Do not clear a live lease manually. After expiry, retry the same deterministic
effect. Receipt and supersession publication are idempotent and directly verified.
Closure recognizes only the exact prior closure ID and can seal it with zero writes.
Inspect `write_performed` separately from `emission_count`: a completed receipt
outbox returns its historical emission evidence while the retry itself writes
nothing. A different resolution is a conflict requiring operator investigation.

### Workflow never progresses

Read the raw-free `RecoveryJob.to_dict()` projection and the checkpoint events.
Check, in order:

1. the linked campaign is still `COMPLETED`;
2. the authorization has not expired or been revoked;
3. the lease is expired according to PostgreSQL, not a worker clock;
4. the exact OCI image and tool labels remain available;
5. replay receipt publication has a durable outbox row;
6. DataHub direct reads return the expected receipt and supersession Documents; and
7. incident resolution belongs to the same closure ID.

Do not update stages, IDs, checksums, or event rows by hand. Restage only through a
new explicitly designed authorization lifecycle; the current version intentionally
permits one recovery workflow per campaign.

## Verification

Run the deterministic and real database suites:

```bash
uv run pytest -q \
  tests/unit/test_recovery_orchestration.py \
  tests/unit/test_recovery_datahub_effects.py \
  tests/unit/test_recovery_closure.py

GLASSBOX_TEST_POSTGRES_DSN='postgresql://...' \
uv run pytest -q tests/integration/test_postgres_recovery.py

GLASSBOX_STATE_POSTGRES_DSN='postgresql://...' \
uv run python -m examples.end_to_end_durable_recovery run \
  --server http://localhost:8080 \
  --sandbox-image-digest 'sha256:...' \
  --allow-live

GLASSBOX_STATE_POSTGRES_DSN='postgresql://...' \
uv run python -m examples.end_to_end_durable_recovery run-uncertain \
  --server http://localhost:8080 \
  --sandbox-image-digest 'sha256:...' \
  --fault-lease-duration-ms 1000 \
  --allow-live
```

The integration suite creates a randomized schema, races eight independent
connections, tests server-clock takeover, reopens in runtime mode, completes every
checkpoint, verifies the event ledger, and drops only that randomized schema.

## Known limits

- PostgreSQL failover, network partitions, backup restore, online schema migration,
  transaction-pooler modes, and physical multi-host deployment are not live-proven.
- The pre-artifact-commit read-only execution window is at least once physically.
- Recovery artifacts can carry an explicitly trusted Semantic Policy 0.1
  assessment. Exact equality remains the default; current domain support is limited
  to numeric tolerance and unordered-collection multiset rules with complete change
  coverage.
- Abrupt fresh-process recovery after every committed checkpoint and after every
  successful OCI/DataHub operation whose PostgreSQL completion is deliberately
  skipped is live-proven on one host. This does not prove host loss or database
  promotion.
