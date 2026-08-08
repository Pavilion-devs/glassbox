# DataHub pgQueue live integration-test packet

**Target:** `datahub-project/datahub`
**Prepared baseline:** `f4fda77cfaa92456c89d1597f271de9366ef38f6` on
2026-08-08
**Prepared branch:** `codex/pgqueue-live-integration`
**Published commit:** `b1f3f458c78e97220b165fca3555aee2a64f2eaa`
**Pull request (ready for review):**
[`datahub-project/datahub#19004`](https://github.com/datahub-project/datahub/pull/19004)
**Title:** `test(pgqueue): add live PostgreSQL lease recovery coverage`

This domain-neutral DataHub Core contribution was committed on the
`Pavilion-devs/datahub` fork, opened as draft pull request #19004, and marked ready
for review after its executable CI matrix passed. It does not claim maintainer
approval or an upstream merge. GitHub reports the branch mergeable; DataHub created
internal tracking ticket `ING-3229`, and it has not yet assigned a core reviewer.
Two automated review findings were fixed in `b1f3f45`: the live fixture now installs
the retention-function migration and uses a dynamically published PostgreSQL port.
Both review threads are resolved and Cubic's follow-up review passed. The dedicated
pgQueue job, Python lint, build, performance suite, Python 3.10–3.12 quick tests,
plugin-dependency validation, integration gate, and Vercel deployment have all
passed on the updated head. The external `Mergeable` policy is still recalculating;
maintainer review remains required.

## Summary

Replace the skipped Python pgQueue integration placeholder with a real PostgreSQL
test using DataHub's extension-enabled Postgres image, all three authoritative
SqlSetup migrations, `pg_partman`, and the public `PgQueueRepository` behavior.

The test proves one high-value delivery invariant end to end:

1. a producer enqueues a message through `PgQueueRepository`;
2. the public `apply_topic_retention()` path executes the installed server-side
   retention function without deleting the per-partition sequence anchor;
3. a first worker leases the message and then loses its connection without
   acknowledging;
4. a second worker cannot receive the message while the lease is live;
5. after deterministic lease expiry, that worker receives the exact same handle and
   payload;
6. the committed offset remains unchanged before acknowledgement;
7. acknowledgement advances the offset exactly once;
8. a third worker sees an empty queue; and
9. the message table has real `pg_partman` child partitions.

This is not a replay fixture and does not hard-code a successful queue response. All
queue state is created, leased, expired, redelivered, acknowledged, and queried in a
temporary real database during the test.

## Why this belongs upstream

The existing Java `PgQueueSqlMigrationModuleIT` covers the migration runner. The
Python test covers a different boundary: whether the repository's producer and
consumer-group operations obey their delivery contract against the actual schema
and extension configuration. It converts a checked-in skipped placeholder into
portable regression coverage for every DataHub workflow that uses pgQueue.

The contribution contains no GlassBox package, policy, receipt, or product concept.
The synthetic routing key uses the `test` data platform, and the only changed paths
are the existing pgQueue integration-test directory.

## Overlap review

Issues and pull requests were searched before implementation on 2026-08-08. No open
change was found that replaces the skipped live Python test. Draft pull request
[#18659](https://github.com/datahub-project/datahub/pull/18659) is adjacent—it adds
a topic-agnostic MCL producer—but does not exercise crash-style lease recovery,
redelivery, offset commitment, or `pg_partman` through the Python repository. The
prepared patch does not modify its producer surface.

## Changed files

- `metadata-ingestion/tests/integration/pgqueue/test_pgqueue_optional_it.py`
- `metadata-ingestion/tests/integration/pgqueue/docker-compose.yml`

The apply-ready patch is
`release-evidence/upstream/datahub-pgqueue-live-f4fda77.patch`. It is 10,369 bytes
with SHA-256
`e3964c8451f30ace43f8c15cf5380ccdce10f884b1f7a144068de5253eede8c6`.

## Verification completed

The final prepared files passed:

```text
ruff check                                              PASS
ruff format --check                                     PASS
mypy --show-traceback --show-error-codes                PASS
pytest tests/integration/pgqueue/test_pgqueue_optional_it.py
                                                        1 passed in 2.37s
Gradle testSingle with the prepared environment         BUILD SUCCESSFUL;
                                                        1 passed in 2.37s
DataHub pre-commit and pre-push hooks                    PASS
updated-head upstream pgQueue integration job           PASS in 3m09s
updated-head Python lint                                PASS
updated-head Cubic follow-up review                     PASS
updated-head plugin-dependency validation               PASS
updated-head Python 3.10 quick tests                    PASS
updated-head Python 3.11 quick tests                    PASS
updated-head Python 3.12 quick tests                    PASS
updated-head integration-tests-gate                     PASS
updated-head Vercel deployment                          PASS
updated-head external Mergeable policy                  IN PROGRESS
git diff --check                                        PASS
temporary Docker container after teardown               ABSENT
```

The live test was also run successfully before the final Gradle-wrapped run. The
last run reported two dependency deprecation warnings and no test warnings, skips,
failures, or errors.

DataHub's full Gradle `testSingle` entry point was attempted first. Its
`installDevTest` prerequisite expanded the complete 422-package connector test
matrix and exhausted this workstation's available disk before the test task could
finish. After recovering the disposable caches, the official `testSingle` task was
run successfully with `installDevTest` skipped and the already prepared focused
environment reused:

```bash
./gradlew :metadata-ingestion:testSingle \
  -PtestFile=tests/integration/pgqueue/test_pgqueue_optional_it.py \
  -x :metadata-ingestion:installDevTest
```

On the updated head, DataHub's dedicated
[`ci (pgqueue, tests/integration/pgqueue/, 3.11)`](https://github.com/datahub-project/datahub/actions/runs/31279343200/job/93158063389)
job passed in 3m09s, providing the authoritative clean-environment proof for both
review fixes. Python lint, the build, performance tests, Python 3.11 quick tests,
plugin-dependency validation, and Cubic's follow-up review also passed. The
follow-up commit `b1f3f45` passed the focused live test and all repository hooks
locally. Every completed updated-head check is green; only the external `Mergeable`
policy is still recalculating. The distinction remains recorded: the Gradle-owned focused
task passed locally, the complete local dependency setup did not finish because of
host disk exhaustion, and the previous head's wider metadata-ingestion quick-test
matrix and `integration-tests-gate` passed upstream.

## Submitted pull-request body

### What changed

Replace the skipped pgQueue integration placeholder with live repository coverage
against DataHub's extension-enabled PostgreSQL image and the authoritative pgQueue
SqlSetup migrations.

### What the test protects

- exclusive delivery while a visibility lease is active;
- redelivery of the exact unacknowledged message after lease expiry;
- no committed-offset advance before acknowledgement;
- one-step committed-offset advance after acknowledgement;
- no third delivery after the commit; and
- real partition creation through `pg_partman`.

### Boundary

This complements the Java migration-runner integration test. It does not introduce
a new queue API or alter pgQueue production behavior.

### Test plan

```bash
./gradlew :metadata-ingestion:testSingle \
  -PtestFile=tests/integration/pgqueue/test_pgqueue_optional_it.py
```

### Related work

Draft PR #18659 is adjacent producer work but does not overlap this repository-level
delivery and recovery test.
