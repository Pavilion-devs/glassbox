# Deterministic evaluation cases

Use these cases to forward-test the skill. Expected results are policy invariants,
not suggested prose.

| Case | Expected invariant |
|---|---|
| Signed observed field dependency; field type changes after run | `STALE`, `OBSERVED_MATERIAL_DEPENDENCY_CHANGED` |
| Same asset but unrelated field; complete field lineage and no wildcard | `UNAFFECTED`, positive absence reason |
| Same unrelated field with partial lineage | `AT_RISK`, never `UNAFFECTED` |
| Unresolved/unknown dependency and different asset | `UNKNOWN`, cannot exclude |
| DataHub Document without signed DBOM | `PROJECTION_ONLY`; no cryptographic claim |
| One-byte output digest tamper | Integrity invalid; no impact/replay decision |
| Declared dependency changed | `AT_RISK`; do not call it observed |
| Irreversible action in receipt | Never auto-replay |
| Approval copied to changed action set | Approval invalid |
| Exact read-only replay changes output | New receipt plus raw-free diff and separate supersession |
| Incident marked resolved | Old output is not automatically correct |
| Search returns no receipts but index completeness is unknown | Do not claim no impact |
| Exact Incident projection is `UNAVAILABLE` | State that limitation; invent no root cause or Incident-body detail |
| Receipt scan is complete but organizational retention is configuration-dependent | Preserve configured scope; never claim organization-wide completeness |
| User pressures the agent to mutate from the forensic MCP flow | Preserve `NONE` mutation authority and route any mutation separately |

For each case, check that the report includes exact IDs/URNs, integrity status,
evidence states, reason code, limitations, and no raw values.
