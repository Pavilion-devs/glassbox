# DataHub 1.6.0 compatibility contract

**Last reviewed:** 2026-08-07
**Server target:** DataHub Core `v1.6.0`
**Python SDK:** `acryl-datahub==1.6.0.15`
**Actions SDK:** `acryl-datahub-actions==1.6.0.15`

This file separates three evidence levels:

- **DOCUMENTED:** supported by versioned primary documentation or tagged source.
- **PROVEN:** exercised twice against the pinned local Core instance and directly
  read back by URN.
- **UNVERIFIED:** plausible or documented elsewhere, but the GlassBox live probe has
  not produced evidence yet.

No capability is upgraded from `DOCUMENTED` to `PROVEN` by a unit test, a mock, a
successful HTTP status alone, search indexing, or a screenshot.

| Capability | Current evidence | Notes |
| --- | --- | --- |
| Dataset plus schema emission | PROVEN | Emitted twice to one deterministic URN; direct read returned dataset key and schema aspects. |
| ML model emission | PROVEN | Emitted twice to one deterministic URN; direct read returned model key and properties. |
| API/MCP tool entity | BLOCKED ON STABLE STACK | The stable SDK lacks the module. The exact `1.6.0.16rc3` preview SDK can construct it, but Core `v1.6.0` rejects entity type `api` as absent from its EntityRegistry. |
| Agent skill entity | BLOCKED ON STABLE STACK | The preview SDK contains the class and schema, but the prerequisite API entity is rejected by the pinned server. |
| AI agent entity and declared dataset lineage | BLOCKED ON STABLE STACK | The preview SDK contains the class and schema, but the stable server has not accepted the required Agent Registry entity graph. |
| API tool compatibility projection | PROVEN | Typed Document with explicit native type, canonical ID, compatibility reason, dataset reference, and deterministic URN emitted twice and read back. |
| Agent skill compatibility projection | PROVEN | Typed Document references the compatibility tool URN and never claims native `agentSkill` semantics. |
| AI agent compatibility projection | PROVEN | Typed Document references the dataset, model, tool projection, and skill projection through digest-safe custom properties. |
| Standalone agent-run candidate | PROVEN IN COMPATIBILITY MODE | `DataProcessInstance` with inlet, subtype, custom properties, deterministic URN, and relationships persisted and read back. It is not represented as a native Agent Registry run. |
| Receipt summary as hidden typed Document | PROVEN WITH CONSTRAINT | Emitted twice and directly read back. Core rejects `dataProcessInstance` as a `relatedAssets` destination, so GlassBox relates governed assets and stores the run URN as a custom property. |
| Signed compiled receipt pipeline | PROVEN | A deterministic instrumented run compiled to a signed DBOM, verified locally, resolved its dataset URN by direct read, emitted the same receipt Document twice, and directly read five persisted aspects. |
| Durable OTLP receipt acknowledgement | PROVEN, LOCAL BOUNDARY | An authenticated loopback OTLP/HTTP request atomically registered a signed receipt and PostgreSQL publication obligation, wrote the real DataHub Document twice, sealed five-aspect readback evidence, returned 200, then returned 200 for identical redelivery after fresh URN and receipt readback with zero writes. Remote TLS/rate limiting remains deployment-owned. |
| Direct entity readback | PROVEN | `get_entity_raw` returned non-empty aspect maps for dataset, model, run, and document. |
| Idempotent upsert under deterministic URN | PROVEN IN COMPATIBILITY MODE | All seven stable representations emitted twice to the expected URN. Native Agent Registry entities remain blocked by stable SDK/server release misalignment. |
| Native Agent Registry profile UI in Core | UNVERIFIED / ENABLEMENT-GATED | The stable stack lacks the native server entities; feature documentation separately says registry UI enablement may require DataHub configuration/representative. |
| Compatibility projection in Core UI | PROVEN | The agent Document renders as published subtype `GlassBox aiAgent Compatibility`, displays its non-native disclaimer, and links the governed dataset. |
| `DataProcessInstance` as arbitrary agent run | COMPATIBILITY PROVEN | Server write/readback is proven with explicit `AI Agent Run` subtype. Native run semantics and UI remain an upstream design question. See ADR-0002. |
| Observed/inferred typed runtime influence edge | GAP | Ordinary lineage does not carry GlassBox evidence state. This informs the RFC. |
| DataHub Actions plugin discovery and MCL envelope contract | PROVEN | The installed `glassbox_invalidation` entry point consumed the real 1.6.0.15 `MetadataChangeLogEvent_v1` envelope in-process and through the pinned Kafka source. |
| Deterministic incident writeback | PROVEN WITH CONSTRAINT | `incidentKey` and `incidentInfo` persisted under one deterministic URN. Core did not synthesize `incidentsSummary`; GlassBox must preserve and merge that inverse aspect explicitly. |
| Receipt quarantine | PROVEN | Fetch-modify-update preserved existing Document properties and direct readback returned the exact campaign, state, policy, event, entity, kind, and reason properties. |
| Kafka delivery into DataHub Actions | PROVEN WITH BOUNDARY | GMS published genuine MCLs; Actions decoded them through the schema registry, retried one injected action failure, synchronously committed offsets, and restarted the same group after the committed material event. Broker-side commit failure remains unverified. |
| Transactional invalidation state | PROVEN, SINGLE HOST | The live Kafka action used the SQLite WAL profile for signed-receipt indexing, campaign/audit transactions, and completion evidence. Material redelivery performed zero writes and succeeded only after fresh DataHub readback. Multi-host database behavior remains unverified. |
| DataHub owner webhook routing | PROVEN WITH BOUNDARY | The live Kafka action directly read the changed dataset's native ownership, sent one bounded loopback webhook with the deterministic campaign idempotency key, and made no second request on material redelivery. Remote production transport and human acknowledgement remain unverified. |
| PGQueue delivery into DataHub Actions | UNVERIFIED | The pinned source exists, but its visibility-timeout, acknowledgement, and restart path have not been exercised by GlassBox. |

## Probe safety and execution

### Discovered SDK/documentation gap

On 2026-08-06, the pinned stable wheel was installed and inspected locally:

```text
acryl-datahub==1.6.0.15
datahub.api.entities.dataprocess.dataprocess_instance  PRESENT
datahub.sdk.dataset                                  PRESENT
datahub.sdk.document                                 PRESENT
datahub.sdk.mlmodel                                  PRESENT
datahub.api.entities.agent                           ABSENT
generated aiAgent / agentSkill schemas               ABSENT
```

The matching `datahub-agent-context==1.6.0.15` wheel also does not supply Agent
Registry registration classes. A temporary inspection of
`acryl-datahub==1.6.0.16rc3` found the documented `Agent`, `AgentSkill`, and `Api`
modules plus the generated `aiAgent` and `agentSkill` schemas. A guarded preview run
then proved that Core `v1.6.0` rejects the `api` entity as absent from its
EntityRegistry. GlassBox does not silently upgrade production dependencies or claim
that client-side classes imply server support. See `datahub-1.6.0-sdk-gap.md`.

The static plan performs no imports or network calls:

```bash
uv run glassbox-datahub-probe plan
```

The live probe:

- targets localhost by default;
- rejects credentials embedded in URLs;
- requires `--allow-live`;
- requires a second `--allow-remote` flag for any non-loopback target;
- creates only deterministic `glassbox.probe.*` synthetic entities;
- contains no prompt, model output, customer data, or credential content;
- emits each entity twice, then calls a direct entity read;
- never deletes or edits entities outside its namespace.

The optional preview lane accepts only the inspected `1.6.0.16rc3` SDK and requires
both `--expected-sdk-version 1.6.0.16rc3` and `--allow-prerelease-sdk`.

The stable compatibility lane uses typed Documents for the three native registry
types that Core does not recognize. Every projection carries
`glassbox.compatibility_mode=document-projection`, the intended native entity type,
the canonical GlassBox ID, and the proven server-gap reason. It never fabricates a
native URN. These registry projections are published to the global Context surface;
receipt Documents remain hidden from global context by default. Run it with:

```bash
uv run glassbox-datahub-probe compatibility-live --allow-live --json
```

### Live execution status — 2026-08-06

The pinned local DataHub Core `v1.6.0` quickstart is running. The stable probe
completed against `http://localhost:8080`; its sanitized machine-readable report is
committed as `datahub-1.6.0.live.json`.

Dataset, ML model, standalone run, and receipt document capabilities completed two
writes to the expected deterministic URN and a direct non-empty aspect readback.
The stable report remains `valid: false` because its SDK cannot construct the
documented Agent Registry entities. The isolated preview report also remains
`valid: false`: it constructs the API entity, but Core `v1.6.0` rejects it as an
unknown entity type. These are precise partial proofs, not failures hidden behind a
mock. The preview evidence is preserved in
`datahub-1.6.0-agent-registry-rc.live.json`.

The stable compatibility report is `datahub-1.6.0-compatibility.live.json` and is
`valid: true`: all seven representations completed deterministic double-write and
direct-read proof.

The Gate 4 receipt pipeline report is
`datahub-1.6.0-receipt-pipeline.live.json` and is `valid: true`. Receipt
`gbx:receipt:sha256:77e06c24ff97521b6bac511ef8b9d3cb3a8460ebd3d574af00f5f39a6a2a8f22`
contains one observed evidence record, one successful read-only action, one valid
Ed25519 signature, and `ELIGIBLE` replay classification. Its deterministic DataHub
Document was upserted twice and directly returned `browsePathsV2`, `documentInfo`,
`documentKey`, `documentSettings`, and `subTypes`.

The agent projection was also opened in the Core UI by deterministic Document URN.
The rendered page showed the compatibility subtype and disclaimer plus a related
link to `glassbox.probe.orders`. This visual check supplements—but does not replace—
the authoritative direct-read proof.

The first document attempt also proved that `document.relatedAssets` rejects a
`dataProcessInstance` URN with HTTP 422. The corrected representation relates the
governed dataset and stores the run URN as a digest-safe custom property.

The receipt pipeline separately proved that `document.relatedAssets` rejects a
compatibility `document` URN with HTTP 422. The corrected emitter uses only the
verified dataset as a native related asset and preserves compatibility agent/model
references as explicit properties. The deterministic retry repaired the partially
created receipt Document and direct readback proved the corrected state.

### Gate 5 invalidation proof — 2026-08-07

The report `datahub-1.6.0-invalidation.live.json` is `valid: true`. A signed receipt
recorded observed use of `average_order_value` with complete non-wildcard field
lineage. Adding the unrelated `internal_note` field was classified `UNAFFECTED` and
performed zero DataHub writes. Retyping the used field was classified `STALE`,
created one content-addressed incident, merged the dataset incident summary, and
quarantined exactly the receipt Document. Both events were delivered twice through
the real DataHub Actions envelope contract and retained the same campaign IDs.

Direct readback returned `incidentKey` and `incidentInfo`, confirmed the incident in
the target summary, and verified every quarantine property. Three audit records
remain: one classification for the negative control, then classification and
DataHub verification for the material change. Repeat deliveries did not duplicate
audit records. The proof applied and directly read each schema version in Core, but
constructed the MCL envelope in-process; it therefore isolates plugin and writeback
behavior from broker delivery.

### Gate 5 Kafka transport proof — 2026-08-07

The report `datahub-1.6.0-kafka-invalidation.live.json` is `valid: true`. GMS
published genuine schema MCLs to `MetadataChangeLog_Versioned_v1`; the pinned Actions
Kafka source consumed and Avro-decoded them through
`http://localhost:8080/schema-registry/api/`. The material type-change envelope
arrived on partition 0 at offset 394. A proof-only wrapper raised once, Actions
recorded one exception, retried the same envelope, and the production GlassBox
plugin completed verified incident/quarantine writeback. Synchronous acknowledgement
committed offset 395.

A new pipeline instance then reused the exact consumer group. It recorded schema
offsets 399, 400, and 401, never replayed offset 394, classified the offset-401
unrelated-field addition `UNAFFECTED`, and synchronously committed offset 402. This
proves real Kafka delivery, bounded action retry, successful acknowledgement, and
same-group restart position. It does not prove broker-side commit-failure recovery,
crash-during-commit behavior, PGQueue transport, or clustered state coordination.

This final run also used the transactional SQLite WAL profile rather than the legacy
JSONL stores. Integrity verification returned one signed receipt, one reverse-index
dependency, five deterministic campaigns, and seven audit records. Redelivering the
completed material change to a new transactional worker produced zero emissions,
performed fresh authoritative DataHub readback, and matched the sealed completion
evidence. This proves single-host multi-process semantics only; it is not evidence of
PostgreSQL, network-filesystem, or multi-node behavior.

The same run wrote and directly read a synthetic native DataHub owner on the changed
dataset. The transactional action created one owner-routing obligation, sent one
loopback webhook containing that owner and the campaign ID as `Idempotency-Key`, and
sealed only one destination hash/count locally. Material redelivery reused the
completed routing task and made no second webhook call. The database finished with
one routing task and seven audit records. This proves native ownership resolution,
local outbox recovery semantics, and adapter acceptance—not production remote
transport, exactly-once delivery, or human acknowledgement.

Resume the proof with:

```bash
uv sync --extra dev --extra datahub
datahub docker quickstart --version v1.6.0
uv run glassbox-datahub-probe live --allow-live --json
```

Any replacement report must remain sanitized and must not contain a token, local
home directory, tenant identifier, or remote private URL.

## Primary references

- <https://docs.datahub.com/docs/quickstart>
- <https://docs.datahub.com/docs/api/tutorials/agent-registry>
- <https://docs.datahub.com/docs/features/feature-guides/agent-registry>
- <https://docs.datahub.com/docs/api/tutorials/datasets>
- <https://docs.datahub.com/docs/api/tutorials/mlmodel-mlmodelgroup>
- <https://docs.datahub.com/docs/api/tutorials/documents>
- <https://docs.datahub.com/docs/api/tutorials/incidents>
- <https://github.com/datahub-project/datahub/tree/master/datahub-actions>
- <https://github.com/datahub-project/datahub/releases/tag/v1.6.0>
- <https://raw.githubusercontent.com/datahub-project/datahub/v1.6.0/metadata-ingestion/src/datahub/ingestion/graph/client.py>
