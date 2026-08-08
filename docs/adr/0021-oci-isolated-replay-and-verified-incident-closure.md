# ADR-0021: Isolate corrected replay and close incidents only after verified supersession

- **Status:** Accepted
- **Date:** 2026-08-08
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0012](0012-capability-scoped-read-only-replay-and-supersession.md), [ADR-0020](0020-signed-invalidation-to-recovery-handoff.md)

## Context

The signed recovery handoff proved that a real stale campaign authorized one exact
corrected bundle, but its capability still ran as trusted Python in the replay
process. A malicious or defective handler could use ambient network, filesystem,
environment, process, or resource authority despite its declared `READ_ONLY` effect.
The live chain also left the DataHub incident active after a verified replay and
supersession, forcing an operator to reconcile metadata that GlassBox already knew.

Neither gap can be closed by a report-only flag. Isolation controls must be enforced
by the host runtime and bound into the replay execution. Incident resolution must
depend on fresh DataHub server readback, preserve both receipt Documents, and refuse
to overwrite a different operator resolution.

## Decision

- Add `ContainerIsolationProfile`, `ContainerCapabilityRunner`, and a
  content-addressed `IsolationAttestation` to the reusable replay package.
- Execute the capability in one exact OCI image ID, never a mutable tag. Before each
  invocation, inspect the image and require labels matching the receipt's exact tool
  source digest, schema digest, and protocol version.
- Run with `--network none`, a read-only root filesystem, all Linux capabilities
  dropped, `no-new-privileges`, a non-root image user, bounded memory, CPU, PIDs,
  timeout, stdin, stdout, stderr, and a small `noexec,nosuid,nodev` temporary
  filesystem. Do not mount the repository, host filesystem, credentials, or Docker
  socket into the child.
- Use a closed canonical-JSON stdin/stdout protocol. The child performs negative
  network, root-write, and host-environment probes; the host constructs the
  attestation from its enforced command plus successful probe results. Child output
  remains transient. Only output digests and raw-free control evidence are retained.
- Bind every isolation attestation into the content-addressed execution and the new
  signed replay receipt. Reject an image whose labels drift from the tool pins.
- Keep the older in-process executor API for offline and explicitly trusted use, but
  never allow it to authorize automated incident closure.
- Add a content-addressed `RecoveryClosureRecord`. Create it only after re-verifying
  the signed recovery authorization, completed campaign, source and replay receipts,
  corrected bundle, successful isolated execution, and exact supersession.
- Before resolving an incident, directly read DataHub and verify the incident is
  active, the target summary is active, the source receipt remains quarantined, the
  replay receipt exists, and every managed supersession property matches.
- Resolve with `state=RESOLVED` and `stage=FIXED`, binding the closure ID in the
  status message. Move the incident from active to resolved rich summary details,
  preserve unrelated incidents, double-write idempotently, and directly read back
  the result.
- Hash both receipt Documents before and after closure and fail if either changes.
  Continue to treat DataHub's rich incident-detail arrays as authoritative because
  Core 1.6 may omit the deprecated `resolvedIncidents` array while persisting
  `resolvedIncidentDetails` correctly.
- If the incident was resolved by a different closure or operator, refuse to
  overwrite it.

## Evidence

Unit tests cover exact OCI arguments, content addressing, tool-pin labels, failed
runtime probes, protocol drift, raw-value exclusion, execution and receipt binding,
unisolated closure refusal, prerequisite drift, non-idempotent writes, altered
receipt Documents, and incident-summary preservation. The live worker was built
from the digest-pinned base in `examples/Dockerfile.replay-sandbox` and executed on
Docker with all three denial probes passing.

The guarded flagship then ran one causal chain against DataHub Core `v1.6.0`, SDK
`1.6.0.15`, official DataHub MCP `0.6.0`, GlassBox MCP, and PostgreSQL `16.14`.
It directly verified the exact OCI image and tool labels, changed the corrected
decision, published both receipts and the supersession, resolved the exact incident,
verified the resolved target summary, and proved both receipt entity digests were
unchanged. The raw-free evidence is
[`datahub-1.6.0-flagship-causal-recovery.live.json`](../compatibility/datahub-1.6.0-flagship-causal-recovery.live.json).

## Alternatives considered

- Trust an in-process read-only declaration: rejected because metadata does not
  constrain operating-system authority.
- Run an arbitrary command supplied in the replay bundle: rejected because the
  bundle must select a reviewed capability, not manufacture executable authority.
- Pin only an image tag: rejected because tags are mutable.
- Let the child self-report isolation: rejected because host-enforced flags, image
  inspection, and negative probes must agree.
- Resolve immediately after execution: rejected because publication and
  supersession may have failed or drifted.
- Treat an already-resolved incident as success: rejected unless its exact closure
  ID and deterministic resolution timestamp match.
- Rewrite the source receipt from stale to recovered: rejected because receipts and
  their DataHub Documents are append-only historical evidence.

## Consequences and limits

The isolated runner depends on an OCI runtime compatible with the documented Docker
flags. It materially narrows capability authority but is not a claim of protection
against a compromised container runtime, host kernel, or Docker daemon. Network
denial covers the child network namespace; it does not remove authority from the
trusted parent orchestrator. Domain-specific semantic equivalence remains separate
from exact output comparison. The invalidation state index still does not persist a
native supersession edge; DataHub holds the verified relation and resolved incident.

## Reversal conditions

Replace the Docker adapter when a portable sandbox supplies equal or stronger exact
image identity, tool-pin binding, network/filesystem/process/resource controls,
bounded transport, and host-created attestations. Replace the Document-based
supersession or incident adapter if DataHub exposes native immutable recovery
workflow entities with equivalent idempotency and direct-read guarantees.
