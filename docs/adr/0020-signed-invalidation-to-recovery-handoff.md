# ADR-0020: Bind completed invalidation to corrected replay with signed authorization

- **Status:** Accepted
- **Date:** 2026-08-08
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0012](0012-capability-scoped-read-only-replay-and-supersession.md), [ADR-0014](0014-shared-live-decision-state.md)

## Context

The invalidation Action and replay worker previously had correct but disconnected
proofs. A receipt could be classified `STALE`, quarantined, and written back through
DataHub, while a separate example replayed an unrelated fixture. Corrected replay
also replaced an evidence digest without requiring the affected action input digest
to change. That allowed a technically valid bundle to describe corrected context
while its handler still consumed the source input.

Invalidation must not automatically grant execution authority. A recovery workflow
needs a durable, separately signed handoff that binds the actual completed campaign,
the exact stale receipt, the corrected bundle, and the operator decision. Corrected
context must also propagate into the action that consumed it.

## Decision

- Add an optional action-input replacement to Replay Bundle 0.1. It commits the
  original and active input digests, source evidence IDs, replacement origin, and
  verification authority inside the action digest and bundle signature.
- A replaced `INPUT` evidence item must bind at least one action-input replacement.
  The context and action authorities must match, both digests must actually change,
  and runtime execution must supply an input whose digest equals the active value.
- Add a content-addressed `RecoveryAuthorization`. It binds one completed
  invalidation campaign, incident, change event, source receipt and payload digest,
  exact `STALE` finding, matched evidence IDs, verified DataHub writeback digest,
  corrected replay bundle, operator, issue time, expiry, scope, and revocation state.
- Issue recovery authorization only when the campaign is `COMPLETED`, direct
  DataHub writeback evidence is valid, and the exact source receipt Document is in
  the verified quarantine set. `AT_RISK`, `UNKNOWN`, `UNAFFECTED`, missing writeback,
  pending work, or a different receipt cannot authorize corrected replay.
- Require the corrected context and corrected action inputs to match exactly the
  campaign's stale evidence IDs. Recheck their original digests against the source
  receipt and require distinct active digests.
- Sign authorizations with Ed25519 and require a trusted key ID plus exact public-key
  fingerprint. Embedded self-asserted keys are not operator authority.
- Recheck content address, every signature, fingerprint trust, exact operational
  binding, expiry, and revocation immediately before planning and execution.
- The handoff grants eligibility for one exact bundle; it does not bypass replay
  planning, exact resource inventory, capability scoping, runtime context
  observations, or source-history preservation.
- Keep the authorization and all reports digest-only. Raw context, action input,
  output, credentials, and private keys never enter DataHub or the handoff artifact.

## Evidence

Unit and offline scenario tests prove deterministic issuance, exact campaign and
source binding, corrected action-input execution, source preservation, changed
output, and supersession. Adversarial cases cover pending and unverified campaigns,
authority mismatch, omitted action propagation, untrusted fingerprint, expiry,
revocation, and completed-campaign drift.

The guarded flagship ran the same contract against DataHub Core `v1.6.0`, SDK
`1.6.0.15`, official DataHub MCP `0.6.0`, GlassBox MCP, and PostgreSQL `16.14`.
One actual receipt moved through publication, unrelated-field negative control,
`STALE` invalidation, verified quarantine, signed recovery authorization, corrected
read-only execution, new receipt publication, and separate supersession readback.
The committed raw-free report is
[`datahub-1.6.0-flagship-causal-recovery.live.json`](../compatibility/datahub-1.6.0-flagship-causal-recovery.live.json).

## Alternatives considered

- Replay any receipt named by an operator flag: rejected because a flag does not
  prove campaign completion, writeback, quarantine, or exact finding identity.
- Let invalidation call replay directly: rejected because metadata mutation must not
  silently become execution authority.
- Replace context but keep the original action input: rejected because the claimed
  correction would not be causally connected to execution.
- Trust any public key embedded in an authorization: rejected because signatures
  prove possession, not operator authority.
- Store raw corrected values in the handoff: rejected because it violates the
  DataHub and DBOM privacy boundary.

## Consequences and limits

The live story is now one causal chain rather than adjacent demos, and the same
contract is reusable by a future queue or approval service. The current capability
handler remains trusted in-process code; this decision itself does not provide an
OS, network, filesystem, or resource sandbox. ADR-0021 now supplies the hardened OCI
execution profile and verified DataHub incident closure. A durable supersession
relation in the invalidation state index remains separate work.

## Reversal conditions

Replace the authorization Document shape if DataHub adopts a native immutable
recovery workflow entity with equivalent signature, trust, campaign, receipt,
bundle, expiry, privacy, and direct-readback semantics. Keep the causal and
fail-closed gates even if transport or storage changes.
