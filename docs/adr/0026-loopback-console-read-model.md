# ADR-0026: Loopback console read model

## Context

The first console rendered one committed flagship report directly inside a single
page. That made a reproducible proof easy to inspect, but it was not an operational
product: navigation did not create distinct workflows, successful content existed
without a running evidence authority, and the UI could be mistaken for the source
of decision state.

The existing `ForensicsService` already owns a bounded, raw-free read boundary over
verified receipt profiles and persisted invalidation campaigns. The console needs
list and detail views without receiving PostgreSQL credentials, signing keys, raw
DBOM bodies, or mutation authority.

## Decision

1. The console is a multi-route read-only application. Overview, investigations,
   receipts, campaigns, recovery, trust, and settings are independent routes.
2. Production UI code never imports the flagship compatibility report or a
   hard-coded successful response.
3. `ForensicsService` exposes bounded receipt-list, campaign-list, and overview
   projections in addition to its existing detail operations.
4. The MCP process may expose those projections as loopback-only HTTP routes when
   started with `--transport streamable-http`. The default remains stdio MCP.
5. The HTTP console surface refuses a non-loopback bind. Remote deployments must
   add authenticated operator infrastructure before relaxing this boundary.
6. The console server reads `GLASSBOX_FORENSICS_API_URL`. Missing, unreachable, or
   unsupported services produce explicit states rather than populated fallback data.
7. Policy classification, receipt verification, campaign processing, quarantine,
   and recovery authorization remain outside the UI.

## Alternatives

- **Bundle the live flagship report:** rejected because proof evidence is not live
  application state.
- **Read PostgreSQL directly from the console:** rejected because it leaks the
  persistence boundary and credentials into the presentation layer.
- **Call DataHub only:** rejected because DataHub projections do not contain the
  full cryptographic receipt and persisted Action authority.
- **Expose unauthenticated remote HTTP:** rejected because the read model contains
  governed operational metadata even though it is raw-free.

## Consequences

- The application is honest when disconnected and useful against any compatible
  receipt/campaign store.
- Each navigation destination can evolve independently without duplicating policy.
- A connected deployment needs the forensics process plus an operator-controlled
  API URL.
- Recovery currently derives its queue from quarantined campaign findings; a
  dedicated persisted recovery-history reader remains separate future work.

## Reversal conditions

Replace the loopback HTTP boundary when GlassBox has a reviewed authenticated API
gateway or when DataHub provides an equivalent native operator read model with the
same receipt-verification, provenance-state, and campaign-history guarantees.
