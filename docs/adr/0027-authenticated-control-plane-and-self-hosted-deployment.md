# ADR-0027: Add an authenticated control plane and self-hosted deployment boundary

- **Status:** Accepted
- **Date:** 2026-08-10
- **Owners:** GlassBox maintainers
- **Extends:** [ADR-0013](0013-read-only-forensics-mcp.md),
  [ADR-0016](0016-durable-receipt-publication-and-otlp-acknowledgement.md), and
  [ADR-0026](0026-loopback-console-read-model.md)

## Context

GlassBox has production-shaped evidence, invalidation, recovery, and read-only
forensics services, but the first console deliberately runs against a loopback-only
unauthenticated API. That is an honest local boundary, not an internet deployment.
Putting the console and its existing API directly behind a domain would expose
governed operational metadata and would provide no safe way to configure DataHub,
issue agent credentials, or identify operators.

The product also needs one coherent installation model. A DataHub deployment is an
organization-level system, so GlassBox should connect once with a scoped DataHub
service account. Human operators and telemetry-producing agents are different
principals and must not share that credential.

## Decision

1. Ship self-hosted, organization-owned GlassBox first. A future hosted control
   plane is not implied by this deployment.
2. Separate three credentials:
   - humans authenticate at the edge through an operator-configured OAuth 2.0 or
     OIDC provider;
   - GlassBox uses one scoped DataHub service-account token;
   - agents use individually named and revocable GlassBox ingestion keys.
3. Add a control-plane service with an authenticated, role-checked HTTP API. The
   service is reachable only on the private application network. Every request must
   carry a high-entropy internal bearer credential added by the console server; it
   never trusts browser-supplied identity headers on their own.
4. The edge proxy removes incoming identity and role headers before authentication,
   obtains identity from the identity proxy, and then injects the normalized subject
   and role for the console. The route order is explicit so sanitization cannot erase
   the trusted identity after it is created. The console forwards those claims to the
   control plane only after authenticating itself with the internal bearer credential.
5. Store control state in one explicitly initialized SQLite database for the
   single-node release candidate. Encrypt the DataHub token with AES-256-GCM using
   a 32-byte deployment master key that is never stored in the database. Bind the
   ciphertext to its organization, connection ID, and format version through
   authenticated additional data.
6. Store agent ingestion credentials only as keyed HMAC-SHA-256 digests. Return the
   clear credential once at creation. Revocation is durable and authorization reads
   fail closed if the control database or master key is unavailable.
7. A connection test performs a real DataHub SDK connection check. The optional
   write proof emits one deterministic, clearly labelled synthetic Document and
   directly reads it back. Reachability is never reported as write permission, and
   mocks never produce a `PROVEN` compatibility state.
8. The console remains a presentation layer. It may proxy bounded control requests,
   but it never persists or logs a DataHub token and never receives the deployment
   master key, signing key, PostgreSQL DSN, or raw receipt content.
9. Keep the forensics service private. Container-to-container access requires a
   separate bearer credential, and the console server sends that credential without
   exposing it to the browser.
10. The public deployment exposes only TLS at the edge. PostgreSQL, the control
    database, forensics API, and service ports remain private. OAuth configuration is
    mandatory for a production profile; an explicitly named local-development
    operator bypass is allowed only outside production.
11. A deployment may serve the static product site and documentation without human
    authentication on an explicitly allowlisted public hostname. That hostname has
    no route to the operator pages or control API. The authenticated console uses a
    separate hostname, while `/v1/traces` remains protected by revocable agent
    credentials. Unknown Host headers fail closed at the edge.

## Role model

- `viewer`: read connection status and evidence projections.
- `operator`: viewer capabilities plus operational inspection.
- `admin`: test or replace the DataHub connection and create or revoke ingestion
  keys.

Mutation responses and audit rows contain bounded identifiers and outcome codes,
never credentials, tokens, exception messages, or request bodies.

## Deployment profile

The release candidate uses a private Compose network with an edge proxy, OAuth proxy,
console, control plane, forensics service, compiler receiver, and PostgreSQL. The
domain and TLS provider are deployment choices. The reference configuration supports
an upstream TLS/HAProxy provider terminating at the VPS as well as direct Caddy TLS;
exact DNS and certificate ownership must be selected before publication.

The reference edge assigns `glassboxhq.xyz` to the unauthenticated landing page,
documentation, and authenticated OTLP receiver, and `app.glassboxhq.xyz` to the
GitHub-OAuth-protected operator console. Both hosts may terminate at the same edge,
but their route allowlists and principal types remain distinct.

SQLite is accepted here only for low-write control metadata on one VPS. Receipt,
campaign, publication, and recovery authority remains PostgreSQL. A multi-replica
control plane requires a new migration design and a shared transactional store.

## Alternatives considered

- **Put the unauthenticated forensics server on the public domain:** rejected because
  read-only governed metadata still requires authenticated principals and rate
  limits.
- **Use each human's DataHub personal token:** rejected because runtime publication
  would depend on a person's lifecycle and would blur human and workload authority.
- **Store the DataHub token in console environment or browser storage:** rejected
  because it would enter the presentation or client boundary.
- **One shared agent bearer token:** retained only as a legacy environment profile;
  named keys are required for accountable issuance and revocation.
- **Claim permissions after a health check:** rejected. Permission is `UNVERIFIED`
  until a real authorized operation and direct readback succeed.
- **Run a new identity database inside GlassBox:** rejected. The configured OAuth or
  OIDC provider remains the organization's identity authority. The reference
  production profile uses a GitHub OAuth App with a deployment allowlist.

## Consequences and limits

- Operators must provide an OAuth client, a control-plane master key, and
  internal service credentials before an internet deployment is production-safe.
- Runtime consumers wait through initial onboarding and transient dependency
  unavailability, then activate automatically after a verified DataHub connection
  is saved.
- The deterministic DataHub write proof leaves an intentionally labelled synthetic
  Document. It is idempotent and contains no secret or customer data.
- Edge RBAC mapping is initially deployment-wide. DataHub-side policies still govern
  the service account, while tenant-specific policy and managed KMS/HSM custody are
  future work.
- The public and console DNS names must both preserve the original Host header when
  an upstream TLS proxy forwards them to the reference edge.

## Reversal conditions

Replace the single-node control store with PostgreSQL or a managed secrets system
when GlassBox needs multiple control replicas, tenant isolation, online key rotation,
or externally managed encryption. Replace the proxy-header identity bridge if the
control API terminates and validates OAuth/OIDC tokens directly with equivalent issuer,
audience, expiry, role, and revocation guarantees.
