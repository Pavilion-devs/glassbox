# Production release-candidate deployment

This profile deploys an organization-owned GlassBox control and evidence plane.
Only the edge port is published. The apex host serves the public product site and
documentation, the console host requires GitHub OAuth, and OTLP ingestion uses
individually issued GlassBox keys. PostgreSQL and internal service APIs stay on an
isolated container network.

The console image is a native Next.js standalone runtime. Vinext, Vite, Wrangler,
and the rest of the local/Sites toolchain remain build-time dependencies and are
absent from the production image. The release check requires a zero-finding
`npm audit --omit=dev` result for the runtime graph.

## Required operator inputs

1. A VPS with Docker Compose, persistent storage, and enough headroom for GlassBox.
   DataHub may be external; this stack does not install or pretend to own DataHub.
2. A public hostname and a separate console hostname routed to the same edge. The
   reference pair is `glassboxhq.xyz` and `app.glassboxhq.xyz`.
3. A GitHub OAuth App whose callback is
   `https://app.glassboxhq.xyz/oauth2/callback` (replace the host for another domain).
   The reference proxy requests `user:email read:org`. OAuth2 Proxy's GitHub
   provider resolves organization membership while creating every session, so
   `read:org` is required even though GlassBox does not restrict sign-in by
   organization. Any authenticated GitHub user becomes a read-only viewer; only
   usernames in `GITHUB_ADMIN_USERS` may change the DataHub connection or issue
   and revoke ingestion keys.
4. A scoped DataHub service account that can read catalog entities and upsert the
   GlassBox Document/Incident aspects used by the compiler and invalidation Action.
5. A receipt signing key and matching operator trust policy.
6. Independent random values for the control master key, internal API credentials,
   OAuth session secret, and PostgreSQL password.

Copy `.env.production.example` to an untracked `.env.production`, fill it through
the VPS secret boundary, and restrict it to the deployment user. Generate the
control master key with `glassbox-control master-key`; generate all other bearer
values independently. Never reuse a DataHub token as a GlassBox credential.

The hosted RC also runs a backend-only reference DataHub Core estate as a separate
Compose project. It is not a dependency bundled into this profile: it publishes no
DataHub port, exposes no DataHub UI, attaches GMS to the GlassBox private network
through one explicit alias, and keeps MySQL, Kafka, and OpenSearch on its own
project network. Customer deployments should normally connect GlassBox to the
organization's existing DataHub estate.

## Start and verify

```bash
docker compose --env-file .env.production -f compose.yml config --quiet
docker compose --env-file .env.production -f compose.yml build
docker compose --env-file .env.production -f compose.yml up -d
curl --fail http://127.0.0.1:8080/healthz
```

Sign in through GitHub at the configured console hostname, open **Connections**, and enter the
DataHub GMS origin, DataHub UI origin, and service-account token. **Verify & save**
performs an actual SDK connection test, one deterministic synthetic Document upsert,
and direct readback before the credential is encrypted. The receiver waits without
accepting traffic until this proof exists, then activates automatically.

Create a named ingestion key in the **Agent keys** tab and configure an exporter:

```text
OTEL_EXPORTER_OTLP_ENDPOINT=https://glassboxhq.xyz
OTEL_EXPORTER_OTLP_HEADERS=Authorization=Bearer <one-time-ingestion-key>
```

## TierHive and DNS

For the current infrastructure, configure TierHive HAProxy to terminate TLS for both
the public and console domains and forward them to the selected VPS private address
on `GLASSBOX_EDGE_PORT` while preserving the original Host header. Point both DNS
records at the exact TierHive regional HAProxy address. Verify the origin health
first, then the public landing page and docs, the console OAuth callback and
authentication, a DataHub connection proof, key issuance/revocation, and an OTLP 200
before calling the deployment live.

Do not attach this stack to an occupied VPS until its CPU, memory, disk, port, and
backup headroom have been inspected. Do not expose ports 3000, 4180, 4318, 5432,
8788, or 8790 directly.

## RC proof recorded on 2026-08-10

The packaged control path was exercised against the retained, commit-pinned
DataHub Core `v1.6.0` estate with DataHub SDK `1.6.0.15`. The verifier connected,
upserted `urn:li:document:glassbox.connection.probe`, directly read it back, and
saved only the AES-256-GCM encrypted service credential.

On the isolated hosted VPS, the separate backend-only DataHub Core `v1.6.0` project
runs with metadata and REST authorization enabled and no published DataHub ports.
Anonymous GraphQL access is denied. A native GlassBox service account has no role
assignment: custom policies grant Document-scoped create/update/read authority and
dataset read/incident authority only. Its rotating token remains root-owned outside
containers except for encrypted control-plane storage.

The separate hosted edge proof provisioned an isolated TierHive VPS, routed
`glassboxhq.xyz` through the regional HAProxy and Let's Encrypt certificate, and
completed the GitHub OAuth flow. Authenticated GitHub users resolve as read-only
viewers unless explicitly configured as administrators; the verified operator can
use the live DataHub connection form and named agent-key controls. The control plane
proved connection, authentication, SDK
compatibility, Document write, and direct readback before activating the receiver.
One named production ingestion key is active; an earlier key whose one-time secret
was not recoverably escrowed is revoked.

The real public `https://glassboxhq.xyz/v1/traces` path then received a two-span
synthetic run produced by the deterministic pricing agent. Delivery one returned
HTTP 200, registered and reread the signed receipt in PostgreSQL, performed the
required idempotent double emission, and directly read back five persisted Document
aspects. Identical redelivery returned HTTP 200 for the same receipt and Document
with `datahub_write_performed=false`. The authenticated console shows the verified
receipt and its resolved `commerce.orders` dependency. The sanitized evidence is
`docs/compatibility/datahub-1.6.0-hosted-production-otlp.live.json`.

The deployed stores also require a trusted signer to be active both at admission
and at the receipt's claimed run time before any durable write. A live PostgreSQL
regression rejected a receipt from before its signer's validity window with zero
receipt, dependency, or publication-task rows. After that hardened image was rolled
out, external identical redelivery again returned HTTP 200 with fresh PostgreSQL and
DataHub readback and no DataHub write.

This reference proof does not claim customer-owned DataHub tenancy, a public
DataHub UI, multi-node high availability, or disaster-recovery readiness. Those
remain deployment-specific operator responsibilities.
