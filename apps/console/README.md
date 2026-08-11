# GlassBox Forensics Console

The read-only operator application for signed agent decisions, DataHub impact
campaigns, and recovery review. The console has independent routes for overview,
investigations, receipts, campaigns, recovery, trust, and settings.

It does not bundle a successful demo response. Every record is read from the
configured GlassBox Forensics API. An absent or unreachable service produces an
explicit connection state rather than invented application data.

## Evidence connection

Run the existing forensics service over its loopback-only HTTP surface:

```bash
glassbox-forensics-mcp \
  --transport streamable-http \
  --state-postgres-dsn-env GLASSBOX_STATE_POSTGRES_DSN \
  --signer-trust-policy "$GLASSBOX_SIGNER_TRUST_POLICY_PATH"
```

Configure the console server:

```bash
GLASSBOX_FORENSICS_API_URL=http://127.0.0.1:8788
GLASSBOX_FORENSICS_API_TOKEN=local-private-service-token
GLASSBOX_CONTROL_API_URL=http://127.0.0.1:8790
GLASSBOX_CONTROL_API_TOKEN=local-private-control-token
GLASSBOX_ALLOW_LOCAL_OPERATOR=true
```

The HTTP surface is loopback-only unless a private service bearer token is supplied.
Remote access belongs behind the authenticated operator boundary in
[`deploy/production`](../../deploy/production/README.md); the browser never receives
the private API credential, PostgreSQL DSN, signing material, control master key, or
DataHub service-account token.

## Connection Center

The Connections route talks to the private `glassbox-control` service through a
server-side allowlisted proxy. An administrator can run a real DataHub SDK test,
prove write permission through a deterministic synthetic Document and direct
readback, save the token encrypted, and create or revoke named agent ingestion keys.
The clear ingestion key is displayed once. A configured DataHub UI origin activates
top-level and entity-specific deep links without putting the service-account token
in the link or browser.

For the live flagship, run `examples.flagship_demo` with `--keep-estate`. The
raw-free report records the retained schema as `estate.state_postgres_schema`;
pass that exact value to the service with `--state-postgres-schema`. The flagship
uses an ephemeral demo signer, so local inspection may use
`--allow-untrusted-signers`; production must supply an operator trust policy.

## Local development

Node.js 22.13 or newer is required.

```bash
npm install
GLASSBOX_PUBLIC_HOSTS=glassbox.localhost npm run dev
```

One build intentionally has two faces. `http://glassbox.localhost:3000` serves
the public landing page and documentation, while `http://localhost:3000` keeps
the operator console at `/`. A self-hosted organization that leaves
`GLASSBOX_PUBLIC_HOSTS` empty receives only the console. The production reference
uses `glassboxhq.xyz` for the public surface and `app.glassboxhq.xyz` for the
OAuth-protected console; public hosts cannot reach operator or control API routes.

Quality gates:

```bash
npm test
npm run lint
npm run typecheck
```

## Trust boundary

The console displays only bounded receipt projections, governed URNs,
deterministic findings, workflow state, and fresh verification results. It never
receives prompts, outputs, tool bodies, credentials, raw query results, or signing
keys. Policy, quarantine, and recovery authority remain in the GlassBox services.
