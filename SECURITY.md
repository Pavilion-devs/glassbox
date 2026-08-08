# Security Policy

GlassBox handles provenance that may reveal sensitive organizational behavior.
Security and privacy failures are therefore product-correctness failures.

## Supported versions

Until the first stable release, only the latest commit on the default branch is
supported for security fixes.

## Reporting a vulnerability

Do not open a public issue for suspected secret disclosure, authentication bypass,
signature-verification failure, cross-tenant leakage, or unsafe replay. Use the
repository's [private security-advisory channel](https://github.com/Pavilion-devs/glassbox/security/advisories/new).

Include a minimal reproduction, affected version/commit, impact, and any temporary
mitigation. Do not include real customer data or working credentials.

## Data-handling baseline

- Plaintext prompts and outputs are opt-in.
- Authorization headers, cookies, tokens, and credential-like fields are removed.
- Tool arguments, results, and evidence representations are committed by digest and
  are not retained in normalized runtime events; exception messages are also omitted.
- Unkeyed digests are integrity commitments, not encryption. Do not publish
  low-entropy sensitive value digests where offline guessing is an unacceptable risk.
- DataHub receives curated receipt summaries, never unbounded raw telemetry.
- Signing private keys and local development receipts containing private material
  are excluded from version control.
- PostgreSQL DSNs and webhook bearer tokens are loaded from named environment
  variables. Commit only variable names and synthetic placeholders; inject real
  values through a secret manager and use TLS in production.
- Live mutation commands require an explicit opt-in flag and refuse unknown targets.

The initial threat model is in `docs/threat-model/README.md`.
