# Initial risk register

| ID | Risk | Likelihood | Impact | Mitigation | Evidence owner |
| --- | --- | --- | --- | --- | --- |
| R-001 | DataHub runtime representation is semantically weak | High | High | Compatibility Document plus metadata RFC; keep ADR-0002 proposed until live probe | DataHub adapter |
| R-002 | Run entities overwhelm the graph | Medium | High | Curate consequential runs; raw spans stay outside DataHub | Compiler |
| R-003 | URN resolution overclaims observed evidence | High | Critical | Explicit hierarchy, direct verification, preserve `UNKNOWN` | Resolver |
| R-004 | Receipt signatures are mistaken for truth | Medium | High | UI/docs wording and separate evaluation fields | DBOM/console |
| R-005 | Tool payloads leak secrets or PII | High | Critical | Default-deny capture, structured redaction, separate trace access | SDK/compiler |
| R-006 | Invalidation creates alert storms | Medium | High | Materiality policy, idempotent campaigns, deduplication | Invalidation |
| R-007 | Replay repeats irreversible actions | Medium | Critical | Unknown-effect is irreversible; deterministic approval gate | Replay/policy |
| R-008 | Demo relies on Cloud-only screens | Medium | Medium | Core-first APIs, external console, capability matrix | Demo/DataHub adapter |
| R-009 | Upstream contribution overlaps active work | Medium | Medium | Search issues/PRs, engage maintainers, focused primitives | Maintainers |
| R-010 | Local setup becomes too heavy to reproduce | High | Medium | Lightweight DBOM core; pinned optional DataHub estate; one-command checks | Developer experience |
| R-011 | Receipt is registered but DataHub publication is abandoned after a crash | Medium | Critical | Atomic publication obligation, leased repair worker, 200-after-seal acknowledgement | Compiler/state |
| R-012 | Public OTLP receiver becomes an ingestion or secret-exposure vector | High | Critical | Bearer auth, non-loopback refusal, body/span/time limits, raw-free errors, external TLS/rate limits | Receiver |
| R-013 | A valid self-signature is mistaken for operator authorization | High | Critical | Fingerprint-bound signer registry, active admission windows, explicit retirement/revocation, threshold tests | DBOM/state |
| R-014 | Stale trust-policy rollout rejects new keys or extends old-key admission | Medium | High | Overlap runbook, startup key check, policy validation, synchronized restart evidence | Operations |
| R-015 | An overly permissive semantic rule hides a material replay change | Medium | Critical | Exact equality by default; closed primitives; content-addressed packs; explicit trusted IDs; output-kind binding; complete change coverage; no ignore rules | Replay/policy |
| R-016 | Source acknowledgement fails after verified DataHub or remote effects | Medium | Critical | Stable consumer groups, transactional campaigns/outboxes, source-specific persisted-offset checks, exact-event redelivery tests, zero-write fresh verification, remote idempotency keys | Actions/state |
