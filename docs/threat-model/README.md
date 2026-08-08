# GlassBox threat model

**Status:** Initial Gate 0 model; expand with each trust boundary.

## Protected assets

- DBOM integrity and signer identity;
- accuracy of evidence-state labels;
- approval scope and replay authorization;
- sensitive prompts, outputs, tool payloads, and credentials;
- tenant and namespace boundaries;
- availability of compilation, invalidation, and replay controls.

## Trust boundaries

1. Instrumented agent to authenticated telemetry ingestion.
2. Untrusted trace and tool content to provenance compiler.
3. Compiler to operational trace and artifact stores.
4. GlassBox adapter to DataHub Core.
5. DataHub change events to invalidation engine.
6. Approval issuer to policy engine.
7. Replay plan to isolated replay executor.
8. APIs to console and forensic skill.

## Initial threats and mandatory controls

| Threat | Initial control | Required evidence |
| --- | --- | --- |
| Forged DataHub URN in tool output | Resolve and directly verify existence | Adversarial integration test |
| Prompt injection in metadata | Treat content only as evidence, never instructions | Injection fixture and refusal test |
| Receipt tampering | RFC 8785 digest, Merkle root, Ed25519 | One-character and signature tamper tests |
| Attacker self-signs with an unauthorized key | Operator registry binds key ID and public-key fingerprint; admission requires active window | Forged signer, ID-substitution, and zero-write state tests |
| Retired signer backdates a new receipt | Current trusted clock for admission; signed run time only for already admitted history | Rotation tests across JSONL, SQLite, and PostgreSQL |
| Compromised signer remains trusted historically | Explicit `REVOKED` state fails fresh admission and historical reads | Revocation startup/read tests |
| Forged migration bundle launders untrusted receipts | Separate transfer authority plus current receipt-signer admission; content address and threshold signatures | Tamper, self-signing, retired-key, and zero-target-write tests |
| State import repeats completed side effects | Activate receipts only; keep campaigns, leases, routing, audit, and completion evidence in a signed inactive archive | Fresh-publication and cross-engine non-reactivation tests |
| Partial state import leaves an ambiguous target | One all-or-nothing receipt batch transaction in SQLite and PostgreSQL | Late-conflict rollback tests on both engines |
| Approval reused for changed action | Bind approval to action digest and policy version | Policy contract test |
| Secret leakage | Default-deny structured redaction | Generated secret-like property tests |
| Trace poisoning | Bearer-authenticated receiver, strict OTLP schema, body/span/time limits | Rejected-export HTTP tests |
| Lost publication after compiler crash | Atomic receipt/publication obligation, leases, independent drain worker | Crash-boundary and recovery tests |
| Duplicate remote mutation after uncertain commit | Stable receipt URN, two idempotency writes, sealed readback, zero-write completed retry | DataHub and outbox integration tests |
| Cross-tenant access | Namespace isolation and authorization checks | Multi-tenant integration suite |
| Unsafe replay | Effect taxonomy; unknown is irreversible | Replay refusal tests |
| DataHub cardinality exhaustion | Consequential-run filter and retention policy | Write-amplification benchmark |
| Misleading causality | Visible evidence states and derivation | Schema and UI contract tests |

## Security invariants already executable

- DBOM schema rejects relabeling incomplete evidence as `OBSERVED`.
- Non-finite or non-canonical JSON is rejected.
- Payload, receipt ID, Merkle root, and signatures are verified independently.
- Production receipt admission additionally requires an active operator-trusted
  signer; a self-contained signature is not its own trust anchor.
- Live DataHub mutation is explicit and loopback-only unless separately authorized.
- An OTLP request is acknowledged only after direct-read publication evidence is
  sealed; completed retry is read-only.

This is not a complete security assessment. Authentication, storage encryption,
tenant enforcement, deletion, managed KMS/HSM integration, and replay sandboxing
remain later-gate deliverables. File-backed signer rotation is implemented; managed
policy distribution and tenant-specific authorities are not.
