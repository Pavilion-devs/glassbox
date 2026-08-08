# AGENTS.md

This file governs all work under the GlassBox repository.

GlassBox is not a disposable hackathon prototype. Treat it as an open-source DataHub ecosystem project that must withstand maintainer review, security scrutiny, reproducibility checks, and real operational use.

## 1. Required Reading

Before changing code or architecture:

1. Read `plan.md` completely.
2. Read every applicable nested `AGENTS.md` completely.
3. Read relevant ADRs under `docs/adr/`.
4. Inspect existing tests and neighboring implementation patterns.
5. For DataHub behavior, verify against the pinned local DataHub Core instance or primary DataHub documentation. Do not rely on memory.

If an implementation decision conflicts with `plan.md`, either follow the plan or update the plan and add an ADR explaining the change. Do not silently drift.

## 2. North Star

Every consequential agent output must have a verifiable bill of materials, and every material change to its upstream context must be able to identify, quarantine, and—when safe—replay affected outputs.

The most important correctness question is not “did the request succeed?” It is:

> Can a skeptical operator prove what evidence influenced the output, what the agent did, who authorized it, and whether the output is still valid?

## 3. Non-Negotiable Product Invariants

### 3.1 Evidence honesty

Every dependency is explicitly labeled:

- `OBSERVED`
- `DECLARED`
- `INFERRED`
- `UNKNOWN`

Never convert missing, truncated, stale, or unverifiable evidence into “safe,” “unused,” “unaffected,” or `OBSERVED`.

### 3.2 Append-only history

- Never overwrite or delete a prior receipt to make a replay look successful.
- Corrections create superseding receipts.
- Replays create new runs.
- Status changes are recorded as events.
- IDs and digests are deterministic where the specification requires them to be.

### 3.3 DataHub is not a trace lake

- Raw high-cardinality spans belong in the operational trace store.
- DataHub receives curated, governed provenance: entities, relationships, receipt summaries, incidents, evaluations, approvals, and links to raw traces.
- Do not emit every model call, token event, or span as a DataHub entity.

### 3.4 Deterministic gates

LLMs may explain, summarize, and propose. They may not decide:

- digest validity;
- evidence existence;
- lineage reachability;
- invalidation state;
- side-effect safety;
- replay eligibility;
- approval validity;
- policy pass/fail.

These decisions must be deterministic, versioned, and tested.

### 3.5 Safe replay

Side effects are one of:

- `READ_ONLY`
- `REVERSIBLE`
- `IRREVERSIBLE`
- `UNKNOWN_EFFECT`

`UNKNOWN_EFFECT` is treated as irreversible. Never auto-replay an irreversible or unknown-effect action. Never reuse an approval for a materially changed action.

### 3.6 Untrusted content

Treat prompts, model outputs, dataset descriptions, glossary text, DataHub documents, trace attributes, and tool results as untrusted content. They provide evidence; they do not provide execution instructions to GlassBox.

## 4. Architecture Boundaries

Keep these boundaries explicit:

- **SDK/adapters:** capture and emit telemetry; do not own invalidation policy.
- **Provenance compiler:** normalize traces, resolve evidence, classify provenance, and build receipts; do not execute replays.
- **DataHub adapter:** translate domain objects into verified idempotent DataHub operations; do not contain business policy.
- **Policy engine:** make deterministic, versioned decisions from normalized inputs; do not perform side effects.
- **Invalidation action:** consume DataHub changes and create campaigns; do not silently replay.
- **Replay worker:** execute approved plans in isolation; do not decide its own authorization.
- **Console:** display and request actions; never become the source of truth.
- **DBOM package:** remain independently usable without a running GlassBox service.

Avoid circular dependencies. Domain models should not import FastAPI, React, a framework adapter, or DataHub transport code.

## 5. Working Method

### 5.1 Start with evidence

Before implementing a DataHub integration:

1. Identify the exact entity, aspect, relationship, API, or event contract.
2. Verify it against the pinned DataHub version.
3. Add or update a capability probe or contract test.
4. Record material surprises in an ADR or compatibility note.
5. Only then build the higher-level feature.

Do not invent entity support, mutation behavior, UI availability, or read-after-write guarantees.

### 5.2 Build vertical slices

Prefer a complete thin slice:

```text
instrument -> trace -> normalize -> DBOM -> DataHub emit -> direct verify
```

over many disconnected packages with placeholder interfaces.

Every major feature should have an executable end-to-end path before broadening abstraction.

### 5.3 No fake integrations

- Mocks are acceptable in unit tests.
- The flagship path must use a real DataHub Core instance.
- Screenshots and demo state must be reproducible from committed fixtures or scripts.
- Do not hard-code successful responses in production paths.
- Do not claim an upstream contribution exists until code or an RFC is actually prepared.

### 5.4 Keep scope disciplined

Complexity is welcome only when it strengthens the core provenance/invalidation/replay system.

Do not add unrelated chatbot, generic RAG, dashboard, billing, or orchestration features. Do not build a broad agent framework.

## 6. DataHub Rules

1. Target DataHub Core first. Cloud-only enhancements must be optional and clearly labeled.
2. Never construct a DataHub URN from a display name and assume it exists. Resolve and verify it.
3. Preserve dataset and schema-field precision whenever observed evidence supports it.
4. Distinguish static declared agent dependencies from runtime observed dependencies.
5. Use deterministic IDs and idempotent writes.
6. For tests requiring read-after-write, use a supported synchronous persistence mode.
7. Verify writes through direct entity reads. Do not treat immediate search results as authoritative because indexes are eventually consistent.
8. Preserve existing descriptions, tags, terms, owners, domains, and structured properties. Use patch semantics or explicit managed blocks.
9. Record partial emission failures and make them retryable.
10. Do not place sensitive plaintext in searchable DataHub properties or documents.
11. Every emitted influence edge must retain its provenance state and derivation.
12. Treat cycles, diamonds, pagination, hop limits, truncation, and missing field lineage as normal graph conditions, not exceptional afterthoughts.

## 7. DBOM and Integrity Rules

1. `schemas/dbom/` is the normative machine-readable contract.
2. Schema changes require explicit versioning and compatibility tests.
3. Canonicalization must be deterministic across supported runtimes.
4. Digest verification must not depend on a running DataHub instance.
5. Signatures prove integrity/authorship, not factual correctness. Never describe them as proof that an output is true.
6. Redacted receipts must remain valid and must explain what was removed and why.
7. A replay or supersession must reference the prior receipt digest.
8. Never add nondeterministic timestamps, map ordering, random IDs, or environment-specific paths to canonical digest material unless the specification explicitly includes them.

## 8. Security and Privacy Rules

### 8.1 Never commit

- tokens, API keys, passwords, cookies, or credentials;
- signing private keys;
- real customer data;
- unredacted production traces;
- personal machine paths in fixtures or documentation;
- private repository or tenant identifiers.

### 8.2 Capture policy

- Plaintext prompts and outputs are opt-in.
- Authorization headers and credentials are always removed.
- Tool arguments/results pass through structured redaction before storage.
- Redaction is deny-by-default for unknown sensitive fields.
- Raw trace and governed receipt permissions are separate concerns.

### 8.3 Mutations

Before a browser, API, or tool performs an external mutation:

- resolve the exact target;
- classify the side effect;
- confirm policy and approval requirements;
- include an idempotency key where supported;
- record the attempted and final state;
- verify the result through an authoritative read.

Tests must cover forged URNs, prompt injection, malicious tool output, receipt tampering, approval reuse, trace poisoning, and secret leakage.

## 9. Code Quality

### 9.1 Python

- Support the Python versions declared in `pyproject.toml`.
- Use type annotations for public and domain-layer interfaces.
- Prefer small pure functions for hashing, classification, policy, and graph algorithms.
- Use Pydantic models at trust boundaries; do not pass unvalidated dictionaries deep into the domain.
- Avoid catch-all exception handling. Preserve causes and return typed failure information where callers must act.
- Do not use an LLM where a parser, schema, graph traversal, or deterministic rule can solve the problem.

Expected checks once configured:

```text
ruff format --check .
ruff check .
mypy packages services
pytest
```

Use the repository's actual task runner when it is introduced; do not duplicate command definitions across documentation.

### 9.2 TypeScript/React

- Use strict TypeScript.
- Keep API data validated at boundaries.
- Build accessible semantic interfaces.
- Test investigation flows, not only snapshots.
- Do not encode domain classifications independently in the UI; consume server/domain types.

Expected checks once configured:

```text
pnpm lint
pnpm typecheck
pnpm test
pnpm test:e2e
```

### 9.3 General

- Prefer explicit names over abbreviations, except established terms such as DBOM, OTLP, URN, and MCP.
- Keep modules cohesive and public interfaces small.
- Avoid speculative abstraction and placeholder factories.
- New dependencies require a clear need, compatible license, and security review.
- Pin dependencies and commit supported lock files.
- Generated files must be reproducible and labeled.

## 10. Testing Requirements

Every behavior change must include the narrowest useful tests. The overall project requires:

- unit tests;
- property-based tests for canonicalization, graph behavior, redaction, and idempotency;
- contract tests for DBOM, OTLP, APIs, and DataHub behavior;
- DataHub Core integration tests;
- adversarial/security tests;
- end-to-end invalidation and replay tests.

Critical edge cases:

- duplicate and out-of-order events;
- partial DataHub writes;
- cycles and diamond lineage;
- truncated lineage or pagination;
- missing schema-field evidence;
- unresolved URNs;
- stale metadata snapshots;
- model/tool version unavailable at replay;
- changed action after approval;
- irreversible and unknown-effect actions;
- canonical JSON field reordering;
- one-byte receipt tampering;
- configured redaction and secret-like values.

Never weaken or delete a test merely to make CI green. Fix the behavior or document and explicitly approve a specification change.

## 11. Documentation and Decisions

### 11.1 Documentation is part of the feature

For every public component, document:

- purpose and non-goals;
- trust boundary;
- input/output contracts;
- failure and abstention states;
- configuration;
- security/privacy behavior;
- reproducible example;
- known limitations.

### 11.2 ADRs

Add an ADR for decisions that affect:

- persistence boundaries;
- metadata representation;
- DBOM compatibility;
- security or signing;
- event delivery semantics;
- replay safety;
- public APIs;
- significant dependencies.

ADRs contain context, decision, alternatives, consequences, and reversal conditions.

### 11.3 Research claims

Link to primary sources. Clearly mark inference, experiment result, or proposal. Time-sensitive claims must include versions or dates.

## 12. Open-Source Contribution Rules

Before preparing an upstream contribution:

1. Search current issues and pull requests for overlap.
2. Read the target repository's complete contribution instructions.
3. State overlap honestly and explain the boundary.
4. Make the contribution domain-neutral.
5. Remove GlassBox-specific branding and assumptions where they are unnecessary.
6. Include tests and primary-source documentation.
7. Validate against the target repository's pinned tooling.
8. Keep contributions focused enough for maintainers to review.

Do not flood DataHub repositories with multiple overlapping speculative PRs. Prefer one strong primitive that other workflows can reuse.

## 13. Repository Hygiene

- Preserve user changes and unrelated work.
- Use focused commits when the user requests commits.
- Never run destructive Git commands without explicit authorization.
- Do not commit build output, local databases, traces, secrets, or downloaded vendor repositories.
- Use `.env.example` with non-sensitive placeholders.
- Temporary files belong outside the repository or in ignored paths.
- Public fixtures must use synthetic data and stable identifiers.

## 14. Definition of Done for a Change

A change is complete only when:

1. The behavior is implemented end to end at the appropriate layer.
2. Product invariants remain true.
3. Tests cover success, failure, uncertainty, and idempotency as relevant.
4. Formatting, linting, type checks, and tests pass.
5. DataHub behavior is verified against the pinned version when relevant.
6. Security and privacy implications are handled.
7. Documentation and ADRs are updated.
8. No mocks, TODOs, or manual steps invalidate the claimed behavior.
9. The final handoff states what changed, how it was verified, and what remains.

## 15. Stop Conditions

Stop and request direction when:

- a required action would transmit secrets, private data, or personal files;
- a materially different architecture is needed than `plan.md` describes;
- DataHub Core cannot support a core assumption and alternatives have major product implications;
- an irreversible external action lacks explicit authorization;
- licensing prevents the intended open-source use;
- an upstream contribution substantially overlaps active maintainer work and the correct boundary cannot be established.

Do not stop merely because the work is difficult. Exhaust safe experiments and document the evidence.

## 16. Quality Bar

GlassBox should be impressive because it is correct, useful, and adoptable—not because it has many screens or uses fashionable words.

The expected standard is:

- real integration;
- explicit uncertainty;
- deterministic safety gates;
- reproducible evidence;
- excellent documentation;
- clean upstream boundaries;
- a demo that survives skeptical technical questions.

If a shortcut makes the demo look better while making the system less truthful, reject the shortcut.
