# GlassBox Forensics Console

The judge-facing investigation surface for GlassBox. It turns signed decision
receipts and DataHub metadata changes into a compact causal explanation:

- whether the receipt itself is trustworthy;
- which observed dependency changed;
- why the change is or is not material to the decision;
- which governed response is allowed next;
- and where DataHub projections stop being cryptographic evidence.

The default case is backed by the repository's live DataHub Core 1.6.0 proof.
Its negative-control view demonstrates that GlassBox can prove a decision was
unaffected when complete field lineage excludes the changed field.

## Local development

Requires Node.js 22.13 or newer.

```bash
npm install
npm run dev
```

The development server prints the exact local URL. The preferred quality gate
is:

```bash
npm test
npm run lint
npm run typecheck
```

`npm test` creates a production build and checks the rendered investigation for
the core forensic claims and the absence of starter or secret material. The console
does not declare database or object-storage bindings because the current experience
is a read-only projection of verified GlassBox evidence.

## Safety posture

This console is deliberately raw-free. It renders receipt digests, governed
metadata, reason codes, evidence identifiers, and proof-gate outcomes. It does
not render model prompts, raw tool payloads, credentials, query results, or
arbitrary DataHub custom properties.

The console is a presentation layer. Receipt verification, materiality
classification, quarantine, and replay authorization remain enforced by the
GlassBox backend and the `datahub-agent-forensics` skill.
