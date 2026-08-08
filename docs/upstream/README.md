# Upstream contribution packet

GlassBox is intentionally split into reviewable ecosystem contributions. These
documents record publication state per contribution. The DataHub Core pgQueue test
is open and ready for review as pull request #19004; the Skill, metadata discussion,
Action, MCP, package, and release remain prepared local artifacts unless stated
otherwise.

| Contribution | Maintainer-facing artifact | Current boundary |
| --- | --- | --- |
| DataHub Skill | [Agent forensics Skill PR](datahub-agent-forensics-pr.md) | Read-only workflow; deterministic helpers are optional |
| DataHub metadata | [Agent decision pre-RFC discussion](agent-decision-rfc-discussion.md) | Seeks direction before proposing PDL or GMS code |
| DataHub Action and MCP | [Release readiness](release-readiness.md) | External plugin and companion server first |
| Action ownership decision | [Actions contribution analysis](datahub-actions-contribution.md) | Avoids transferring the full policy/state stack into DataHub core prematurely |
| DataHub Core pgQueue test | [Live pgQueue integration PR](datahub-pgqueue-integration-pr.md) | PR #19004 ready for review; domain-neutral recovery coverage with no GlassBox runtime code |
| Deterministic handoff | `release-evidence/upstream/upstream-packet.json` | Exact-baseline, raw-free, publication-state manifest plus apply-ready patch |

## Reproducible Skill handoff

The local packet builder validates the exact `datahub-project/datahub-skills`
baseline and branch, rejects out-of-scope paths, unsafe file types, large files,
whitespace defects, secret markers, invalid release evidence, and invalid live
proofs. It then emits:

- `release-evidence/upstream/upstream-packet.json`, which hashes every changed file,
  the GlassBox release artifacts, five live/evaluated implementation proofs
  spanning dual-MCP forensics, narration, both durable crash boundaries, and
  domain-semantic policy projection, plus these maintainer documents;
- `release-evidence/upstream/datahub-skills-agent-forensics-f22f930.patch`, an
  apply-ready patch for exact baseline `f22f930`.

The patch was applied to a clean detached clone of that baseline on 2026-08-07.
DataHub's pinned Prettier and markdownlint checks, Ruff, the focused helper test,
JSON parsing, and `git diff --check` all passed in the patched clone. This proves a
local handoff artifact; it does not claim a fork, commit, discussion, or pull
request exists upstream.

## Submission order

1. Ask the focused pre-RFC question on Agent Registry RFC #16012.
2. Land the focused pgQueue live integration test now ready for review as PR #19004;
   it closes an existing test gap without depending on the metadata RFC or GlassBox
   runtime.
3. Submit the self-contained Skill PR with its tests and evaluation fixtures.
4. Publish the externally installable Action and read-only MCP package only after
   the public repository, trusted-publishing identity, and release provenance are in
   place.
5. Propose native metadata code only after maintainers agree on entity ownership,
   influence semantics, cardinality, and retention.

This sequence avoids flooding DataHub with overlapping speculative changes. The
Skill remains useful with DataHub projections alone, the external package proves the
runtime contract, and the RFC asks DataHub to own only the generic metadata
primitive.
