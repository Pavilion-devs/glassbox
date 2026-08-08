# Release readiness and provenance

**Status:** local release candidate verified; not published
**Package:** `glassbox-core==0.1.0`
**Declared Python:** 3.11–3.13
**DataHub compatibility target:** Core 1.6.0, SDK and Actions 1.6.0.15

The Python distribution carries the portable DBOM verifier, runtime SDK, compiler,
DataHub adapter, invalidation Action, read-only forensic MCP server, deterministic
policy package, machine-auditable agent narration CLI, and replay worker. Optional
dependencies keep framework and ecosystem integrations explicit.

## Release gate

The release automation performs the following checks from a clean checkout:

1. build the wheel and source archive twice with `--no-sources`;
2. require both independent builds to be byte-identical;
3. reject duplicate, absolute, traversal, or backslash archive paths;
4. reject symbolic/hard links and development-tree leakage from the source archive;
5. cap the wheel at 5 MiB and source archive at 10 MiB;
6. match wheel name, version, Python constraint, console scripts, and DataHub Action
   entry point to `pyproject.toml`;
7. verify every wheel `RECORD` SHA-256 digest and size;
8. require the DBOM, signer-trust, runtime-event, replay-bundle, state-transfer
   schemas and every shipped `py.typed` marker;
9. emit sorted SHA-256 checksums, a deterministic release report, and a CycloneDX
   1.6 inventory of the complete `uv.lock` all-extras dependency graph;
10. install the wheel with the DataHub Action, DataHub, MCP, and PostgreSQL extras in
    an isolated environment;
11. run dependency consistency, runtime-package imports, plugin discovery, offline
    pipeline validation, and MCP executable smoke tests.

The source archive uses an explicit allowlist. The console and its dependency tree,
local test caches, virtual environments, private artifacts, traces, databases, and
keys are outside the Python release boundary.

## Local compatibility evidence — 2026-08-06

| Python | Clean wheel install | Dependency check | Runtime imports | Action doctor | MCP executable |
| --- | --- | --- | --- | --- | --- |
| 3.11.15 | Pass | Pass | Pass | Pass | Pass |
| 3.12.13 | Pass | Pass | Pass | Pass | Pass |
| 3.13.13 | Pass | Pass | Pass | Pass | Pass |

The installed extras were `actions,datahub,mcp,postgres`. The Action doctor found
exactly one `datahub_actions.action.plugins` registration under distribution
`glassbox-core`, validated the committed Kafka pipeline with the runtime Pydantic
contract, returned no secret-bearing values, and made zero network calls.

## Pre-publication flagship check — 2026-08-08

The complete causal flagship was rerun against pinned DataHub Core 1.6.0, SDK and
Actions 1.6.0.15, PostgreSQL 16.14, the official DataHub MCP server 0.6.0, and the
GlassBox read-only MCP server. The result was `valid=true` with a fresh material
change campaign, verified DataHub writeback, zero-write completed redelivery,
fingerprint-bound recovery authorization, digest-pinned OCI execution, immutable
supersession, verified incident closure, and unchanged source and replay receipt
Documents.

The unrelated-field control performed zero DataHub writes. Post-run checks found no
transient flagship schema or sandbox container, while GMS, the frontend, Kafka,
OpenSearch, and PostgreSQL remained healthy. The bounded raw-free record is
`release-evidence/prepublication-flagship-check.json`.

This is an untagged local pre-publication check. It does not replace the required
tagged-commit release matrix or claim a draft pull request, package, or release.

Two independent builds were byte-identical. Exact artifact sizes and hashes belong
in the generated `release-report.json` and `SHA256SUMS`, not this source document:
including an archive's digest inside a file contained by that archive would create a
self-referential and unreproducible contract. Any source or metadata change must
regenerate the external evidence.

## Commands

```bash
uv build --no-sources
uv build --no-sources --out-dir reproducibility-dist
uv run python -m scripts.release_evidence \
  --reproducibility-dist reproducibility-dist
```

The generated `release-evidence/` directory contains:

- `SHA256SUMS`;
- `glassbox_core-0.1.0.cdx.json`;
- `release-report.json`.

## Maintainer handoff packet

After the release report is valid, the repository can bind it to the prepared
DataHub Skills contribution without publishing anything:

```bash
python -m scripts.upstream_packet \
  --skills-worktree ../datahub-skills-glassbox \
  --glassbox-root . \
  --output-dir release-evidence/upstream
```

The command verifies the exact target baseline and contribution scope, then writes
an apply-ready patch and a deterministic `upstream-packet.json`. The manifest hashes
the release artifacts, live implementation proofs, maintainer documents, and every
target-repository change; records that no package, release, discussion, or pull
request has been published; and excludes raw prompts and responses. The packet
builder's adversarial unit suite has 21 tests and 98.25% focused coverage.

## Still required before publication

- create or confirm the public source repository and canonical package URLs;
- choose the package registry name and verify that it is available;
- configure PyPI trusted publishing with a protected GitHub environment;
- sign release artifacts through an identity-backed mechanism and attach
  provenance attestations;
- run the live DataHub/Kafka/PostgreSQL proof matrix from the tagged commit;
- publish checksums, SBOM, compatibility matrix, and known limits with the release;
- verify the installed package again from the public registry, not a local wheel;
- never publish from an uncommitted or dirty source tree.

No registry upload, GitHub release, signing identity, or trusted-publishing claim is
made by this document.
