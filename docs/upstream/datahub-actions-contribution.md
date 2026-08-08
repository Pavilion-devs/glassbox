# DataHub Actions ecosystem package

**Status:** installable external plugin; core-upstream boundary audited
**Audit baseline:** `datahub-project/datahub` commit `217dd98` on 2026-08-06
**Plugin entry point:** `glassbox_invalidation`

GlassBox Decision Invalidation is packaged through DataHub Actions' public Python
plugin mechanism. Installing `glassbox-core` with its Actions and DataHub extras
registers:

```text
datahub_actions.action.plugins
glassbox_invalidation = glassbox_invalidation.datahub_action:GlassBoxInvalidationAction
```

This is a real standalone ecosystem integration, not a source-tree patch or a
hard-coded demo response. The same installed entry point drove the live Kafka
commit-failure recovery and independent PostgreSQL Queue visibility/ack recovery,
including incident, quarantine, owner routing, and direct-readback proof.

## Why this is external first

The current DataHub repository places core Actions under
`datahub-actions/src/datahub_actions/plugin/action`, registers them in the
`datahub_actions.action.plugins` group, and requires unit tests plus a deduplication
case for inclusion. Its custom-action guide also supports separately installed
Python packages and fully qualified action classes.

GlassBox is broadly useful, but its trust contract includes a versioned DBOM,
cryptographic verification, deterministic materiality, durable reverse indexes,
transactional outboxes, replay boundaries, and optional PostgreSQL state. Moving all
of those dependencies into the core `acryl-datahub-actions` distribution would make
DataHub maintainers own a specialized policy system before the metadata RFC is
accepted.

The contribution boundary is therefore:

- publish and support the complete Action as an external Apache-2.0 plugin now;
- contribute focused generic framework fixes if live testing reveals them;
- use the metadata RFC to seek agreement on native decision-receipt primitives;
- reconsider core inclusion only if DataHub maintainers want the full invalidation
  policy and persistence contract in the main distribution.

This avoids a large speculative PR while producing something operators can install
and use today.

## Install and preflight

```bash
pip install 'glassbox-core[actions,datahub]'
glassbox-datahub-action inspect-install
glassbox-datahub-action validate-config actions.yml
datahub actions -c actions.yml
```

Use the `postgres` extra for distributed workers:

```bash
pip install 'glassbox-core[actions,datahub,postgres]'
```

The offline doctor performs zero network calls. `inspect-install` proves the entry
point exists exactly once without importing it. `validate-config` parses the pipeline
with safe YAML, applies the same closed Pydantic configuration contract as runtime,
requires DataHub and source blocks, and returns only bounded operational facts. It
never prints tokens, DSNs, webhook credentials, file contents, or validation input.

## Runtime contract

The Action:

1. accepts only real `MetadataChangeLogEvent_v1` envelopes;
2. normalizes supported aspects into a closed `NormalizedChange` model;
3. selects verified receipt candidates without treating missing evidence as safe;
4. applies `glassbox.materiality.v1` without an LLM;
5. stages content-addressed campaigns and writeback obligations transactionally;
6. writes deterministic DataHub incidents and receipt quarantine state twice;
7. directly reads back managed aspects before acknowledging the source event;
8. routes native owners through a separate durable idempotent outbox;
9. performs zero replay, approval, or supersession work.

SQLite is the single-host profile. PostgreSQL 14+ is the multi-worker profile. The
legacy JSONL profile exists only for compatibility and must not be shared across
workers.

## Upstream compatibility evidence

The implementation uses the same current public contracts documented by DataHub:

- `Action.create(config_dict, PipelineContext)`;
- `Action.act(EventEnvelope)` and `Action.close()`;
- `datahub_actions.action.plugins` discovery;
- the typed `MetadataChangeLogEvent_v1` registry envelope;
- the authenticated graph in `PipelineContext`;
- Pydantic v2 configuration.

The project pins its live compatibility target to DataHub Core 1.6.0 and
`acryl-datahub-actions==1.6.0.15`. Forward compatibility with a later DataHub release
must be established by contract tests and a live proof before widening the package
constraint. The current upstream module targets Python 3.10 while GlassBox targets
3.11–3.13; this is a documented support-floor difference, not silently claimed
parity.

The two source authorities are evidenced separately. The
[Kafka report](../compatibility/datahub-1.6.0-kafka-invalidation.live.json) proves
exhausted synchronous commit retries, unchanged broker offset, exact same-offset
redelivery, and recovery commit. The
[pgQueue report](../compatibility/datahub-1.6.0-pgqueue-invalidation.live.json)
proves PostgreSQL lease exclusion, visibility-timeout redelivery, persisted ack
marker, contiguous offset advance, and an empty third restart. Neither report is
used to infer the other transport's behavior.

## Packaging and release checklist

Before publishing a release:

1. Run the complete unit, contract, PostgreSQL, and live DataHub proof matrix.
2. Build the wheel and inspect `entry_points.txt`, packaged schemas, and typed marker
   files.
3. Install the wheel into a clean Python 3.11, 3.12, and 3.13 environment with only
   the requested extras.
4. Run `glassbox-datahub-action inspect-install` and validate every example pipeline.
5. Start DataHub Actions from the installed wheel and run both live source recovery
   proofs with stable consumer-group identity.
6. Generate an SBOM, scan dependencies, sign the wheel, and publish hashes.
7. State the exact DataHub Core, SDK, Actions, PostgreSQL, and Python matrix.
8. Never ship credentials, live traces, local databases, or private receipt stores.

## Upstream references

- [Developing a DataHub Action](https://github.com/datahub-project/datahub/blob/master/docs/actions/guides/developing-an-action.md)
- [Current Actions package entry points](https://github.com/datahub-project/datahub/blob/master/datahub-actions/setup.py)
- [Current Actions lint configuration](https://github.com/datahub-project/datahub/blob/master/datahub-actions/pyproject.toml)
- [Action plugin registry](https://github.com/datahub-project/datahub/blob/master/datahub-actions/src/datahub_actions/action/action_registry.py)
