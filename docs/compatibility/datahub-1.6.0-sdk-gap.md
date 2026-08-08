# Reproduction: Agent Registry tutorial is ahead of the stable 1.6.0 Python wheel

- **Observed:** 2026-08-06
- **Stable package:** `acryl-datahub==1.6.0.15`
- **Matching context package checked:** `datahub-agent-context==1.6.0.15`
- **Preview package inspected:** `acryl-datahub==1.6.0.16rc3`
- **Evidence state:** OBSERVED through live server write and direct read attempts

## Expected

The official DataHub 1.6.0 Agent Registry tutorial imports:

```python
from datahub.api.entities.agent.agent import Agent
from datahub.api.entities.agent.agent_skill import AgentSkill
from datahub.api.entities.agent.api import Api, ApiParam
```

It states that registration works against local DataHub Core.

## Actual stable-wheel result

```text
ModuleNotFoundError: No module named 'datahub.api.entities.agent'
```

The stable wheel contains Dataset, Document, MLModel, and DataProcessInstance APIs,
but neither the `datahub/api/entities/agent/` package nor generated `aiAgent` /
`agentSkill` metadata classes and URNs.

Installing the matching stable `datahub-agent-context` wheel does not change that
result; it contains MCP tools and framework bindings but no registry entity package.

## Preview comparison and live result

The `acryl-datahub==1.6.0.16rc3` wheel was downloaded into an isolated temporary
directory without dependencies. It contains:

```text
datahub/api/entities/agent/agent.py
datahub/api/entities/agent/agent_skill.py
datahub/api/entities/agent/api.py
datahub/metadata/schemas/AIAgentInfo.avsc
datahub/metadata/schemas/AIAgentDependencies.avsc
datahub/metadata/schemas/AgentSkillInfo.avsc
```

The exact preview build was then installed in an isolated Python 3.12 environment
and exercised against the pinned local DataHub Core `v1.6.0` server. Dataset, model,
run, and receipt writes still passed. The first `Api.emit` failed with HTTP 422:

```text
Failed to find entity with name api in EntityRegistry
```

This proves two independent release-alignment gaps: the public 1.6.0 tutorial is
ahead of both the stable 1.6.0 Python wheel and the stable 1.6.0 OSS server metadata
model. The sanitized report is `datahub-1.6.0-agent-registry-rc.live.json`.

## GlassBox handling

- Keep stable `acryl-datahub==1.6.0.15` as the default dependency.
- Probe stable Dataset, MLModel, DataProcessInstance, and Document capabilities
  independently.
- Mark API tool, agent skill, and AI agent checks failed—not unknown—when the stable
  module import is attempted.
- Do not fabricate `aiAgent` URNs on a server whose model support is unproven.
- Keep an explicit preview probe lane for `1.6.0.16rc3`; it accepts only this exact
  inspected build and requires `--allow-prerelease-sdk`.
- Do not claim native Agent Registry support until a server image containing the
  matching `api`, `agentSkill`, and `aiAgent` entity definitions is identified and
  passes the same write-twice/direct-readback test.
- Prepare a focused upstream documentation/packaging issue with this reproduction.

## Primary references

- <https://docs.datahub.com/docs/api/tutorials/agent-registry>
- <https://docs.datahub.com/docs/features/feature-guides/agent-registry>
- <https://pypi.org/project/acryl-datahub/>
- <https://pypi.org/project/datahub-agent-context/>
