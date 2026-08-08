"""Guarded, idempotent DataHub Core capability probe.

The orchestration is independent of the DataHub SDK so contract behavior can be
tested without pretending a mock proves server compatibility. Only a live report
with direct readback can promote a capability to ``PROVEN``.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from enum import StrEnum
from importlib import metadata
from typing import Any, Protocol
from urllib.parse import urlparse

PINNED_DATAHUB_SERVER_VERSION = "1.6.0"
PINNED_DATAHUB_SDK_VERSION = "1.6.0.15"
INSPECTED_AGENT_REGISTRY_RC_VERSION = "1.6.0.16rc3"
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+[^\s,;]+")
_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(authorization|token|password|secret|api[_-]?key)\s*[:=]\s*([^\s,;]+)"
)
_HOME_PATH_PATTERN = re.compile(r"/(?:Users|home)/[^/\s]+")


class CapabilityStatus(StrEnum):
    """Evidence state for one integration capability."""

    PROVEN = "PROVEN"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"
    UNVERIFIED = "UNVERIFIED"


@dataclass(frozen=True)
class EntitySpec:
    """One deterministic synthetic entity in dependency order."""

    kind: str
    entity_id: str
    expected_urn: str
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProbePlan:
    """Static plan safe to inspect without importing DataHub or making requests."""

    server_version: str
    sdk_version: str
    entities: tuple[EntitySpec, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_version": self.server_version,
            "sdk_version": self.sdk_version,
            "mode": "PLAN_ONLY",
            "entities": [asdict(entity) for entity in self.entities],
        }


@dataclass(frozen=True)
class CapabilityResult:
    """Outcome for one entity emission and direct readback."""

    kind: str
    expected_urn: str
    status: CapabilityStatus
    emitted_urn: str | None
    aspect_names: tuple[str, ...]
    detail: str


@dataclass(frozen=True)
class CapabilityReport:
    """Machine-readable evidence from one probe execution."""

    target: str
    server_version: str
    sdk_version: str
    connection: CapabilityStatus
    results: tuple[CapabilityResult, ...]

    @property
    def valid(self) -> bool:
        return self.connection is CapabilityStatus.PROVEN and all(
            result.status is CapabilityStatus.PROVEN for result in self.results
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "target": self.target,
            "server_version": self.server_version,
            "sdk_version": self.sdk_version,
            "connection": self.connection.value,
            "results": [
                {
                    "kind": result.kind,
                    "expected_urn": result.expected_urn,
                    "status": result.status.value,
                    "emitted_urn": result.emitted_urn,
                    "aspect_names": list(result.aspect_names),
                    "detail": result.detail,
                }
                for result in self.results
            ],
        }


class ProbeBackend(Protocol):
    """Narrow SDK adapter used by the deterministic probe runner."""

    sdk_version: str

    def test_connection(self) -> None: ...

    def emit(self, spec: EntitySpec, emitted_urns: Mapping[str, str]) -> str: ...

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]: ...


def build_probe_plan(*, sdk_version: str = PINNED_DATAHUB_SDK_VERSION) -> ProbePlan:
    """Build the versioned, deterministic DataHub 1.6 compatibility plan."""

    dataset = EntitySpec(
        kind="dataset",
        entity_id="glassbox.probe.orders",
        expected_urn=("urn:li:dataset:(urn:li:dataPlatform:postgres,glassbox.probe.orders,PROD)"),
    )
    model = EntitySpec(
        kind="ml_model",
        entity_id="glassbox.probe.model",
        expected_urn=("urn:li:mlModel:(urn:li:dataPlatform:openai,glassbox.probe.model,PROD)"),
    )
    agent_run = EntitySpec(
        kind="agent_run",
        entity_id="glassbox.probe.run",
        expected_urn="urn:li:dataProcessInstance:0fb35cf48d682d4b105c67218bdd3cf7",
        dependencies=(dataset.kind,),
    )
    tool = EntitySpec(
        kind="api_tool",
        entity_id="glassbox.probe.orders.lookup",
        expected_urn="urn:li:api:glassbox.probe.orders.lookup",
    )
    skill = EntitySpec(
        kind="agent_skill",
        entity_id="glassbox.probe.pricing-analysis",
        expected_urn="urn:li:agentSkill:glassbox.probe.pricing-analysis",
        dependencies=(tool.kind,),
    )
    agent = EntitySpec(
        kind="ai_agent",
        entity_id="glassbox.probe.pricing-agent",
        expected_urn="urn:li:aiAgent:glassbox.probe.pricing-agent",
        dependencies=(dataset.kind, model.kind, tool.kind, skill.kind),
    )
    receipt = EntitySpec(
        kind="receipt_document",
        entity_id="glassbox.probe.receipt",
        expected_urn="urn:li:document:glassbox.probe.receipt",
        dependencies=(dataset.kind, agent_run.kind),
    )
    return ProbePlan(
        server_version=PINNED_DATAHUB_SERVER_VERSION,
        sdk_version=sdk_version,
        entities=(dataset, model, agent_run, tool, skill, agent, receipt),
    )


def build_compatibility_probe_plan(*, sdk_version: str = PINNED_DATAHUB_SDK_VERSION) -> ProbePlan:
    """Build a stable-Core plan using typed Documents for unavailable registry nodes."""

    native = build_probe_plan()
    dataset, model, agent_run = native.entities[:3]
    tool = EntitySpec(
        kind="api_tool_compat",
        entity_id="glassbox.probe.tool.orders.lookup",
        expected_urn="urn:li:document:glassbox.probe.tool.orders.lookup",
        dependencies=(dataset.kind,),
    )
    skill = EntitySpec(
        kind="agent_skill_compat",
        entity_id="glassbox.probe.skill.pricing-analysis",
        expected_urn="urn:li:document:glassbox.probe.skill.pricing-analysis",
        dependencies=(tool.kind,),
    )
    agent = EntitySpec(
        kind="ai_agent_compat",
        entity_id="glassbox.probe.agent.pricing-agent",
        expected_urn="urn:li:document:glassbox.probe.agent.pricing-agent",
        dependencies=(dataset.kind, model.kind, tool.kind, skill.kind),
    )
    receipt = EntitySpec(
        kind="receipt_document",
        entity_id="glassbox.probe.receipt",
        expected_urn="urn:li:document:glassbox.probe.receipt",
        dependencies=(dataset.kind, agent_run.kind, agent.kind),
    )
    return ProbePlan(
        server_version=PINNED_DATAHUB_SERVER_VERSION,
        sdk_version=sdk_version,
        entities=(dataset, model, agent_run, tool, skill, agent, receipt),
    )


class ProbeRunner:
    """Execute each capability twice, then verify it through a direct entity read."""

    def __init__(self, backend: ProbeBackend, *, target: str) -> None:
        self._backend = backend
        self._target = target

    def run(self, plan: ProbePlan) -> CapabilityReport:
        try:
            self._backend.test_connection()
        except Exception as exc:
            blocked = tuple(
                CapabilityResult(
                    kind=spec.kind,
                    expected_urn=spec.expected_urn,
                    status=CapabilityStatus.BLOCKED,
                    emitted_urn=None,
                    aspect_names=(),
                    detail=f"connection failed: {_safe_exception_detail(exc)}",
                )
                for spec in plan.entities
            )
            return CapabilityReport(
                target=self._target,
                server_version=plan.server_version,
                sdk_version=self._backend.sdk_version,
                connection=CapabilityStatus.FAILED,
                results=blocked,
            )

        results: list[CapabilityResult] = []
        emitted_urns: dict[str, str] = {}
        statuses: dict[str, CapabilityStatus] = {}
        for spec in plan.entities:
            failed_dependencies = tuple(
                dependency
                for dependency in spec.dependencies
                if statuses.get(dependency) is not CapabilityStatus.PROVEN
            )
            if failed_dependencies:
                result = CapabilityResult(
                    kind=spec.kind,
                    expected_urn=spec.expected_urn,
                    status=CapabilityStatus.BLOCKED,
                    emitted_urn=None,
                    aspect_names=(),
                    detail="blocked by: " + ", ".join(failed_dependencies),
                )
            else:
                result = self._probe_entity(spec, emitted_urns)
            results.append(result)
            statuses[spec.kind] = result.status
            if result.status is CapabilityStatus.PROVEN and result.emitted_urn is not None:
                emitted_urns[spec.kind] = result.emitted_urn

        return CapabilityReport(
            target=self._target,
            server_version=plan.server_version,
            sdk_version=self._backend.sdk_version,
            connection=CapabilityStatus.PROVEN,
            results=tuple(results),
        )

    def _probe_entity(self, spec: EntitySpec, emitted_urns: Mapping[str, str]) -> CapabilityResult:
        try:
            first_urn = self._backend.emit(spec, emitted_urns)
            second_urn = self._backend.emit(spec, emitted_urns)
            if first_urn != second_urn:
                raise RuntimeError(f"non-idempotent URNs: {first_urn!r} then {second_urn!r}")
            if first_urn != spec.expected_urn:
                raise RuntimeError(f"emitted URN {first_urn!r} did not equal {spec.expected_urn!r}")
            aspects = self._backend.direct_read_aspects(first_urn)
            if not aspects:
                raise RuntimeError("direct read returned no persisted aspects")
        except Exception as exc:
            return CapabilityResult(
                kind=spec.kind,
                expected_urn=spec.expected_urn,
                status=CapabilityStatus.FAILED,
                emitted_urn=None,
                aspect_names=(),
                detail=_safe_exception_detail(exc),
            )
        return CapabilityResult(
            kind=spec.kind,
            expected_urn=spec.expected_urn,
            status=CapabilityStatus.PROVEN,
            emitted_urn=first_urn,
            aspect_names=aspects,
            detail="same deterministic URN emitted twice and directly read back",
        )


class DataHubSdkBackend:  # pragma: no cover - exercised only by the live integration job
    """Pinned acryl-datahub adapter. Importing it is deferred until live execution."""

    def __init__(self, *, server: str, token: str | None, expected_sdk_version: str) -> None:
        from datahub.api.entities.dataprocess.dataprocess_instance import DataProcessInstance
        from datahub.ingestion.graph.client import DataHubGraph
        from datahub.ingestion.graph.config import DatahubClientConfig
        from datahub.metadata.urns import DatasetUrn
        from datahub.sdk.dataset import Dataset
        from datahub.sdk.document import Document
        from datahub.sdk.main_client import DataHubClient
        from datahub.sdk.mlmodel import MLModel

        graph = DataHubGraph(config=DatahubClientConfig(server=server, token=token))
        self._graph = graph
        self._client = DataHubClient(graph=graph)
        self._DataProcessInstance = DataProcessInstance
        self._DatasetUrn = DatasetUrn
        self._Dataset = Dataset
        self._Document = Document
        self._MLModel = MLModel
        self._expected_sdk_version = expected_sdk_version
        self.sdk_version = metadata.version("acryl-datahub")

    def test_connection(self) -> None:
        self._graph.test_connection()
        if self.sdk_version != self._expected_sdk_version:
            raise RuntimeError(
                f"SDK drift: expected {self._expected_sdk_version}, found {self.sdk_version}"
            )

    def emit(self, spec: EntitySpec, emitted_urns: Mapping[str, str]) -> str:
        if spec.kind == "dataset":
            dataset_entity = self._Dataset(
                platform="postgres",
                name=spec.entity_id,
                schema=[
                    ("order_id", "varchar(64)", "Synthetic capability-probe identifier."),
                    ("revenue", "decimal(18,2)", "Synthetic revenue for field lineage."),
                ],
            )
            self._client.entities.upsert(dataset_entity)
            return str(dataset_entity.urn)
        if spec.kind == "ml_model":
            model_entity = self._MLModel(
                id=spec.entity_id,
                name="GlassBox Probe Model",
                platform="openai",
                description="Synthetic model emitted only to verify DataHub Core compatibility.",
            )
            self._client.entities.upsert(model_entity)
            return str(model_entity.urn)
        if spec.kind == "agent_run":
            run_entity = self._DataProcessInstance(
                id=spec.entity_id,
                orchestrator="glassbox",
                subtype="AI Agent Run",
                properties={
                    "glassbox.receipt_spec": "0.1.0",
                    "glassbox.evidence_state": "OBSERVED",
                },
                inlets=[self._DatasetUrn.from_string(emitted_urns["dataset"])],
            )
            for proposal in run_entity.generate_mcp(
                created_ts_millis=1785974400000,
                materialize_iolets=False,
            ):
                self._graph.emit(proposal)
            return str(run_entity.urn)
        if spec.kind == "api_tool":
            _, _, api_class, api_param_class = self._agent_registry_classes()
            return str(
                api_class(
                    id=spec.entity_id,
                    name="orders_lookup",
                    subtypes=["MCP_TOOL"],
                    description="Read synthetic order aggregates for the capability probe.",
                    parameters=[
                        api_param_class(name="order_id", data_type="string", required=True)
                    ],
                    returns=[api_param_class(name="order", data_type="object")],
                ).emit(self._graph)
            )
        if spec.kind == "agent_skill":
            _, skill_class, _, _ = self._agent_registry_classes()
            return str(
                skill_class(
                    id=spec.entity_id,
                    name="GlassBox Pricing Analysis",
                    description="Synthetic skill for runtime-provenance capability testing.",
                    instructions=(
                        "Read the synthetic orders asset and produce a digest-only result."
                    ),
                    required_tools=[emitted_urns["api_tool"]],
                ).emit(self._graph)
            )
        if spec.kind == "ai_agent":
            agent_class, _, _, _ = self._agent_registry_classes()
            return str(
                agent_class(
                    id=spec.entity_id,
                    name="GlassBox Probe Agent",
                    description="Synthetic external agent used by the GlassBox capability probe.",
                    instructions="Exercise registration and lineage without external mutations.",
                    skills=[emitted_urns["agent_skill"]],
                    tools=[emitted_urns["api_tool"]],
                    models=[emitted_urns["ml_model"]],
                    consumes_datasets=[emitted_urns["dataset"]],
                    platform="glassbox",
                ).emit(self._graph)
            )
        if spec.kind == "api_tool_compat":
            return self._emit_compatibility_document(
                spec,
                title="GlassBox Probe Tool: orders.lookup",
                native_entity_type="api",
                references={"glassbox.dataset_urn": emitted_urns["dataset"]},
                related_assets=[emitted_urns["dataset"]],
            )
        if spec.kind == "agent_skill_compat":
            return self._emit_compatibility_document(
                spec,
                title="GlassBox Probe Skill: Pricing Analysis",
                native_entity_type="agentSkill",
                references={"glassbox.tool_urn": emitted_urns["api_tool_compat"]},
                related_assets=[],
            )
        if spec.kind == "ai_agent_compat":
            return self._emit_compatibility_document(
                spec,
                title="GlassBox Probe Agent: Pricing Agent",
                native_entity_type="aiAgent",
                references={
                    "glassbox.dataset_urn": emitted_urns["dataset"],
                    "glassbox.model_urn": emitted_urns["ml_model"],
                    "glassbox.tool_urn": emitted_urns["api_tool_compat"],
                    "glassbox.skill_urn": emitted_urns["agent_skill_compat"],
                },
                related_assets=[emitted_urns["dataset"]],
            )
        if spec.kind == "receipt_document":
            agent_urn = emitted_urns.get("ai_agent") or emitted_urns.get("ai_agent_compat")
            document_entity = self._Document.create_document(
                id=spec.entity_id,
                title="GlassBox synthetic decision receipt",
                text=(
                    "Capability-probe receipt summary. No prompt, model output, credential, "
                    "or customer data is stored in this document."
                ),
                subtype="Agent Decision Receipt",
                show_in_global_context=False,
                related_assets=[emitted_urns["dataset"]],
                custom_properties={
                    "glassbox.spec_version": "0.1.0",
                    "glassbox.evidence_state": "OBSERVED",
                    "glassbox.run_urn": emitted_urns["agent_run"],
                    **({"glassbox.agent_urn": agent_urn} if agent_urn else {}),
                },
            )
            self._client.entities.upsert(document_entity)
            return str(document_entity.urn)
        raise ValueError(f"unsupported probe entity kind: {spec.kind}")

    def _emit_compatibility_document(
        self,
        spec: EntitySpec,
        *,
        title: str,
        native_entity_type: str,
        references: Mapping[str, str],
        related_assets: list[str],
    ) -> str:
        document = self._Document.create_document(
            id=spec.entity_id,
            title=title,
            text=(
                "Synthetic GlassBox capability-probe registry projection. This is an "
                "explicit compatibility representation, not a native Agent Registry entity."
            ),
            subtype=f"GlassBox {native_entity_type} Compatibility",
            show_in_global_context=True,
            related_assets=related_assets,
            custom_properties={
                "glassbox.spec_version": "0.1.0",
                "glassbox.compatibility_mode": "document-projection",
                "glassbox.native_entity_type": native_entity_type,
                "glassbox.compatibility_reason": "core-v1.6.0-entity-absent",
                "glassbox.canonical_id": spec.entity_id,
                **dict(references),
            },
        )
        self._client.entities.upsert(document)
        return str(document.urn)

    @staticmethod
    def _agent_registry_classes() -> tuple[Any, Any, Any, Any]:
        try:
            from datahub.api.entities.agent.agent import Agent
            from datahub.api.entities.agent.agent_skill import AgentSkill
            from datahub.api.entities.agent.api import Api, ApiParam
        except ModuleNotFoundError as exc:
            raise RuntimeError(
                "Agent Registry SDK is absent from stable acryl-datahub 1.6.0.15; "
                "the documented modules first appear in 1.6.0.16rc3"
            ) from exc
        return Agent, AgentSkill, Api, ApiParam

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        response = self._graph.get_entity_raw(urn)
        aspects = response.get("aspects")
        if not isinstance(aspects, dict):
            return ()
        return tuple(sorted(name for name, value in aspects.items() if value is not None))


def validate_probe_target(server: str, *, allow_remote: bool) -> str:
    """Resolve and constrain the exact server before any live mutation."""

    parsed = urlparse(server)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("DataHub server must be an absolute http(s) URL")
    if parsed.username or parsed.password:
        raise ValueError("credentials must not be embedded in the DataHub server URL")
    if parsed.query or parsed.fragment:
        raise ValueError("DataHub server URL must not contain a query or fragment")
    if not allow_remote and parsed.hostname not in _LOCAL_HOSTS:
        raise ValueError("remote DataHub target requires --allow-remote")
    return server.rstrip("/")


def validate_probe_sdk_version(requested: str, *, allow_prerelease: bool) -> str:
    """Allow the stable pin or one explicitly inspected Agent Registry release candidate."""

    if requested == PINNED_DATAHUB_SDK_VERSION:
        return requested
    if requested != INSPECTED_AGENT_REGISTRY_RC_VERSION:
        raise ValueError(
            "unsupported capability-probe SDK version; expected "
            f"{PINNED_DATAHUB_SDK_VERSION} or {INSPECTED_AGENT_REGISTRY_RC_VERSION}"
        )
    if not allow_prerelease:
        raise ValueError("prerelease DataHub SDK requires --allow-prerelease-sdk")
    return requested


def _safe_exception_detail(exc: Exception) -> str:
    """Preserve actionable failures while removing common secret and home-path forms."""

    message = str(exc)
    message = _BEARER_PATTERN.sub("Bearer [REDACTED]", message)
    message = _CREDENTIAL_PATTERN.sub(lambda match: f"{match.group(1)}=[REDACTED]", message)
    message = _HOME_PATH_PATTERN.sub("$HOME", message)
    return f"{type(exc).__name__}: {message}"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-datahub-probe")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("plan", help="print deterministic entities without importing DataHub")
    live = subparsers.add_parser("live", help="probe native entities against Core")
    compatibility_live = subparsers.add_parser(
        "compatibility-live",
        help="probe stable-Core typed Document projections for unavailable registry entities",
    )
    for live_parser in (live, compatibility_live):
        _add_live_arguments(live_parser)
    return parser


def _add_live_arguments(live: argparse.ArgumentParser) -> None:
    live.add_argument(
        "--server",
        default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"),
    )
    live.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    live.add_argument("--allow-live", action="store_true", required=True)
    live.add_argument("--allow-remote", action="store_true")
    live.add_argument("--expected-sdk-version", default=PINNED_DATAHUB_SDK_VERSION)
    live.add_argument("--allow-prerelease-sdk", action="store_true")
    live.add_argument("--json", action="store_true", dest="json_output")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "plan":
        plan = build_probe_plan()
        print(json.dumps(plan.to_dict(), indent=2, sort_keys=True))
        return 0

    try:
        server = validate_probe_target(args.server, allow_remote=args.allow_remote)
        sdk_version = validate_probe_sdk_version(
            args.expected_sdk_version,
            allow_prerelease=args.allow_prerelease_sdk,
        )
        plan = (
            build_compatibility_probe_plan(sdk_version=sdk_version)
            if args.command == "compatibility-live"
            else build_probe_plan(sdk_version=sdk_version)
        )
        backend = DataHubSdkBackend(
            server=server,
            token=args.token,
            expected_sdk_version=sdk_version,
        )
        report = ProbeRunner(backend, target=server).run(plan)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        print(f"glassbox-datahub-probe: {exc}", file=sys.stderr)
        return 2

    if args.json_output:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"DataHub capability probe: {'PROVEN' if report.valid else 'FAILED'}")
        for result in report.results:
            print(f"- {result.kind}: {result.status.value} — {result.detail}")
    return 0 if report.valid else 1


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point
    raise SystemExit(main())
