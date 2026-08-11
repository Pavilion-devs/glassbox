"""One-command live proof of the complete DataHub-native GlassBox recovery loop."""

from __future__ import annotations

import argparse
import asyncio
import copy
import hashlib
import json
import os
import shutil
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from examples.deterministic_pricing_agent import (
    _synthetic_order_aggregate,
    corrected_pricing_input,
)
from examples.end_to_end_dual_mcp_forensics import (
    DATASET_URN,
    EXPECTED_NATIVE_TYPE,
    OFFICIAL_DATAHUB_MCP_PACKAGE,
    OFFICIAL_DATAHUB_MCP_VERSION,
    _datahub_version,
    _query_both_servers,
)
from examples.end_to_end_invalidation import (
    CHANGE_TIME_MS,
    FIELD_PATH,
    FIELD_URN,
    _emit_schema,
    _mcl,
    _schema,
)
from examples.end_to_end_receipt import (
    build_signed_receipt,
    demo_signer_trust_policy,
    demo_signing_key,
)
from examples.pricing_policy import apply_replayable_pricing_policy
from psycopg import sql

from glassbox.redaction import digest_value
from glassbox_compiler import LiveReceiptPipeline, VerifiedURNResolver
from glassbox_datahub import (
    DataHubInvalidationBackend,
    DataHubReceiptBackend,
    DataHubRecoveryClosureBackend,
    DataHubSupersessionBackend,
    ReceiptEmitter,
    RecoveryClosureEmitter,
    SupersessionEmitter,
)
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_dbom import SigningKey, signing_key_fingerprint
from glassbox_dbom.canonical import canonicalize
from glassbox_forensics import DualMCPExpectation
from glassbox_invalidation import OutboxStatus, TransactionalInvalidationAction
from glassbox_invalidation.datahub_action import (
    GlassBoxInvalidationAction,
    GlassBoxInvalidationActionConfig,
)
from glassbox_invalidation.postgres_store import PostgresInvalidationStore
from glassbox_policy import (
    FieldCoverage,
    FieldLineageProof,
    ImpactState,
    SemanticPolicyRegistry,
    pricing_recommendation_policy_v1,
)
from glassbox_replay import (
    ActionInputReplacement,
    ContainerCapabilityRunner,
    ContainerIsolationProfile,
    ContextReplacement,
    ProcessRunner,
    ReadOnlyCapability,
    ReadOnlyReplayExecutor,
    ReplayActionInput,
    ReplayContextObservation,
    ReplayExecutionInputs,
    ReplayMode,
    ReplaySupplement,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
    build_replay_bundle,
    build_replay_diff,
    build_replay_receipt,
    create_recovery_closure_record,
    create_supersession_record,
    issue_recovery_authorization,
    plan_replay,
    verify_recovery_authorization,
)

PROOF_DATE = "2026-08-08"
CUSTOMER_ID = "synthetic-live-customer"
CORRECTED_AVERAGE_ORDER_VALUE = 62
EVALUATED_AT = "2026-08-08T12:00:00Z"
AUTHORIZATION_EXPIRES_AT = "2026-08-08T13:00:00Z"
REPLAY_STARTED_AT = "2026-08-08T12:01:00Z"
REPLAY_ENDED_AT = "2026-08-08T12:01:01Z"
SUPERSESSION_CREATED_AT = "2026-08-08T12:02:00Z"
INCIDENT_CLOSED_AT = "2026-08-08T12:03:00Z"
_BEFORE_TIME_MS = CHANGE_TIME_MS - 7_200_000
_UNRELATED_TIME_MS = CHANGE_TIME_MS - 3_600_000
_OBSERVATION_AUTHORITY = "glassbox.synthetic-orders-direct-read.v1"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-flagship")
    parser.add_argument("--server", default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    parser.add_argument("--state-postgres-dsn-env", default="GLASSBOX_STATE_POSTGRES_DSN")
    parser.add_argument(
        "--state-postgres-schema",
        default=None,
        help="Explicit state schema; defaults to an isolated random proof schema.",
    )
    parser.add_argument(
        "--keep-state-schema",
        action="store_true",
        help="Retain the proven PostgreSQL state for a live operator console.",
    )
    parser.add_argument("--uvx", type=Path, default=None)
    parser.add_argument(
        "--sandbox-image-digest",
        required=True,
        help="Exact sha256 Docker image ID built from Dockerfile.replay-sandbox.",
    )
    parser.add_argument(
        "--proof-run-offset-ms",
        type=int,
        default=0,
        help="Non-negative deterministic offset for reruns against a non-empty DataHub instance.",
    )
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    return parser


def _drop_schema(dsn: str, schema: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
        )


def _entity_digest(graph: DataHubGraph, urn: str) -> str:
    entity = graph.get_entity_raw(urn)
    if not isinstance(entity, Mapping) or not entity.get("aspects"):
        raise RuntimeError(f"DataHub direct read returned no aspects for {urn}")
    return hashlib.sha256(canonicalize(entity)).hexdigest()


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _digest_value(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, Mapping) or selected.get("algorithm") != "sha256":
        raise RuntimeError(f"{key} is not a SHA-256 commitment")
    digest = selected.get("value")
    if not isinstance(digest, str):
        raise RuntimeError(f"{key} is missing its digest value")
    return digest


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise RuntimeError(f"{key} must be a non-empty string")
    return selected


def _inventory(receipt: Mapping[str, Any]) -> ResourceInventory:
    agent = receipt["agent"]
    workflow = receipt["workflow"]
    if not isinstance(agent, Mapping) or not isinstance(workflow, Mapping):
        raise RuntimeError("receipt component pins are invalid")
    resources = [
        ResourceAvailability(
            ResourceKind.AGENT,
            _text(agent, "id"),
            _text(agent, "version"),
            source_digest=_digest_value(agent, "source_digest"),
        ),
        ResourceAvailability(
            ResourceKind.WORKFLOW,
            _text(workflow, "id"),
            _text(workflow, "version"),
        ),
    ]
    for kind, key in ((ResourceKind.MODEL, "models"), (ResourceKind.SKILL, "skills")):
        selected = receipt[key]
        if not isinstance(selected, list):
            raise RuntimeError(f"{key} must be a list")
        for item in selected:
            if not isinstance(item, Mapping):
                raise RuntimeError(f"{key} contains an invalid pin")
            resources.append(
                ResourceAvailability(
                    kind,
                    _text(item, "id"),
                    _text(item, "version"),
                    source_digest=_digest_value(item, "source_digest"),
                )
            )
    tools = receipt["tools"]
    if not isinstance(tools, list):
        raise RuntimeError("tools must be a list")
    for tool in tools:
        if not isinstance(tool, Mapping):
            raise RuntimeError("tools contains an invalid pin")
        resources.append(
            ResourceAvailability(
                ResourceKind.TOOL,
                _text(tool, "id"),
                _text(tool, "version"),
                source_digest=_digest_value(tool, "source_digest"),
                schema_digest=_digest_value(tool, "schema_digest"),
            )
        )
    return ResourceInventory(tuple(resources))


def _action_report(plugin: GlassBoxInvalidationAction, envelope: Any) -> Any:
    if not plugin.act(envelope) or len(plugin.last_reports) != 1:
        raise RuntimeError("DataHub Action did not return exactly one campaign")
    return plugin.last_reports[0]


def _replay_artifacts(
    source_receipt: Mapping[str, Any],
    task: Any,
    *,
    signing_key: SigningKey,
    sandbox_image_digest: str,
    process_runner: ProcessRunner | None = None,
    docker_executable: str | None = None,
) -> tuple[Any, ...]:
    evidence = source_receipt["evidence"]
    actions = source_receipt["actions"]
    tools = source_receipt["tools"]
    if not (
        isinstance(evidence, list)
        and len(evidence) == 1
        and isinstance(evidence[0], Mapping)
        and isinstance(actions, list)
        and len(actions) == 1
        and isinstance(actions[0], Mapping)
        and isinstance(tools, list)
        and len(tools) == 1
        and isinstance(tools[0], Mapping)
    ):
        raise RuntimeError("flagship receipt requires one evidence item, action, and tool")
    evidence_id = _text(evidence[0], "evidence_id")
    action_id = _text(actions[0], "action_id")
    corrected_input = corrected_pricing_input(
        CUSTOMER_ID,
        average_order_value=CORRECTED_AVERAGE_ORDER_VALUE,
    )
    replay_input = {"customer_id": CUSTOMER_ID, "recovery": "corrected-context"}
    bundle_key = SigningKey("glassbox-live-replay-bundle", Ed25519PrivateKey.generate())
    bundle = build_replay_bundle(
        source_receipt,
        mode=ReplayMode.CORRECTED,
        supplement=ReplaySupplement(
            input_digest=digest_value(replay_input),
            input_reference="artifact://glassbox-flagship/recovery-input",
            feature_flags_digest=_digest("glassbox.demo.pricing-policy:0.2.0"),
        ),
        context_replacements=(
            ContextReplacement(
                evidence_id,
                digest_value(corrected_input),
                _OBSERVATION_AUTHORITY,
            ),
        ),
        action_input_replacements=(
            ActionInputReplacement(
                action_id,
                digest_value(corrected_input),
                (evidence_id,),
                _OBSERVATION_AUTHORITY,
            ),
        ),
        signing_keys=(bundle_key,),
    )

    operator_key = SigningKey("glassbox-live-recovery-operator", Ed25519PrivateKey.generate())
    authorization = issue_recovery_authorization(
        task,
        source_receipt,
        bundle,
        issuer="urn:li:corpuser:glassbox-recovery-operator",
        issued_at=EVALUATED_AT,
        expires_at=AUTHORIZATION_EXPIRES_AT,
        signing_keys=(operator_key,),
    )
    authorization_verification = verify_recovery_authorization(
        authorization,
        task,
        source_receipt,
        bundle,
        evaluated_at=EVALUATED_AT,
        trusted_signer_fingerprints={
            operator_key.key_id: signing_key_fingerprint(operator_key),
        },
    )
    if not authorization_verification.valid:
        raise RuntimeError("campaign recovery authorization did not verify")

    inventory = _inventory(source_receipt)
    plan = plan_replay(
        bundle,
        source_receipt=source_receipt,
        inventory=inventory,
        evaluated_at=EVALUATED_AT,
    )
    tool = tools[0]
    isolation_profile = ContainerIsolationProfile(
        sandbox_image_digest,
        ("python", "-B", "/capability/worker.py"),
        _digest_value(tool, "source_digest"),
        _digest_value(tool, "schema_digest"),
    )
    capability = ReadOnlyCapability(
        _text(tool, "id"),
        _text(tool, "version"),
        _digest_value(tool, "source_digest"),
        _digest_value(tool, "schema_digest"),
        f"glassbox.flagship.oci-read-only-capability:{sandbox_image_digest}",
        ContainerCapabilityRunner(
            isolation_profile,
            docker_executable=docker_executable,
            process_runner=process_runner,
        ),
    )
    observation = ReplayContextObservation(
        evidence_id,
        digest_value(corrected_input),
        _OBSERVATION_AUTHORITY,
        "4444444444444444",
        REPLAY_STARTED_AT,
        "TOOL_RESULT",
    )
    inputs = ReplayExecutionInputs(
        replay_input,
        (ReplayActionInput(action_id, corrected_input),),
        (observation,),
    )
    execution = ReadOnlyReplayExecutor((capability,)).execute(
        bundle,
        plan,
        source_receipt=source_receipt,
        inventory=inventory,
        inputs=inputs,
        output_projector=lambda _input, outputs: outputs[action_id],
        run_id="glassbox-live-pricing-replay-001",
        trace_id="fedcba9876543210fedcba9876543210",
        started_at=REPLAY_STARTED_AT,
        ended_at=REPLAY_ENDED_AT,
    )
    replay_receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source_receipt,
        inputs=inputs,
        signing_keys=(signing_key,),
    )

    source_input = _synthetic_order_aggregate(CUSTOMER_ID)
    source_input["average_order_value"] = str(source_input["average_order_value"])
    source_output = apply_replayable_pricing_policy(source_input)
    output = source_receipt["output"]
    if not isinstance(output, Mapping) or digest_value(source_output) != _digest_value(
        output, "digest"
    ):
        raise RuntimeError("source output cannot be reproduced from its pinned capability")
    semantic_policy = pricing_recommendation_policy_v1()
    diff = build_replay_diff(
        source_receipt,
        replay_receipt,
        source_output=source_output,
        replay_output=execution.output,
        semantic_policy_id=semantic_policy.policy_id,
        semantic_registry=SemanticPolicyRegistry.trust((semantic_policy,)),
    )
    supersession = create_supersession_record(
        source_receipt,
        replay_receipt,
        execution=execution,
        plan=plan,
        diff=diff,
        created_at=SUPERSESSION_CREATED_AT,
    )
    closure = create_recovery_closure_record(
        authorization,
        task,
        source_receipt,
        replay_receipt,
        bundle,
        execution=execution,
        supersession=supersession,
        evaluated_at=EVALUATED_AT,
        trusted_signer_fingerprints={
            operator_key.key_id: signing_key_fingerprint(operator_key),
        },
        closed_at=INCIDENT_CLOSED_AT,
    )
    return (
        authorization,
        authorization_verification,
        bundle,
        plan,
        execution,
        replay_receipt,
        diff,
        supersession,
        closure,
    )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.proof_run_offset_ms < 0:
        raise ValueError("proof-run-offset-ms must be non-negative")
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    dsn = os.getenv(args.state_postgres_dsn_env)
    if dsn is None or not dsn:
        raise ValueError("configured PostgreSQL DSN environment variable is unset")
    uvx = args.uvx or (Path(found) if (found := shutil.which("uvx")) else None)
    if uvx is None or not uvx.is_file():
        raise ValueError("uvx is required for the pinned official DataHub MCP proof")

    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=args.token))
    graph.test_connection()
    core_version, core_commit = _datahub_version(graph)
    schema = args.state_postgres_schema or f"gbx_flagship_{uuid.uuid4().hex}"
    try:
        before = _schema(native_type="VARCHAR", numeric=False, time_ms=_BEFORE_TIME_MS)
        unrelated = _schema(
            native_type="VARCHAR",
            numeric=False,
            time_ms=_UNRELATED_TIME_MS,
            include_unrelated=True,
        )
        corrected_schema = _schema(
            native_type=EXPECTED_NATIVE_TYPE,
            numeric=True,
            time_ms=CHANGE_TIME_MS + args.proof_run_offset_ms,
            include_unrelated=True,
        )
        _emit_schema(graph, before)

        receipt_backend = DataHubReceiptBackend(server=server, token=args.token)
        receipt_backend.test_connection()
        signing_key = demo_signing_key()
        trust_policy = demo_signer_trust_policy(signing_key)
        source_receipt = build_signed_receipt(
            urn_resolver=VerifiedURNResolver(receipt_backend),
            schema_field_urn=FIELD_URN,
            signing_key=signing_key,
            replay_ready=True,
        )
        source_snapshot = copy.deepcopy(source_receipt)
        store = PostgresInvalidationStore(
            dsn,
            schema=schema,
            signer_trust_policy=trust_policy,
        )
        lineage = FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.flagship-field-lineage.v1",
            wildcard_query=False,
        )
        emitter = ReceiptEmitter(receipt_backend, signer_trust_policy=trust_policy)
        pipeline = LiveReceiptPipeline(store, emitter)
        source_publication = pipeline.publish_compiled(
            source_receipt,
            field_lineage=lineage,
        )
        source_redelivery = pipeline.publish_compiled(
            source_receipt,
            field_lineage=lineage,
        )
        if not (
            source_publication.valid
            and source_redelivery.valid
            and not source_redelivery.datahub_write_performed
        ):
            raise RuntimeError("source receipt publication was not idempotent")

        with TemporaryDirectory(prefix="glassbox-flagship-") as temporary:
            trust_policy_path = Path(temporary) / "trusted-signers.json"
            trust_policy_path.write_text(
                json.dumps(trust_policy.to_dict(), sort_keys=True),
                encoding="utf-8",
            )
            trust_policy_path.chmod(0o600)
            invalidation_backend = DataHubInvalidationBackend.from_graph(graph)
            invalidation_backend.test_connection()
            action = TransactionalInvalidationAction(
                invalidation_backend,
                store,
                worker_id="flagship-live-action",
            )
            plugin = GlassBoxInvalidationAction(
                GlassBoxInvalidationActionConfig(
                    state_postgres_dsn_env=args.state_postgres_dsn_env,
                    state_postgres_schema=schema,
                    signer_trust_policy_path=trust_policy_path,
                    worker_id="flagship-live-action",
                ),
                action,
                store,
            )

            _emit_schema(graph, unrelated)
            negative_envelope = _mcl(before, unrelated, event_time_ms=_UNRELATED_TIME_MS)
            negative = _action_report(plugin, negative_envelope)
            negative_redelivery = _action_report(plugin, negative_envelope)
            negative_assessment = negative.campaign.assessments[0]
            if not (
                negative.valid
                and negative_redelivery.valid
                and negative.emissions == 0
                and negative_redelivery.emissions == 0
                and negative_assessment.state is ImpactState.UNAFFECTED
                and negative.campaign.campaign_id == negative_redelivery.campaign.campaign_id
            ):
                raise RuntimeError("unrelated-field negative control failed")

            _emit_schema(graph, corrected_schema)
            material_envelope = _mcl(
                unrelated,
                corrected_schema,
                event_time_ms=CHANGE_TIME_MS + args.proof_run_offset_ms,
            )
            stale = _action_report(plugin, material_envelope)
            stale_redelivery = _action_report(plugin, material_envelope)
            stale_assessment = stale.campaign.assessments[0]
            if not (
                stale.valid
                and stale.emissions == 2
                and stale_redelivery.valid
                and stale_redelivery.emissions == 0
                and stale_redelivery.reused_completion
                and stale_assessment.state is ImpactState.STALE
                and stale.campaign.campaign_id == stale_redelivery.campaign.campaign_id
            ):
                raise RuntimeError("material invalidation campaign failed")
            task = store.get_task(stale.campaign.campaign_id)
            if (
                task is None
                or task.status is not OutboxStatus.COMPLETED
                or task.write_evidence is None
                or not task.write_evidence.valid
            ):
                raise RuntimeError("completed campaign evidence is unavailable")

            expectation = DualMCPExpectation(
                dataset_urn=DATASET_URN,
                field_path=FIELD_PATH,
                native_type=EXPECTED_NATIVE_TYPE,
                receipt_id=_text(source_receipt, "receipt_id"),
                document_urn=source_publication.datahub.document_urn,
                campaign_id=stale.campaign.campaign_id,
                incident_urn=stale.campaign.incident_urn,
            )
            mcp_report, mcp_runtime = asyncio.run(
                _query_both_servers(
                    server=server,
                    token=args.token,
                    dsn_environment_name=args.state_postgres_dsn_env,
                    dsn=dsn,
                    schema=schema,
                    trust_policy_path=trust_policy_path,
                    uvx=uvx,
                    expectation=expectation,
                )
            )

        (
            authorization,
            authorization_verification,
            bundle,
            replay_plan,
            execution,
            replay_receipt,
            replay_diff,
            supersession,
            closure,
        ) = _replay_artifacts(
            source_receipt,
            task,
            signing_key=signing_key,
            sandbox_image_digest=args.sandbox_image_digest,
        )
        replay_publication = pipeline.publish_compiled(
            replay_receipt,
            field_lineage=lineage,
        )
        replay_redelivery = pipeline.publish_compiled(
            replay_receipt,
            field_lineage=lineage,
        )
        if not (
            replay_publication.valid
            and replay_redelivery.valid
            and not replay_redelivery.datahub_write_performed
        ):
            raise RuntimeError("replay receipt publication was not idempotent")

        documents_before = {
            source_publication.datahub.document_urn: _entity_digest(
                graph, source_publication.datahub.document_urn
            ),
            replay_publication.datahub.document_urn: _entity_digest(
                graph, replay_publication.datahub.document_urn
            ),
        }
        supersession_backend = DataHubSupersessionBackend(server=server, token=args.token)
        supersession_backend.test_connection()
        supersession_emission = SupersessionEmitter(supersession_backend).emit_verified(
            supersession
        )
        closure_backend = DataHubRecoveryClosureBackend.from_graph(graph)
        closure_backend.test_connection()
        closure_emission = RecoveryClosureEmitter(closure_backend).close_verified(
            closure,
            supersession,
        )
        documents_after = {urn: _entity_digest(graph, urn) for urn in documents_before}
        source_state_unchanged = store.get_receipt(_text(source_receipt, "receipt_id")) == (
            source_snapshot
        )
        documents_unchanged = documents_before == documents_after
        integrity = store.verify_integrity()
        with psycopg.connect(dsn) as connection:
            version_row = connection.execute("SHOW server_version").fetchone()
        if version_row is None:
            raise RuntimeError("PostgreSQL did not return its server version")

        result: dict[str, Any] = {
            "valid": (
                source_publication.valid
                and negative.valid
                and stale.valid
                and authorization_verification.valid
                and replay_plan.execution_permitted
                and execution.valid
                and replay_diff.valid
                and replay_publication.valid
                and supersession.valid
                and supersession_emission.valid
                and closure_emission.valid
                and source_state_unchanged
                and documents_unchanged
            ),
            "scenario": "GLASSBOX_DATAHUB_CAUSAL_RECOVERY",
            "runtime": {
                "proof_date": PROOF_DATE,
                "proof_run_offset_ms": args.proof_run_offset_ms,
                "datahub_core_version": core_version,
                "datahub_core_commit": core_commit,
                "datahub_sdk_version": receipt_backend.sdk_version,
                "official_datahub_mcp_package": OFFICIAL_DATAHUB_MCP_PACKAGE,
                "official_datahub_mcp_package_version": OFFICIAL_DATAHUB_MCP_VERSION,
                **mcp_runtime,
                "postgresql_server_version": version_row[0],
            },
            "source_decision": {
                "receipt_id": _text(source_receipt, "receipt_id"),
                "evidence_count": len(source_receipt["evidence"]),
                "action_count": len(source_receipt["actions"]),
                "resource_pins_complete": True,
                "publication": source_publication.to_dict(),
                "completed_redelivery_datahub_write_performed": (
                    source_redelivery.datahub_write_performed
                ),
            },
            "negative_control": {
                "campaign_id": negative.campaign.campaign_id,
                "finding": negative_assessment.state.value,
                "reason_code": negative_assessment.reason_code,
                "first_delivery_emissions": negative.emissions,
                "redelivery_emissions": negative_redelivery.emissions,
                "datahub_mutation_required": False,
            },
            "invalidation": {
                "campaign_id": stale.campaign.campaign_id,
                "incident_urn": stale.campaign.incident_urn,
                "source_receipt_id": stale_assessment.receipt_id,
                "finding": stale_assessment.state.value,
                "reason_code": stale_assessment.reason_code,
                "matched_evidence_ids": list(stale_assessment.matched_evidence_ids),
                "workflow_status": task.status.value,
                "datahub_writeback_verified": task.write_evidence.valid,
                "first_delivery_emissions": stale.emissions,
                "redelivery_emissions": stale_redelivery.emissions,
                "redelivery_reused_completion": stale_redelivery.reused_completion,
            },
            "dual_mcp_forensics": mcp_report,
            "recovery_authorization": {
                "authorization_id": authorization.authorization_id,
                "campaign_id": authorization.campaign_id,
                "source_receipt_id": authorization.source_receipt_id,
                "bundle_id": authorization.bundle_id,
                "mode": authorization.mode,
                "finding_state": authorization.finding_state,
                "verification": authorization_verification.to_dict(),
            },
            "corrected_replay": {
                "bundle_id": _text(bundle, "bundle_id"),
                "plan_id": replay_plan.plan_id,
                "decision": replay_plan.decision.value,
                "reason_codes": [item.value for item in replay_plan.reason_codes],
                "execution_id": execution.execution_id,
                "execution_status": execution.status,
                "source_history_mutations": execution.source_history_mutations,
                "context_observation_count": len(execution.context_observations),
                "action_input_digest_changed": (
                    source_receipt["actions"][0]["input_digest"]
                    != replay_receipt["actions"][0]["input_digest"]
                ),
                "replay_receipt_id": _text(replay_receipt, "receipt_id"),
                "diff_id": replay_diff.diff_id,
                "semantic_policy_id": replay_diff.semantic.policy_id,
                "semantic_rule_id": replay_diff.semantic.rule_id,
                "semantic_rule_version": replay_diff.semantic.rule_version,
                "semantic_result": replay_diff.semantic.result,
                "semantic_exact_match": replay_diff.semantic.exact_match,
                "structural_change_count": len(replay_diff.structural_changes),
                "publication": replay_publication.to_dict(),
                "completed_redelivery_datahub_write_performed": (
                    replay_redelivery.datahub_write_performed
                ),
                "isolation": execution.actions[0].isolation_attestation.to_dict()
                if execution.actions[0].isolation_attestation is not None
                else None,
            },
            "supersession": supersession_emission.to_dict(),
            "incident_closure": closure_emission.to_dict(),
            "history_preservation": {
                "postgres_source_receipt_unchanged": source_state_unchanged,
                "datahub_receipt_documents_unchanged_after_supersession": (documents_unchanged),
                "direct_entity_digests_before": documents_before,
                "direct_entity_digests_after": documents_after,
            },
            "shared_state": {
                "engine": "PostgreSQL",
                "receipts": integrity.receipts,
                "campaigns": integrity.campaigns,
                "audit_records": integrity.audit_records,
                "state_postgres_schema": schema if args.keep_state_schema else None,
                "dsn_persisted_or_reported": False,
            },
            "privacy": {
                "raw_prompts_returned": False,
                "raw_evidence_returned": False,
                "raw_action_inputs_returned": False,
                "raw_outputs_returned": False,
                "private_keys_returned": False,
                "database_credentials_returned": False,
            },
            "scope": {
                "live_datahub_core": "PROVEN",
                "live_postgresql": "PROVEN",
                "official_datahub_mcp_stdio": "PROVEN",
                "glassbox_mcp_stdio": "PROVEN",
                "real_datahub_mutation_and_direct_readback": "PROVEN",
                "corrected_action_input_execution": "PROVEN",
                "process_level_capability_sandbox": "PROVEN",
                "incident_resolution_after_recovery": "PROVEN",
                "organizational_retention_completeness": "CONFIGURATION_DEPENDENT",
            },
        }
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["valid"] else 1
    finally:
        if not args.keep_state_schema:
            _drop_schema(dsn, schema)


if __name__ == "__main__":
    raise SystemExit(main())
