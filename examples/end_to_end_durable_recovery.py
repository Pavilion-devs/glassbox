"""Live DataHub/PostgreSQL/OCI recovery with one abrupt process exit per checkpoint."""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, NoReturn

import psycopg
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from datahub.ingestion.graph.client import DataHubGraph
from datahub.ingestion.graph.config import DatahubClientConfig
from examples.deterministic_pricing_agent import (
    _synthetic_order_aggregate,
    corrected_pricing_input,
)
from examples.end_to_end_dual_mcp_forensics import EXPECTED_NATIVE_TYPE, _datahub_version
from examples.end_to_end_flagship import (
    _BEFORE_TIME_MS,
    _OBSERVATION_AUTHORITY,
    _UNRELATED_TIME_MS,
    CORRECTED_AVERAGE_ORDER_VALUE,
    CUSTOMER_ID,
    _action_report,
    _digest,
    _digest_value,
    _drop_schema,
    _entity_digest,
    _inventory,
    _text,
)
from examples.end_to_end_invalidation import (
    CHANGE_TIME_MS,
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
from glassbox_dbom import (
    SigningKey,
    load_signer_trust_policy,
    signing_key_fingerprint,
    signing_key_from_base64url,
)
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
    RecoveryArtifacts,
    RecoveryEffectEvidence,
    RecoveryJob,
    RecoveryOperation,
    RecoveryOrchestrator,
    RecoveryStage,
    ReplayActionInput,
    ReplayContextObservation,
    ReplayExecutionInputs,
    ReplayMode,
    ReplaySupplement,
    build_replay_bundle,
    build_replay_diff,
    build_replay_receipt,
    create_recovery_closure_record,
    create_supersession_record,
    issue_recovery_authorization,
    plan_replay,
    verify_recovery_authorization,
)
from glassbox_replay.datahub_effects import DataHubRecoveryEffects
from glassbox_replay.execution import ReplayExecutionError
from glassbox_replay.postgres_recovery import PostgresRecoveryStore

PROOF_DATE = "2026-08-08"
PROOF_CONTRACT = "glassbox.durable-causal-recovery-crash.v1"
UNCERTAIN_PROOF_CONTRACT = "glassbox.durable-uncertain-completion-crash.v1"
WORKER_REPORT_PREFIX = "GLASSBOX_RECOVERY_WORKER_REPORT="
FAULT_REPORT_PREFIX = "GLASSBOX_RECOVERY_PRECOMMIT_FAULT="
ABRUPT_CHECKPOINT_EXIT_CODE = 86
ABRUPT_PRECOMMIT_EXIT_CODE = 87
REPLAY_SIGNING_KEY_ENV = "GLASSBOX_DURABLE_REPLAY_SIGNING_KEY"
_ROOT = Path(__file__).resolve().parents[1]


@dataclass(frozen=True)
class LiveProofTimeline:
    """A real authorization window with stable artifact offsets inside that window."""

    issued_at: str
    expires_at: str
    evaluated_at: str

    @classmethod
    def now(cls) -> LiveProofTimeline:
        current = datetime.now(UTC).replace(microsecond=0)
        return cls(
            issued_at=_iso(current - timedelta(minutes=10)),
            expires_at=_iso(current + timedelta(hours=1)),
            evaluated_at=_iso(current),
        )


class FlagshipRecoveryExecutor:
    """Build one raw-free artifact set from the exact durable recovery job."""

    def __init__(
        self,
        *,
        signing_key: SigningKey,
        sandbox_image_digest: str,
        trusted_signer_fingerprints: Mapping[str, str],
        process_runner: ProcessRunner | None = None,
        docker_executable: str | None = None,
    ) -> None:
        self._signing_key = signing_key
        self._sandbox_image_digest = sandbox_image_digest
        self._trusted = dict(trusted_signer_fingerprints)
        self._process_runner = process_runner
        self._docker_executable = docker_executable

    def execute(
        self,
        job: RecoveryJob,
        task: Any,
        source_receipt: Mapping[str, Any],
    ) -> RecoveryArtifacts:
        evidence, actions, tools = _single_replay_components(source_receipt)
        evidence_id = _text(evidence, "evidence_id")
        action_id = _text(actions, "action_id")
        corrected_input = corrected_pricing_input(
            CUSTOMER_ID,
            average_order_value=CORRECTED_AVERAGE_ORDER_VALUE,
        )
        replay_input = {"customer_id": CUSTOMER_ID, "recovery": "corrected-context"}
        inventory = _inventory(source_receipt)
        replay_plan = plan_replay(
            job.bundle,
            source_receipt=source_receipt,
            inventory=inventory,
            evaluated_at=_offset(job.authorization.issued_at, seconds=30),
        )
        isolation_profile = ContainerIsolationProfile(
            self._sandbox_image_digest,
            ("python", "-B", "/capability/worker.py"),
            _digest_value(tools, "source_digest"),
            _digest_value(tools, "schema_digest"),
        )
        capability = ReadOnlyCapability(
            _text(tools, "id"),
            _text(tools, "version"),
            _digest_value(tools, "source_digest"),
            _digest_value(tools, "schema_digest"),
            f"glassbox.flagship.oci-read-only-capability:{self._sandbox_image_digest}",
            ContainerCapabilityRunner(
                isolation_profile,
                docker_executable=self._docker_executable,
                process_runner=self._process_runner,
            ),
        )
        inputs = ReplayExecutionInputs(
            replay_input,
            (ReplayActionInput(action_id, corrected_input),),
            (
                ReplayContextObservation(
                    evidence_id,
                    digest_value(corrected_input),
                    _OBSERVATION_AUTHORITY,
                    "5555555555555555",
                    _offset(job.authorization.issued_at, minutes=1),
                    "TOOL_RESULT",
                ),
            ),
        )
        execution = ReadOnlyReplayExecutor((capability,)).execute(
            job.bundle,
            replay_plan,
            source_receipt=source_receipt,
            inventory=inventory,
            inputs=inputs,
            output_projector=lambda _input, outputs: outputs[action_id],
            run_id="glassbox-live-pricing-replay-durable-001",
            trace_id="abcdef0123456789abcdef0123456789",
            started_at=_offset(job.authorization.issued_at, minutes=1),
            ended_at=_offset(job.authorization.issued_at, minutes=1, seconds=1),
        )
        replay_receipt = build_replay_receipt(
            execution,
            job.bundle,
            replay_plan,
            source_receipt=source_receipt,
            inputs=inputs,
            signing_keys=(self._signing_key,),
        )
        source_input = _synthetic_order_aggregate(CUSTOMER_ID)
        source_input["average_order_value"] = str(source_input["average_order_value"])
        source_output = apply_replayable_pricing_policy(source_input)
        output = source_receipt.get("output")
        if not isinstance(output, Mapping) or digest_value(source_output) != _digest_value(
            output, "digest"
        ):
            raise ReplayExecutionError(
                "source output cannot be reproduced from its pinned capability"
            )
        semantic_policy = pricing_recommendation_policy_v1()
        replay_diff = build_replay_diff(
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
            plan=replay_plan,
            diff=replay_diff,
            created_at=_offset(job.authorization.issued_at, minutes=2),
        )
        closure = create_recovery_closure_record(
            job.authorization,
            task,
            source_receipt,
            replay_receipt,
            job.bundle,
            execution=execution,
            supersession=supersession,
            evaluated_at=_offset(job.authorization.issued_at, seconds=30),
            trusted_signer_fingerprints=self._trusted,
            closed_at=_offset(job.authorization.issued_at, minutes=3),
        )
        return RecoveryArtifacts.from_domain(
            execution,
            replay_receipt,
            replay_diff,
            supersession,
            closure,
        )


class CrashBeforePostgresCompletionStore:
    """Fault seam that kills a worker after success but before durable completion."""

    def __init__(
        self,
        store: PostgresRecoveryStore,
        *,
        exit_process: Callable[[int], NoReturn] = os._exit,
    ) -> None:
        self._store = store
        self._exit_process = exit_process

    def get(self, campaign_id: str) -> RecoveryJob | None:
        return self._store.get(campaign_id)

    def claim(
        self,
        campaign_id: str,
        *,
        worker_id: str,
        now_ms: int,
        lease_duration_ms: int,
    ) -> RecoveryJob | None:
        return self._store.claim(
            campaign_id,
            worker_id=worker_id,
            now_ms=now_ms,
            lease_duration_ms=lease_duration_ms,
        )

    def release(self, campaign_id: str, *, worker_id: str, error_type: str) -> None:
        self._store.release(campaign_id, worker_id=worker_id, error_type=error_type)

    def complete_execution(
        self,
        campaign_id: str,
        artifacts: RecoveryArtifacts,
        *,
        worker_id: str,
    ) -> bool:
        del worker_id
        self._abort(
            campaign_id,
            operation=RecoveryOperation.EXECUTE_ISOLATED_REPLAY,
            artifact_or_evidence_id=artifacts.artifact_set_id,
            bound_artifact_id=artifacts.artifact_set_id,
            readback_verified=artifacts.valid,
            emission_count=None,
            write_performed=None,
            execution_id=str(artifacts.execution["execution_id"]),
            isolation_attestation_ids=list(artifacts.closure.isolation_attestation_ids),
        )

    def complete_effect(
        self,
        campaign_id: str,
        evidence: RecoveryEffectEvidence,
        *,
        worker_id: str,
    ) -> bool:
        del worker_id
        self._abort(
            campaign_id,
            operation=evidence.operation,
            artifact_or_evidence_id=evidence.evidence_id,
            bound_artifact_id=evidence.artifact_id,
            readback_verified=evidence.readback_verified and evidence.valid,
            emission_count=evidence.emission_count,
            write_performed=evidence.write_performed,
            execution_id=None,
            isolation_attestation_ids=[],
        )

    def _abort(
        self,
        campaign_id: str,
        *,
        operation: RecoveryOperation,
        artifact_or_evidence_id: str,
        bound_artifact_id: str,
        readback_verified: bool,
        emission_count: int | None,
        write_performed: bool | None,
        execution_id: str | None,
        isolation_attestation_ids: list[str],
    ) -> NoReturn:
        job = self._store.get(campaign_id)
        if job is None or job.lease_operation is not operation:
            raise RuntimeError("pre-commit fault lost the active recovery lease")
        payload = {
            "contract": "glassbox.recovery-precommit-fault.v1",
            "valid": True,
            "pid": os.getpid(),
            "fault_point": "AFTER_SUCCESS_BEFORE_POSTGRES_COMPLETION",
            "operation": operation.value,
            "durable_stage_before": job.stage.value,
            "durable_stage_version_before": job.stage_version,
            "durable_event_count_before": len(self._store.read_events(campaign_id)),
            "attempt_count": job.attempt_count,
            "lease_operation": job.lease_operation.value,
            "lease_expires_at_ms": job.lease_expires_at_ms,
            "artifact_or_evidence_id": artifact_or_evidence_id,
            "bound_artifact_id": bound_artifact_id,
            "readback_verified": readback_verified,
            "emission_count": emission_count,
            "write_performed": write_performed,
            "execution_id": execution_id,
            "isolation_attestation_ids": isolation_attestation_ids,
            "postgres_completion_called": False,
            "raw_content_returned": False,
        }
        print(FAULT_REPORT_PREFIX + json.dumps(payload, sort_keys=True), flush=True)
        self._exit_process(ABRUPT_PRECOMMIT_EXIT_CODE)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-durable-recovery")
    commands = parser.add_subparsers(dest="command", required=True)

    for name, help_text in (
        ("run", "run the committed-checkpoint crash-recovery proof"),
        (
            "run-uncertain",
            "crash after external success but before PostgreSQL completion",
        ),
    ):
        run = commands.add_parser(name, help=help_text)
        _live_arguments(run)
        run.add_argument(
            "--proof-run-offset-ms",
            type=int,
            default=0,
            help="Non-negative offset for reruns against a non-empty DataHub instance.",
        )
        run.add_argument("--python", type=Path, default=Path(sys.executable))
        run.add_argument("--fault-lease-duration-ms", type=int, default=1_000)

    worker = commands.add_parser("worker", help=argparse.SUPPRESS)
    _live_arguments(worker)
    worker.add_argument("--schema", required=True)
    worker.add_argument("--campaign-id", required=True)
    worker.add_argument("--trust-policy-path", type=Path, required=True)
    worker.add_argument("--operator-key-id", required=True)
    worker.add_argument("--operator-fingerprint", required=True)
    worker.add_argument("--lease-duration-ms", type=int, default=60_000)
    worker.add_argument("--crash-after-checkpoint", action="store_true")
    worker.add_argument("--fault-before-postgres-completion", action="store_true")
    return parser


def _live_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--server",
        default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"),
    )
    parser.add_argument("--token-env", default="DATAHUB_GMS_TOKEN")
    parser.add_argument("--state-postgres-dsn-env", default="GLASSBOX_STATE_POSTGRES_DSN")
    parser.add_argument("--sandbox-image-digest", required=True)
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")


def _build_corrected_handoff(
    source_receipt: Mapping[str, Any],
    task: Any,
    *,
    timeline: LiveProofTimeline,
) -> tuple[Any, dict[str, Any], Any, dict[str, str]]:
    evidence, actions, _tools = _single_replay_components(source_receipt)
    evidence_id = _text(evidence, "evidence_id")
    action_id = _text(actions, "action_id")
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
    operator_key = SigningKey(
        "glassbox-live-recovery-operator",
        Ed25519PrivateKey.generate(),
    )
    authorization = issue_recovery_authorization(
        task,
        source_receipt,
        bundle,
        issuer="urn:li:corpuser:glassbox-recovery-operator",
        issued_at=timeline.issued_at,
        expires_at=timeline.expires_at,
        signing_keys=(operator_key,),
    )
    trusted = {operator_key.key_id: signing_key_fingerprint(operator_key)}
    verification = verify_recovery_authorization(
        authorization,
        task,
        source_receipt,
        bundle,
        evaluated_at=timeline.evaluated_at,
        trusted_signer_fingerprints=trusted,
    )
    if not verification.valid:
        raise RuntimeError("live recovery handoff failed exact authorization verification")
    return authorization, bundle, verification, trusted


def _run_worker(args: argparse.Namespace) -> int:
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    dsn = _required_environment(args.state_postgres_dsn_env)
    token = os.getenv(args.token_env) or None
    trust_policy = load_signer_trust_policy(args.trust_policy_path)
    authority = PostgresInvalidationStore(
        dsn,
        schema=args.schema,
        signer_trust_policy=trust_policy,
        initialize_schema=False,
    )
    state = PostgresRecoveryStore(
        dsn,
        authority,
        schema=args.schema,
        initialize_schema=False,
    )
    signing_key = signing_key_from_base64url(
        "glassbox-live-ephemeral",
        _required_environment(REPLAY_SIGNING_KEY_ENV),
    )
    trusted = {args.operator_key_id: args.operator_fingerprint}
    executor = FlagshipRecoveryExecutor(
        signing_key=signing_key,
        sandbox_image_digest=args.sandbox_image_digest,
        trusted_signer_fingerprints=trusted,
    )
    receipt_backend = DataHubReceiptBackend(server=server, token=token)
    receipt_backend.test_connection()
    receipt_pipeline = LiveReceiptPipeline(
        authority,
        ReceiptEmitter(receipt_backend, signer_trust_policy=trust_policy),
    )
    supersession_backend = DataHubSupersessionBackend(server=server, token=token)
    supersession_backend.test_connection()
    closure_backend = DataHubRecoveryClosureBackend(server=server, token=token)
    closure_backend.test_connection()
    effects = DataHubRecoveryEffects(
        receipt_pipeline,
        SupersessionEmitter(supersession_backend),
        RecoveryClosureEmitter(closure_backend),
    )
    orchestration_state = (
        CrashBeforePostgresCompletionStore(state)
        if args.fault_before_postgres_completion
        else state
    )
    orchestrator = RecoveryOrchestrator(
        orchestration_state,
        authority,
        executor,
        effects,
        trusted_signer_fingerprints=trusted,
        worker_id=f"durable-live-worker-{uuid.uuid4().hex}",
        lease_duration_ms=args.lease_duration_ms,
    )
    step = orchestrator.process_next(args.campaign_id)
    job = state.get(args.campaign_id)
    if job is None or not job.valid:
        raise RuntimeError("worker checkpoint readback is invalid")
    payload = {
        "valid": True,
        "pid": os.getpid(),
        "abrupt_exit_injected": bool(args.crash_after_checkpoint),
        "step": step.to_dict(),
        "durable_job": job.to_dict(),
        "event_count": len(state.read_events(args.campaign_id)),
        "runtime_schema_ddl_permitted": False,
        "raw_content_returned": False,
    }
    print(WORKER_REPORT_PREFIX + json.dumps(payload, sort_keys=True), flush=True)
    if args.crash_after_checkpoint:
        os._exit(ABRUPT_CHECKPOINT_EXIT_CODE)
    return 0


def _run_parent(args: argparse.Namespace) -> int:
    if args.proof_run_offset_ms < 0:
        raise ValueError("proof-run-offset-ms must be non-negative")
    if args.fault_lease_duration_ms <= 0:
        raise ValueError("fault-lease-duration-ms must be positive")
    if not args.python.is_absolute() or not args.python.is_file():
        raise ValueError("--python must name an existing absolute interpreter")
    inject_uncertain_completion = args.command == "run-uncertain"
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    dsn = _required_environment(args.state_postgres_dsn_env)
    token = os.getenv(args.token_env) or None
    graph = DataHubGraph(config=DatahubClientConfig(server=server, token=token))
    graph.test_connection()
    schema = f"gbx_durable_flagship_{uuid.uuid4().hex}"
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

        receipt_backend = DataHubReceiptBackend(server=server, token=token)
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
        authority = PostgresInvalidationStore(
            dsn,
            schema=schema,
            signer_trust_policy=trust_policy,
        )
        lineage = FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.durable-flagship-field-lineage.v1",
            wildcard_query=False,
        )
        pipeline = LiveReceiptPipeline(
            authority,
            ReceiptEmitter(receipt_backend, signer_trust_policy=trust_policy),
        )
        source_publication = pipeline.publish_compiled(source_receipt, field_lineage=lineage)
        source_redelivery = pipeline.publish_compiled(source_receipt, field_lineage=lineage)
        if not (
            source_publication.valid
            and source_redelivery.valid
            and not source_redelivery.datahub_write_performed
        ):
            raise RuntimeError("source receipt publication was not idempotent")

        with TemporaryDirectory(prefix="glassbox-durable-flagship-") as temporary:
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
                authority,
                worker_id="durable-flagship-live-action",
            )
            plugin = GlassBoxInvalidationAction(
                GlassBoxInvalidationActionConfig(
                    state_postgres_dsn_env=args.state_postgres_dsn_env,
                    state_postgres_schema=schema,
                    signer_trust_policy_path=trust_policy_path,
                    worker_id="durable-flagship-live-action",
                ),
                action,
                authority,
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
            ):
                raise RuntimeError("material invalidation campaign failed")
            task = authority.get_task(stale.campaign.campaign_id)
            if (
                task is None
                or task.status is not OutboxStatus.COMPLETED
                or task.write_evidence is None
                or not task.write_evidence.valid
            ):
                raise RuntimeError("completed campaign evidence is unavailable")

            timeline = LiveProofTimeline.now()
            authorization, bundle, authorization_verification, trusted = _build_corrected_handoff(
                source_receipt, task, timeline=timeline
            )
            recovery = PostgresRecoveryStore(dsn, authority, schema=schema)
            if not recovery.stage_authorized(
                authorization,
                bundle,
                evaluated_at=timeline.evaluated_at,
                trusted_signer_fingerprints=trusted,
            ):
                raise RuntimeError("new live recovery authorization was not staged")

            worker_environment = _worker_environment(
                dsn_environment=args.state_postgres_dsn_env,
                dsn=dsn,
                token_environment=args.token_env,
                token=token,
                signing_key=signing_key,
            )
            transitions = (
                (
                    RecoveryStage.AUTHORIZED,
                    RecoveryOperation.EXECUTE_ISOLATED_REPLAY,
                    RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
                ),
                (
                    RecoveryStage.ISOLATED_EXECUTION_SUCCEEDED,
                    RecoveryOperation.PUBLISH_REPLAY_RECEIPT,
                    RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
                ),
                (
                    RecoveryStage.REPLAY_RECEIPT_PUBLISHED,
                    RecoveryOperation.PUBLISH_SUPERSESSION,
                    RecoveryStage.SUPERSESSION_VERIFIED,
                ),
                (
                    RecoveryStage.SUPERSESSION_VERIFIED,
                    RecoveryOperation.CLOSE_INCIDENT,
                    RecoveryStage.INCIDENT_CLOSED,
                ),
            )
            worker_reports: list[dict[str, Any]] = []
            fault_reports: list[dict[str, Any]] = []
            seen_pids: set[int] = set()
            documents_before: dict[str, str] | None = None
            for prior_stage, operation, expected_stage in transitions:
                if inject_uncertain_completion:
                    fault = _launch_precommit_fault_worker(
                        args,
                        schema=schema,
                        campaign_id=task.campaign.campaign_id,
                        trust_policy_path=trust_policy_path,
                        trusted=trusted,
                        environment=worker_environment,
                        expected_stage=prior_stage,
                        expected_operation=operation,
                        seen_pids=seen_pids,
                    )
                    fault_reports.append(fault)
                    fault_authority = PostgresInvalidationStore(
                        dsn,
                        schema=schema,
                        signer_trust_policy=trust_policy,
                        initialize_schema=False,
                    )
                    fault_state = PostgresRecoveryStore(
                        dsn,
                        fault_authority,
                        schema=schema,
                        initialize_schema=False,
                    )
                    fault_job = fault_state.get(task.campaign.campaign_id)
                    expected_event_count = list(RecoveryStage).index(prior_stage) + 1
                    if (
                        fault_job is None
                        or not fault_job.valid
                        or fault_job.stage is not prior_stage
                        or fault_job.lease_operation is not operation
                        or len(fault_state.read_events(task.campaign.campaign_id))
                        != expected_event_count
                        or fault["durable_event_count_before"] != expected_event_count
                        or fault["attempt_count"] != fault_job.attempt_count
                    ):
                        raise RuntimeError(
                            "pre-commit crash changed the durable checkpoint unexpectedly"
                        )
                    _wait_for_lease_expiry(
                        dsn,
                        schema=schema,
                        campaign_id=task.campaign.campaign_id,
                    )
                report = _launch_checkpoint_worker(
                    args,
                    schema=schema,
                    campaign_id=task.campaign.campaign_id,
                    trust_policy_path=trust_policy_path,
                    trusted=trusted,
                    environment=worker_environment,
                    expected_stage=expected_stage,
                    seen_pids=seen_pids,
                )
                worker_reports.append(report)
                observer_authority = PostgresInvalidationStore(
                    dsn,
                    schema=schema,
                    signer_trust_policy=trust_policy,
                    initialize_schema=False,
                )
                observer = PostgresRecoveryStore(
                    dsn,
                    observer_authority,
                    schema=schema,
                    initialize_schema=False,
                )
                observed_job = observer.get(task.campaign.campaign_id)
                if (
                    observed_job is None
                    or not observed_job.valid
                    or observed_job.stage is not expected_stage
                    or observed_job.lease_operation is not None
                ):
                    raise RuntimeError("fresh-process durable checkpoint readback failed")
                if expected_stage is RecoveryStage.REPLAY_RECEIPT_PUBLISHED:
                    if observed_job.replay_publication is None:
                        raise RuntimeError("replay publication evidence is unavailable")
                    documents_before = {
                        source_publication.datahub.document_urn: _entity_digest(
                            graph, source_publication.datahub.document_urn
                        ),
                        observed_job.replay_publication.target_id: _entity_digest(
                            graph, observed_job.replay_publication.target_id
                        ),
                    }

            closed_redelivery = _launch_checkpoint_worker(
                args,
                schema=schema,
                campaign_id=task.campaign.campaign_id,
                trust_policy_path=trust_policy_path,
                trusted=trusted,
                environment=worker_environment,
                expected_stage=RecoveryStage.INCIDENT_CLOSED,
                seen_pids=seen_pids,
                expect_reused=True,
            )
            worker_reports.append(closed_redelivery)

            final_authority = PostgresInvalidationStore(
                dsn,
                schema=schema,
                signer_trust_policy=trust_policy,
                initialize_schema=False,
            )
            final_store = PostgresRecoveryStore(
                dsn,
                final_authority,
                schema=schema,
                initialize_schema=False,
            )
            final_job = final_store.get(task.campaign.campaign_id)
            if final_job is None or final_job.artifacts is None:
                raise RuntimeError("closed recovery artifacts are unavailable")
            recovery_integrity = final_store.verify_integrity()
            events = final_store.read_events(task.campaign.campaign_id)
            if documents_before is None:
                raise RuntimeError("receipt Document preservation baseline is unavailable")
            documents_after = {urn: _entity_digest(graph, urn) for urn in documents_before}
            source_state_unchanged = (
                final_authority.get_receipt(_text(source_receipt, "receipt_id")) == source_snapshot
            )
            documents_unchanged = documents_before == documents_after

            closure_backend = DataHubRecoveryClosureBackend.from_graph(graph)
            closure_backend.test_connection()
            closure_recovery = RecoveryClosureEmitter(closure_backend).close_verified(
                final_job.artifacts.closure,
                final_job.artifacts.supersession,
            )
            zero_write_closure_recovery = (
                closure_recovery.valid
                and closure_recovery.reused_completion
                and closure_recovery.emission_attempts == 0
                and closure_recovery.aspect_writes == 0
            )
            abrupt_workers = all(item["abrupt_exit_injected"] is True for item in worker_reports)
            fault_workers = all(
                item["fault_point"] == "AFTER_SUCCESS_BEFORE_POSTGRES_COMPLETION"
                and item["postgres_completion_called"] is False
                and item["readback_verified"] is True
                for item in fault_reports
            )
            total_workers = len(worker_reports) + len(fault_reports)
            unique_workers = len(seen_pids) == total_workers
            stage_sequence = [item["step"]["stage"] for item in worker_reports[:-1]] == [
                transition[2].value for transition in transitions
            ]
            final_reused = worker_reports[-1]["step"]["reused_completion"] is True
            expected_attempts = 8 if inject_uncertain_completion else 4
            uncertain_bindings_valid = not inject_uncertain_completion or (
                len(fault_reports) == 4
                and [item["operation"] for item in fault_reports]
                == [transition[1].value for transition in transitions]
                and [item["attempt_count"] for item in fault_reports] == [1, 3, 5, 7]
                and [item["step"]["attempt_count"] for item in worker_reports[:-1]] == [2, 4, 6, 8]
                and fault_reports[0]["artifact_or_evidence_id"]
                == final_job.artifacts.artifact_set_id
                and fault_reports[0]["bound_artifact_id"] == final_job.artifacts.artifact_set_id
                and final_job.replay_publication is not None
                and final_job.supersession_publication is not None
                and final_job.incident_closure is not None
                and [item["write_performed"] for item in fault_reports] == [None, True, True, True]
                and final_job.replay_publication.emission_count == 2
                and final_job.replay_publication.write_performed is False
                and final_job.supersession_publication.emission_count == 2
                and final_job.supersession_publication.write_performed is True
                and final_job.incident_closure.emission_count == 0
                and final_job.incident_closure.write_performed is False
            )
            valid = (
                source_publication.valid
                and negative.valid
                and stale.valid
                and authorization_verification.valid
                and final_job.valid
                and final_job.stage is RecoveryStage.INCIDENT_CLOSED
                and recovery_integrity.workflows == 1
                and recovery_integrity.closed_workflows == 1
                and recovery_integrity.events == 5
                and len(events) == 5
                and abrupt_workers
                and fault_workers
                and unique_workers
                and stage_sequence
                and final_reused
                and final_job.attempt_count == expected_attempts
                and uncertain_bindings_valid
                and source_state_unchanged
                and documents_unchanged
                and zero_write_closure_recovery
            )
            result = {
                "contract": (
                    UNCERTAIN_PROOF_CONTRACT if inject_uncertain_completion else PROOF_CONTRACT
                ),
                "valid": valid,
                "scenario": (
                    "GLASSBOX_DURABLE_UNCERTAIN_COMPLETION_RECOVERY"
                    if inject_uncertain_completion
                    else "GLASSBOX_DURABLE_CAUSAL_RECOVERY_WITH_PROCESS_CRASHES"
                ),
                "runtime": {
                    "proof_date": PROOF_DATE,
                    "proof_run_offset_ms": args.proof_run_offset_ms,
                    "datahub_core_version": _datahub_core_version(graph),
                    "datahub_sdk_version": receipt_backend.sdk_version,
                    "postgresql_server_version": _postgres_version(dsn),
                    "sandbox_image_digest": args.sandbox_image_digest,
                    "worker_processes": total_workers,
                    "distinct_worker_pids": len(seen_pids),
                    "abrupt_checkpoint_exit_code": ABRUPT_CHECKPOINT_EXIT_CODE,
                    "abrupt_precommit_exit_code": ABRUPT_PRECOMMIT_EXIT_CODE,
                    "fault_lease_duration_ms": args.fault_lease_duration_ms,
                },
                "invalidation": {
                    "negative_control": negative_assessment.state.value,
                    "campaign_id": stale.campaign.campaign_id,
                    "incident_urn": stale.campaign.incident_urn,
                    "finding": stale_assessment.state.value,
                    "datahub_writeback_verified": task.write_evidence.valid,
                    "completed_redelivery_emissions": stale_redelivery.emissions,
                },
                "authorization": {
                    "authorization_id": authorization.authorization_id,
                    "bundle_id": authorization.bundle_id,
                    "source_receipt_id": authorization.source_receipt_id,
                    "verification": authorization_verification.to_dict(),
                    "staged_before_worker_start": True,
                },
                "recovery": {
                    "workflow_id": final_job.workflow_id,
                    "final_stage": final_job.stage.value,
                    "attempt_count": final_job.attempt_count,
                    "artifact_set_id": final_job.artifacts.artifact_set_id,
                    "replay_receipt_id": final_job.artifacts.replay_receipt["receipt_id"],
                    "supersession_id": final_job.artifacts.supersession.supersession_id,
                    "closure_id": final_job.artifacts.closure.closure_id,
                    "effect_evidence_ids": final_job.to_dict()["effect_evidence_ids"],
                    "checkpoint_events": [item.to_dict() for item in events],
                    "workers": worker_reports,
                    "precommit_faults": fault_reports,
                    "closed_redelivery_reused_completion": final_reused,
                    "zero_write_exact_closure_recovery": closure_recovery.to_dict(),
                    "retry_effect_evidence": {
                        "replay_receipt": (
                            final_job.replay_publication.to_dict()
                            if final_job.replay_publication is not None
                            else None
                        ),
                        "supersession": (
                            final_job.supersession_publication.to_dict()
                            if final_job.supersession_publication is not None
                            else None
                        ),
                        "incident_closure": (
                            final_job.incident_closure.to_dict()
                            if final_job.incident_closure is not None
                            else None
                        ),
                    },
                },
                "history_preservation": {
                    "postgres_source_receipt_unchanged": source_state_unchanged,
                    "datahub_receipt_documents_unchanged": documents_unchanged,
                    "direct_entity_digests_before": documents_before,
                    "direct_entity_digests_after": documents_after,
                },
                "integrity": {
                    "workflows": recovery_integrity.workflows,
                    "active_workflows": recovery_integrity.active_workflows,
                    "closed_workflows": recovery_integrity.closed_workflows,
                    "events": recovery_integrity.events,
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
                    "digest_pinned_oci_execution": "PROVEN",
                    "fresh_process_after_each_checkpoint": "PROVEN",
                    "abrupt_interpreter_exit_after_each_checkpoint": "PROVEN",
                    "closed_redelivery_zero_effect": "PROVEN",
                    "exact_prior_closure_zero_write": "PROVEN",
                    "crash_before_checkpoint_commit": (
                        "PROVEN" if inject_uncertain_completion else "NOT_EXERCISED"
                    ),
                    "crash_after_oci_before_artifact_commit": (
                        "PROVEN" if inject_uncertain_completion else "NOT_EXERCISED"
                    ),
                    "crash_after_datahub_before_stage_commit": (
                        "PROVEN" if inject_uncertain_completion else "NOT_EXERCISED"
                    ),
                    "physical_read_only_execution_repeated": (
                        "PROVEN" if inject_uncertain_completion else "NOT_EXERCISED"
                    ),
                    "physical_multi_host_failover": "NOT_EXERCISED",
                },
                "raw_content_returned": False,
            }
            serialized = json.dumps(result, indent=2, sort_keys=True)
            if CUSTOMER_ID in serialized or '"average_order_value": 62' in serialized:
                raise RuntimeError("live durable report crossed the raw-content boundary")
            print(serialized)
            return 0 if valid else 1
    finally:
        _drop_schema(dsn, schema)


def _launch_checkpoint_worker(
    args: argparse.Namespace,
    *,
    schema: str,
    campaign_id: str,
    trust_policy_path: Path,
    trusted: Mapping[str, str],
    environment: Mapping[str, str],
    expected_stage: RecoveryStage,
    seen_pids: set[int],
    expect_reused: bool = False,
) -> dict[str, Any]:
    if len(trusted) != 1:
        raise RuntimeError("live proof requires exactly one configured recovery authority")
    key_id, fingerprint = next(iter(trusted.items()))
    command = [
        str(args.python),
        "-m",
        "examples.end_to_end_durable_recovery",
        "worker",
        "--server",
        args.server,
        "--token-env",
        args.token_env,
        "--state-postgres-dsn-env",
        args.state_postgres_dsn_env,
        "--sandbox-image-digest",
        args.sandbox_image_digest,
        "--schema",
        schema,
        "--campaign-id",
        campaign_id,
        "--trust-policy-path",
        str(trust_policy_path),
        "--operator-key-id",
        key_id,
        "--operator-fingerprint",
        fingerprint,
        "--lease-duration-ms",
        str(args.fault_lease_duration_ms),
        "--allow-live",
        "--crash-after-checkpoint",
    ]
    if args.allow_remote:
        command.append("--allow-remote")
    completed = subprocess.run(
        command,
        cwd=_ROOT,
        env=dict(environment),
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    return _parse_worker_report(
        completed,
        expected_stage=expected_stage,
        seen_pids=seen_pids,
        expect_reused=expect_reused,
    )


def _launch_precommit_fault_worker(
    args: argparse.Namespace,
    *,
    schema: str,
    campaign_id: str,
    trust_policy_path: Path,
    trusted: Mapping[str, str],
    environment: Mapping[str, str],
    expected_stage: RecoveryStage,
    expected_operation: RecoveryOperation,
    seen_pids: set[int],
) -> dict[str, Any]:
    if len(trusted) != 1:
        raise RuntimeError("live proof requires exactly one configured recovery authority")
    key_id, fingerprint = next(iter(trusted.items()))
    command = [
        str(args.python),
        "-m",
        "examples.end_to_end_durable_recovery",
        "worker",
        "--server",
        args.server,
        "--token-env",
        args.token_env,
        "--state-postgres-dsn-env",
        args.state_postgres_dsn_env,
        "--sandbox-image-digest",
        args.sandbox_image_digest,
        "--schema",
        schema,
        "--campaign-id",
        campaign_id,
        "--trust-policy-path",
        str(trust_policy_path),
        "--operator-key-id",
        key_id,
        "--operator-fingerprint",
        fingerprint,
        "--lease-duration-ms",
        str(args.fault_lease_duration_ms),
        "--allow-live",
        "--fault-before-postgres-completion",
    ]
    if args.allow_remote:
        command.append("--allow-remote")
    completed = subprocess.run(
        command,
        cwd=_ROOT,
        env=dict(environment),
        capture_output=True,
        text=True,
        timeout=360,
        check=False,
    )
    return _parse_fault_report(
        completed,
        expected_stage=expected_stage,
        expected_operation=expected_operation,
        seen_pids=seen_pids,
    )


def _parse_fault_report(
    completed: subprocess.CompletedProcess[str],
    *,
    expected_stage: RecoveryStage,
    expected_operation: RecoveryOperation,
    seen_pids: set[int],
) -> dict[str, Any]:
    if completed.returncode != ABRUPT_PRECOMMIT_EXIT_CODE:
        raise RuntimeError(
            "pre-commit worker did not terminate through the injected exit "
            f"({completed.returncode})"
        )
    matches = [
        line.removeprefix(FAULT_REPORT_PREFIX)
        for line in completed.stdout.splitlines()
        if line.startswith(FAULT_REPORT_PREFIX)
    ]
    if len(matches) != 1:
        raise RuntimeError("pre-commit worker returned no unique bounded report")
    value = json.loads(matches[0])
    if not isinstance(value, dict):
        raise RuntimeError("pre-commit worker report must be an object")
    pid = value.get("pid")
    if (
        value.get("contract") != "glassbox.recovery-precommit-fault.v1"
        or value.get("valid") is not True
        or value.get("fault_point") != "AFTER_SUCCESS_BEFORE_POSTGRES_COMPLETION"
        or value.get("operation") != expected_operation.value
        or value.get("durable_stage_before") != expected_stage.value
        or value.get("lease_operation") != expected_operation.value
        or value.get("readback_verified") is not True
        or value.get("postgres_completion_called") is not False
        or value.get("raw_content_returned") is not False
        or not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or pid in seen_pids
    ):
        raise RuntimeError("pre-commit worker report failed boundary verification")
    seen_pids.add(pid)
    return value


def _parse_worker_report(
    completed: subprocess.CompletedProcess[str],
    *,
    expected_stage: RecoveryStage,
    seen_pids: set[int],
    expect_reused: bool,
) -> dict[str, Any]:
    if completed.returncode != ABRUPT_CHECKPOINT_EXIT_CODE:
        raise RuntimeError(
            f"checkpoint worker did not terminate through the injected exit "
            f"({completed.returncode})"
        )
    matches = [
        line.removeprefix(WORKER_REPORT_PREFIX)
        for line in completed.stdout.splitlines()
        if line.startswith(WORKER_REPORT_PREFIX)
    ]
    if len(matches) != 1:
        raise RuntimeError("checkpoint worker returned no unique bounded report")
    value = json.loads(matches[0])
    if not isinstance(value, dict):
        raise RuntimeError("checkpoint worker report must be an object")
    step = value.get("step")
    pid = value.get("pid")
    if (
        value.get("valid") is not True
        or value.get("abrupt_exit_injected") is not True
        or value.get("raw_content_returned") is not False
        or not isinstance(step, dict)
        or step.get("stage") != expected_stage.value
        or step.get("reused_completion") is not expect_reused
        or not isinstance(pid, int)
        or isinstance(pid, bool)
        or pid <= 0
        or pid in seen_pids
    ):
        raise RuntimeError("checkpoint worker report failed stage or identity verification")
    seen_pids.add(pid)
    return value


def _worker_environment(
    *,
    dsn_environment: str,
    dsn: str,
    token_environment: str,
    token: str | None,
    signing_key: SigningKey,
) -> dict[str, str]:
    allowed = (
        "PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "XDG_RUNTIME_DIR",
    )
    environment = {key: os.environ[key] for key in allowed if key in os.environ}
    environment[dsn_environment] = dsn
    if token is not None:
        environment[token_environment] = token
    environment[REPLAY_SIGNING_KEY_ENV] = _private_key_base64url(signing_key)
    return environment


def _private_key_base64url(signing_key: SigningKey) -> str:
    raw = signing_key.private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _single_replay_components(
    source_receipt: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any], Mapping[str, Any]]:
    evidence = source_receipt.get("evidence")
    actions = source_receipt.get("actions")
    tools = source_receipt.get("tools")
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
        raise ReplayExecutionError(
            "durable flagship receipt requires one evidence item, action, and tool"
        )
    return evidence[0], actions[0], tools[0]


def _required_environment(name: str) -> str:
    value = os.getenv(name)
    if value is None or not value:
        raise ValueError(f"configured environment variable {name!r} is unset")
    return value


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


def _offset(value: str, *, minutes: int = 0, seconds: int = 0) -> str:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return _iso(parsed + timedelta(minutes=minutes, seconds=seconds))


def _datahub_core_version(graph: DataHubGraph) -> str:
    version, _commit = _datahub_version(graph)
    return version


def _postgres_version(dsn: str) -> str:
    with psycopg.connect(dsn) as connection:
        row = connection.execute("SHOW server_version").fetchone()
    if row is None or not isinstance(row[0], str):
        raise RuntimeError("PostgreSQL did not report its server version")
    return row[0]


def _wait_for_lease_expiry(
    dsn: str,
    *,
    schema: str,
    campaign_id: str,
    timeout_seconds: float = 15.0,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    statement = sql.SQL(
        """
        SELECT lease_expires_at_ms,
               floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms
        FROM {}.recovery_jobs WHERE campaign_id = %s
        """
    ).format(sql.Identifier(schema))
    while time.monotonic() < deadline:
        with psycopg.connect(dsn) as connection:
            row = connection.execute(statement, (campaign_id,)).fetchone()
        if row is None or not isinstance(row[0], int) or not isinstance(row[1], int):
            raise RuntimeError("pre-commit crash did not leave a server-clock lease")
        if row[1] >= row[0]:
            return
        time.sleep(0.05)
    raise RuntimeError("PostgreSQL recovery lease did not expire before timeout")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "worker":
        return _run_worker(args)
    return _run_parent(args)


if __name__ == "__main__":
    raise SystemExit(main())
