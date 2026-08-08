"""Live proof: instrument a run, compile a signed DBOM, and verify it in DataHub."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from examples.deterministic_pricing_agent import (
    build_pricing_agent,
    build_replayable_pricing_agent,
    pricing_source_digest,
)
from examples.pricing_policy import pricing_policy_schema_digest, pricing_policy_source_digest

from glassbox import GlassBox, InMemorySink
from glassbox_compiler import (
    CompilationProfile,
    ComponentDeclaration,
    Environment,
    LiveReceiptPipeline,
    PostgresReceiptStateConfig,
    ToolDeclaration,
    VerifiedURNResolver,
    compile_events,
)
from glassbox_datahub import DataHubReceiptBackend, ReceiptEmitter
from glassbox_datahub.capability_probe import validate_probe_target
from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    signing_key_fingerprint,
    signing_key_public_key,
)


class DemoIds:
    """Stable non-secret IDs make the live proof repeatable."""

    def __init__(self) -> None:
        self._spans = iter(
            (
                "1111111111111111",
                "2222222222222222",
                "3333333333333333",
            )
        )

    def trace_id(self) -> str:
        return "0123456789abcdef0123456789abcdef"

    def span_id(self) -> str:
        return next(self._spans)

    def run_id(self) -> str:
        return "glassbox-live-pricing-run-001"


class DemoClock:
    """Stable UTC event time source for content-addressed proof output."""

    def __init__(self) -> None:
        self._next = datetime(2026, 8, 6, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        current = self._next
        self._next += timedelta(seconds=1)
        return current


def build_signed_receipt(
    *,
    urn_resolver: VerifiedURNResolver | None = None,
    schema_field_urn: str | None = None,
    signing_key: SigningKey | None = None,
    replay_ready: bool = False,
) -> dict[str, Any]:
    """Execute the synthetic agent and compile its privacy-safe runtime events."""

    sink = InMemorySink()
    runtime = GlassBox(sink, id_generator=DemoIds(), clock=DemoClock())
    if replay_ready:
        if schema_field_urn is None:
            raise ValueError("replay-ready pricing receipt requires a schema-field URN")
        agent = build_replayable_pricing_agent(runtime, schema_field_urn=schema_field_urn)
    else:
        agent = build_pricing_agent(runtime, schema_field_urn=schema_field_urn)
    agent("synthetic-live-customer")

    selected_signing_key = signing_key or demo_signing_key()
    source_digest = pricing_source_digest() if replay_ready else None
    tool_source_digest = pricing_policy_source_digest() if replay_ready else None
    component_version = "0.2.0" if replay_ready else "0.1.0"
    profile = CompilationProfile(
        environment=Environment.DEV,
        output_kind="pricing-recommendation",
        output_mime_type="application/json",
        agent=ComponentDeclaration(
            id="glassbox.demo.pricing-agent",
            version=component_version,
            datahub_urn="urn:li:document:glassbox.probe.agent.pricing-agent",
            source_digest=source_digest,
        ),
        models=()
        if replay_ready
        else (
            ComponentDeclaration(
                id="glassbox.probe.model",
                datahub_urn=(
                    "urn:li:mlModel:(urn:li:dataPlatform:openai,glassbox.probe.model,PROD)"
                ),
            ),
        ),
        skills=(
            ComponentDeclaration(
                id="glassbox.demo.pricing-analysis",
                version=component_version,
                source_digest=source_digest,
            ),
        ),
        tools=(
            ToolDeclaration(
                id="glassbox.demo.pricing-policy",
                version=component_version,
                source_digest=tool_source_digest,
                schema_digest=(pricing_policy_schema_digest() if replay_ready else None),
            ),
        ),
        signing_keys=(selected_signing_key,),
        urn_resolver=urn_resolver,
    )
    return compile_events(sink.events, profile=profile)


def demo_signing_key() -> SigningKey:
    """Create one process-local key for a live proof; never persist its private bytes."""

    return SigningKey("glassbox-live-ephemeral", Ed25519PrivateKey.generate())


def demo_signer_trust_policy(signing_key: SigningKey) -> SignerTrustPolicy:
    """Bind the process-local live-proof signer to an explicit operator policy."""

    return SignerTrustPolicy(
        policy_id="glassbox-live-proof-trust-v1",
        minimum_trusted_signatures=1,
        signers=(
            TrustedSigner(
                key_id=signing_key.key_id,
                public_key=signing_key_public_key(signing_key),
                public_key_sha256=signing_key_fingerprint(signing_key),
                status=SignerStatus.ACTIVE,
                not_before="2020-01-01T00:00:00Z",
                not_after="2100-01-01T00:00:00Z",
            ),
        ),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-live-receipt")
    parser.add_argument("--server", default=os.getenv("DATAHUB_GMS_URL", "http://localhost:8080"))
    parser.add_argument("--token", default=os.getenv("DATAHUB_GMS_TOKEN") or None)
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--allow-remote", action="store_true")
    parser.add_argument(
        "--state-postgres-dsn-env",
        default=(
            "GLASSBOX_STATE_POSTGRES_DSN" if os.getenv("GLASSBOX_STATE_POSTGRES_DSN") else None
        ),
        help=(
            "environment-variable name containing initialized shared-state PostgreSQL DSN; "
            "auto-enabled when GLASSBOX_STATE_POSTGRES_DSN is present"
        ),
    )
    parser.add_argument("--state-postgres-schema", default="glassbox")
    parser.add_argument("--postgres-connect-timeout-seconds", type=float, default=10.0)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    server = validate_probe_target(args.server, allow_remote=args.allow_remote)
    backend = DataHubReceiptBackend(server=server, token=args.token)
    backend.test_connection()
    signing_key = demo_signing_key()
    trust_policy = demo_signer_trust_policy(signing_key)
    receipt = build_signed_receipt(
        urn_resolver=VerifiedURNResolver(backend),
        signing_key=signing_key,
    )
    verification = trust_policy.verify_receipt(receipt)
    if not verification.valid:
        raise RuntimeError("locally compiled receipt did not pass signature verification")

    publication = None
    redelivery = None
    emitter = ReceiptEmitter(backend, signer_trust_policy=trust_policy)
    if args.state_postgres_dsn_env is not None:
        registry = PostgresReceiptStateConfig(
            dsn_environment_variable=args.state_postgres_dsn_env,
            schema=args.state_postgres_schema,
            connect_timeout_seconds=args.postgres_connect_timeout_seconds,
            signer_trust_policy=trust_policy,
        ).connect()
        pipeline = LiveReceiptPipeline(registry, emitter)
        publication = pipeline.publish_compiled(receipt)
        redelivery = pipeline.publish_compiled(receipt)
        emission = publication.datahub
    else:
        emission = emitter.emit_verified(receipt)
    shared_state: dict[str, object] | str = "NOT_CONFIGURED"
    if publication is not None:
        if redelivery is None:  # pragma: no cover - assigned with publication
            raise RuntimeError("completed redelivery report is missing")
        state_projection = publication.to_dict()["state"]
        if not isinstance(state_projection, dict):  # pragma: no cover - fixed report shape
            raise RuntimeError("live receipt state projection is invalid")
        shared_state = {
            **state_projection,
            "engine": "PostgreSQL",
            "signer_admission_evidence_verified": publication.state_readback_verified,
            "completed_redelivery_readback_verified": redelivery.state_readback_verified,
            "completed_redelivery_datahub_write_performed": (redelivery.datahub_write_performed),
        }
    print(
        json.dumps(
            {
                "valid": (
                    verification.valid
                    and emission.valid
                    and (
                        redelivery is None
                        or (redelivery.valid and not redelivery.datahub_write_performed)
                    )
                ),
                "receipt": {
                    "receipt_id": receipt["receipt_id"],
                    "payload_digest": receipt["integrity"]["payload_digest"]["value"],
                    "merkle_root": receipt["integrity"]["merkle_root"]["value"],
                    "signature_key_ids": [
                        signature["key_id"] for signature in receipt["integrity"]["signatures"]
                    ],
                    "evidence_count": len(receipt["evidence"]),
                    "action_count": len(receipt["actions"]),
                    "replay_eligibility": receipt["replay"]["eligibility"],
                },
                "signer_trust": {
                    "policy_id": verification.policy_id,
                    "mode": verification.mode.value,
                    "minimum_trusted_signatures": verification.minimum_trusted_signatures,
                    "trusted_signature_count": verification.trusted_signature_count,
                    "signer_key_id": signing_key.key_id,
                    "signer_public_key_sha256": signing_key_fingerprint(signing_key),
                    "private_key_returned": False,
                },
                "datahub": emission.to_dict(),
                "shared_state": shared_state,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
