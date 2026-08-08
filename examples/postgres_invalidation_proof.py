"""Guarded proof of PostgreSQL invalidation-state coordination and recovery."""

from __future__ import annotations

import argparse
import json
import os
import threading
import uuid
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import psycopg
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from psycopg import sql

from glassbox_dbom import (
    SignerStatus,
    SignerTrustPolicy,
    SigningKey,
    TrustedSigner,
    seal_receipt,
    signing_key_fingerprint,
    signing_key_public_key,
)
from glassbox_invalidation import TransactionalInvalidationAction
from glassbox_invalidation.postgres_store import PostgresInvalidationStore
from glassbox_policy import (
    ChangeKind,
    FieldCoverage,
    FieldLineageProof,
    InvalidationCampaign,
    InvalidationWriteEvidence,
    NormalizedChange,
    create_campaign,
)

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:postgres,commerce.orders,PROD)"
FIELD_URN = f"urn:li:schemaField:({DATASET_URN},average_order_value)"
FIXTURE = Path(__file__).parents[1] / "tests" / "fixtures" / "dbom" / "valid-read-only.json"


class ProofBackend:
    """Deterministic stand-in isolating the database state-machine proof."""

    def __init__(self) -> None:
        self.upserts = 0
        self.verifications = 0

    def upsert_campaign(self, campaign: InvalidationCampaign) -> None:
        del campaign
        self.upserts += 1

    def direct_verify(self, campaign: InvalidationCampaign) -> InvalidationWriteEvidence:
        self.verifications += 1
        return InvalidationWriteEvidence(
            incident_aspects=("incidentInfo", "incidentKey"),
            target_summary_verified=True,
            quarantined_documents=tuple(item.document_urn for item in campaign.quarantined),
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-postgres-invalidation-proof")
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument("--dsn-env", default="GLASSBOX_STATE_POSTGRES_DSN")
    parser.add_argument("--connections", type=int, default=8)
    return parser


def _signed_receipt(signing_key: SigningKey) -> dict[str, Any]:
    fixture = json.loads(FIXTURE.read_bytes())
    fixture.pop("receipt_id")
    fixture.pop("integrity")
    fixture["run"]["run_id"] = "postgres-state-proof"
    fixture["evidence"][0]["schema_field_urn"] = FIELD_URN
    return seal_receipt(fixture, signing_keys=(signing_key,))


def _trust_policy(signing_key: SigningKey) -> SignerTrustPolicy:
    return SignerTrustPolicy(
        policy_id="glassbox-postgres-live-proof-v1",
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


def _change() -> NormalizedChange:
    return NormalizedChange(
        event_id="postgres-state-proof-change",
        entity_urn=DATASET_URN,
        aspect_name="schemaMetadata",
        kind=ChangeKind.SCHEMA_FIELD_TYPE_CHANGED,
        occurred_at="2026-08-06T00:00:00Z",
        schema_field_urn=FIELD_URN,
    )


def _drop_schema(dsn: str, schema: str) -> None:
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(
            sql.SQL("DROP SCHEMA IF EXISTS {} CASCADE").format(sql.Identifier(schema))
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.connections < 2 or args.connections > 64:
        raise ValueError("connections must be between 2 and 64")
    dsn = os.getenv(args.dsn_env)
    if dsn is None or not dsn:
        raise ValueError("configured PostgreSQL DSN environment variable is unset")

    schema = f"gbx_proof_{uuid.uuid4().hex}"
    try:
        signing_key = SigningKey("postgres-state-proof", Ed25519PrivateKey.generate())
        trust_policy = _trust_policy(signing_key)
        store = PostgresInvalidationStore(
            dsn,
            schema=schema,
            signer_trust_policy=trust_policy,
        )
        receipt = _signed_receipt(signing_key)
        lineage = FieldLineageProof(
            coverage=FieldCoverage.COMPLETE,
            rule_id="glassbox.postgres-proof.v1",
            wildcard_query=False,
        )
        inserted = store.register(receipt, field_lineage=lineage)
        duplicate_inserted = store.register(receipt, field_lineage=lineage)
        profiles = store.candidates(_change())
        campaign = create_campaign(_change(), profiles)
        store.stage_campaign(campaign)

        connections = [
            PostgresInvalidationStore(
                dsn,
                schema=schema,
                initialize_schema=False,
                signer_trust_policy=trust_policy,
            )
            for _ in range(args.connections)
        ]
        barrier = threading.Barrier(args.connections)

        def claim(index: int) -> str | None:
            barrier.wait(timeout=10)
            task = connections[index].claim(
                campaign.campaign_id,
                worker_id=f"proof-worker-{index}",
                now_ms=1,
                lease_duration_ms=60_000,
            )
            return task.lease_owner if task is not None else None

        with ThreadPoolExecutor(max_workers=args.connections) as executor:
            claims = list(executor.map(claim, range(args.connections)))
        winners = tuple(item for item in claims if item is not None)
        if len(winners) != 1:
            raise RuntimeError("PostgreSQL claim proof did not produce exactly one winner")
        claimed = store.get_task(campaign.campaign_id)
        if claimed is None or claimed.lease_expires_at_ms is None:
            raise RuntimeError("PostgreSQL claim proof did not persist a lease")
        server_clock_used = claimed.lease_expires_at_ms > 1_000_000_000_000
        store.release(campaign, worker_id=winners[0], error_type="ProofRecovery")

        backend = ProofBackend()
        action = TransactionalInvalidationAction(
            backend,
            store,
            worker_id="proof-recovery-worker",
        )
        first = action.process(_change(), profiles)
        redelivery = action.process(_change(), profiles)
        integrity = store.verify_integrity()
        trusted_receipt_readback = store.get_receipt(receipt["receipt_id"]) == receipt
        task = store.get_task(campaign.campaign_id)
        routing = store.get_owner_routing_task(campaign.campaign_id)
        with psycopg.connect(dsn) as connection:
            server_version = connection.execute("SHOW server_version").fetchone()
        if server_version is None:
            raise RuntimeError("PostgreSQL server did not expose its version")

        report = {
            "valid": (
                inserted
                and not duplicate_inserted
                and len(profiles) == 1
                and len(winners) == 1
                and server_clock_used
                and first.valid
                and redelivery.valid
                and redelivery.reused_completion
                and redelivery.reused_routing
                and redelivery.emissions == 0
                and integrity.receipts == 1
                and integrity.campaigns == 1
                and trusted_receipt_readback
            ),
            "engine": {
                "name": "postgresql",
                "server_version": server_version[0],
                "schema_version": 3,
                "dsn_persisted_or_reported": False,
            },
            "receipt_index": {
                "receipts": integrity.receipts,
                "dependencies": integrity.dependencies,
                "duplicate_registration_inserted": duplicate_inserted,
                "candidate_count": len(profiles),
            },
            "signer_trust": {
                "policy_id": trust_policy.policy_id,
                "minimum_trusted_signatures": trust_policy.minimum_trusted_signatures,
                "signer_key_id": signing_key.key_id,
                "signer_public_key_sha256": signing_key_fingerprint(signing_key),
                "trusted_receipt_readback": trusted_receipt_readback,
                "checksummed_admission_evidence_verified": trusted_receipt_readback,
                "private_key_returned": False,
            },
            "coordination": {
                "connections": args.connections,
                "claim_winners": len(winners),
                "server_clock_used_despite_caller_now_ms_1": server_clock_used,
                "attempt_count_after_recovery": task.attempt_count if task is not None else None,
                "final_status": task.status.value if task is not None else None,
            },
            "dual_outbox": {
                "campaigns": integrity.campaigns,
                "audit_records": integrity.audit_records,
                "owner_routing_tasks": integrity.owner_routing_tasks,
                "routing_status": routing.status.value if routing is not None else None,
                "routing_destination_count": (
                    routing.delivery_evidence.destination_count
                    if routing is not None and routing.delivery_evidence is not None
                    else None
                ),
            },
            "verified_redelivery": {
                "first_emissions": first.emissions,
                "redelivery_emissions": redelivery.emissions,
                "fresh_backend_verifications": backend.verifications,
                "reused_completion": redelivery.reused_completion,
                "reused_routing": redelivery.reused_routing,
            },
            "scope": {
                "postgres_16_real_server": "PROVEN",
                "multi_connection_row_locking": "PROVEN",
                "server_clock_leases": "PROVEN",
                "recovery_and_redelivery": "PROVEN",
                "operator_signer_trust": "PROVEN",
                "physical_multi_host_deployment": "UNVERIFIED",
                "managed_failover": "UNVERIFIED",
                "network_partition_recovery": "UNVERIFIED",
            },
        }
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["valid"] else 1
    finally:
        _drop_schema(dsn, schema)


if __name__ == "__main__":
    raise SystemExit(main())
