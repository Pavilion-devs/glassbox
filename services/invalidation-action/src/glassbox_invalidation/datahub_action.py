"""Installable DataHub Actions plugin for GlassBox invalidation campaigns."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Protocol
from uuid import uuid4

from datahub.metadata.schema_classes import MetadataChangeLogClass
from datahub_actions.action.action import Action
from datahub_actions.event.event_envelope import EventEnvelope
from datahub_actions.event.event_registry import METADATA_CHANGE_LOG_EVENT_V1_TYPE
from datahub_actions.pipeline.pipeline_context import PipelineContext
from pydantic import BaseModel, ConfigDict, Field, model_validator

from glassbox_datahub import DataHubInvalidationBackend
from glassbox_dbom import SignerTrustPolicy, load_signer_trust_policy
from glassbox_invalidation.action import InvalidationAction, InvalidationActionReport
from glassbox_invalidation.audit_log import AppendOnlyCampaignAuditLog
from glassbox_invalidation.mcl import normalize_metadata_change_log
from glassbox_invalidation.owner_routing import DataHubOwnershipWebhookRouter
from glassbox_invalidation.receipt_store import VerifiedReceiptStore
from glassbox_invalidation.transactional_action import TransactionalInvalidationAction
from glassbox_invalidation.transactional_store import SQLiteInvalidationStore
from glassbox_policy import NormalizedChange, ReceiptDependencyProfile


class _ReceiptIndex(Protocol):
    def candidates(self, change: NormalizedChange) -> tuple[ReceiptDependencyProfile, ...]: ...


class _InvalidationProcessor(Protocol):
    def process(
        self,
        change: NormalizedChange,
        profiles: tuple[ReceiptDependencyProfile, ...],
    ) -> InvalidationActionReport: ...


class GlassBoxInvalidationActionConfig(BaseModel):
    """No-secret state configuration for the Actions plugin."""

    model_config = ConfigDict(extra="forbid")

    receipt_store_path: Path | None = None
    audit_log_path: Path | None = None
    state_database_path: Path | None = None
    state_postgres_dsn_env: str | None = None
    state_postgres_schema: str = "glassbox"
    actor_urn: str = "urn:li:corpuser:datahub"
    sync_audit: bool = True
    require_receipt_signature: bool = True
    require_trusted_receipt_signer: bool = True
    signer_trust_policy_path: Path | None = None
    allowed_entity_urn_prefixes: tuple[str, ...] = Field(default_factory=lambda: ("urn:li:",))
    worker_id: str | None = None
    lease_duration_ms: int = Field(default=60_000, gt=0)
    claim_timeout_seconds: float = Field(default=10.0, gt=0)
    claim_poll_seconds: float = Field(default=0.05, gt=0)
    sqlite_busy_timeout_seconds: float = Field(default=10.0, gt=0)
    postgres_connect_timeout_seconds: float = Field(default=10.0, gt=0)
    owner_webhook_url: str | None = None
    owner_webhook_bearer_token_env: str | None = None
    owner_webhook_timeout_seconds: float = Field(default=10.0, gt=0)
    allow_insecure_owner_webhook_http: bool = False

    @model_validator(mode="after")
    def validate_state_profile(self) -> GlassBoxInvalidationActionConfig:
        any_jsonl = self.receipt_store_path is not None or self.audit_log_path is not None
        complete_jsonl = self.receipt_store_path is not None and self.audit_log_path is not None
        if any_jsonl and not complete_jsonl:
            raise ValueError("JSONL state requires both receipt_store_path and audit_log_path")
        profiles = sum(
            (
                self.state_database_path is not None,
                self.state_postgres_dsn_env is not None,
                complete_jsonl,
            )
        )
        if profiles != 1:
            raise ValueError("configure exactly one state profile: SQLite, PostgreSQL, or JSONL")
        if self.state_postgres_dsn_env is not None and not self.state_postgres_dsn_env:
            raise ValueError("state_postgres_dsn_env must be non-empty")
        if self.worker_id is not None and not self.worker_id:
            raise ValueError("worker_id must be non-empty when configured")
        if self.require_trusted_receipt_signer and self.signer_trust_policy_path is None:
            raise ValueError(
                "signer_trust_policy_path is required unless trusted-signer enforcement "
                "is explicitly disabled"
            )
        if self.require_trusted_receipt_signer and not self.require_receipt_signature:
            raise ValueError("trusted-signer enforcement requires receipt signatures")
        transactional = (
            self.state_database_path is not None or self.state_postgres_dsn_env is not None
        )
        if self.owner_webhook_url is not None and not transactional:
            raise ValueError("owner_webhook_url requires the transactional state profile")
        if self.owner_webhook_bearer_token_env is not None:
            if not self.owner_webhook_bearer_token_env:
                raise ValueError("owner_webhook_bearer_token_env must be non-empty")
            if self.owner_webhook_url is None:
                raise ValueError("owner_webhook_bearer_token_env requires owner_webhook_url")
        if self.allow_insecure_owner_webhook_http and self.owner_webhook_url is None:
            raise ValueError("allow_insecure_owner_webhook_http requires owner_webhook_url")
        return self


class GlassBoxInvalidationAction(Action):  # type: ignore[misc]
    """Normalize MCLs and acknowledge only after verified idempotent writeback."""

    @classmethod
    def create(
        cls,
        config_dict: dict[str, Any],
        ctx: PipelineContext,
    ) -> GlassBoxInvalidationAction:
        config = GlassBoxInvalidationActionConfig.model_validate(config_dict or {})
        if ctx.graph is None:
            raise ValueError("GlassBox invalidation requires the pipeline datahub configuration")
        graph = ctx.graph.graph
        backend = DataHubInvalidationBackend.from_graph(
            graph,
            actor_urn=config.actor_urn,
        )
        backend.test_connection()
        signer_trust_policy: SignerTrustPolicy | None = None
        if config.signer_trust_policy_path is not None:
            signer_trust_policy = load_signer_trust_policy(config.signer_trust_policy_path)
        owner_router = None
        if config.owner_webhook_url is not None:
            bearer_token = None
            if config.owner_webhook_bearer_token_env is not None:
                bearer_token = os.getenv(config.owner_webhook_bearer_token_env)
                if bearer_token is None or not bearer_token:
                    raise ValueError(
                        "configured owner webhook bearer-token environment variable is unset"
                    )
            owner_router = DataHubOwnershipWebhookRouter(
                graph,
                webhook_url=config.owner_webhook_url,
                bearer_token=bearer_token,
                timeout_seconds=config.owner_webhook_timeout_seconds,
                allow_insecure_http=config.allow_insecure_owner_webhook_http,
            )
        if config.state_database_path is not None:
            store = SQLiteInvalidationStore(
                config.state_database_path,
                require_signature=config.require_receipt_signature,
                signer_trust_policy=signer_trust_policy,
                busy_timeout_seconds=config.sqlite_busy_timeout_seconds,
            )
            worker_id = config.worker_id or f"{ctx.pipeline_name}:{uuid4().hex}"
            invalidation = TransactionalInvalidationAction(
                backend,
                store,
                worker_id=worker_id,
                lease_duration_ms=config.lease_duration_ms,
                claim_timeout_seconds=config.claim_timeout_seconds,
                claim_poll_seconds=config.claim_poll_seconds,
                owner_router=owner_router,
            )
            return cls(config, invalidation, store)

        if config.state_postgres_dsn_env is not None:
            dsn = os.getenv(config.state_postgres_dsn_env)
            if dsn is None or not dsn:
                raise ValueError("configured PostgreSQL DSN environment variable is unset")
            from glassbox_invalidation.postgres_store import PostgresInvalidationStore

            postgres_store = PostgresInvalidationStore(
                dsn,
                schema=config.state_postgres_schema,
                require_signature=config.require_receipt_signature,
                signer_trust_policy=signer_trust_policy,
                connect_timeout_seconds=config.postgres_connect_timeout_seconds,
                initialize_schema=False,
            )
            worker_id = config.worker_id or f"{ctx.pipeline_name}:{uuid4().hex}"
            postgres_invalidation = TransactionalInvalidationAction(
                backend,
                postgres_store,
                worker_id=worker_id,
                lease_duration_ms=config.lease_duration_ms,
                claim_timeout_seconds=config.claim_timeout_seconds,
                claim_poll_seconds=config.claim_poll_seconds,
                owner_router=owner_router,
            )
            return cls(config, postgres_invalidation, postgres_store)

        if config.receipt_store_path is None or config.audit_log_path is None:
            raise AssertionError("validated JSONL state configuration is incomplete")
        legacy_store = VerifiedReceiptStore(
            config.receipt_store_path,
            sync=config.sync_audit,
            require_signature=config.require_receipt_signature,
            signer_trust_policy=signer_trust_policy,
        )
        audit = AppendOnlyCampaignAuditLog(config.audit_log_path, sync=config.sync_audit)
        return cls(config, InvalidationAction(backend, audit), legacy_store)

    def __init__(
        self,
        config: GlassBoxInvalidationActionConfig,
        invalidation: _InvalidationProcessor,
        receipt_store: _ReceiptIndex,
    ) -> None:
        self.config = config
        self._invalidation = invalidation
        self._receipt_store = receipt_store
        self.last_reports: tuple[InvalidationActionReport, ...] = ()

    def act(self, event: EventEnvelope) -> bool:
        if event.event_type != METADATA_CHANGE_LOG_EVENT_V1_TYPE:
            self.last_reports = ()
            return True
        if not isinstance(event.event, MetadataChangeLogClass):
            raise TypeError("MetadataChangeLogEvent_v1 envelope contains the wrong event class")

        reports: list[InvalidationActionReport] = []
        for change in normalize_metadata_change_log(event.event):
            if not any(
                change.entity_urn.startswith(prefix)
                for prefix in self.config.allowed_entity_urn_prefixes
            ):
                continue
            profiles = self._receipt_store.candidates(change)
            if profiles:
                reports.append(self._invalidation.process(change, profiles))
        self.last_reports = tuple(reports)
        return True

    def close(self) -> None:
        """The action owns no background resource requiring shutdown."""


__all__ = ["GlassBoxInvalidationAction", "GlassBoxInvalidationActionConfig"]
