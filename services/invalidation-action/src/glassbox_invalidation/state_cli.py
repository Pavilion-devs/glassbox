"""Operator CLI for the transactional invalidation state database."""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from glassbox_dbom import (
    SignerTrustPolicy,
    SigningKey,
    load_signer_trust_policy,
    signing_key_from_base64url,
)
from glassbox_invalidation.state_transfer import (
    StateTransferError,
    build_state_transfer_bundle,
    import_state_transfer_bundle,
    load_state_transfer_bundle,
    verify_state_transfer_bundle,
    write_state_transfer_bundle,
)
from glassbox_invalidation.transactional_protocol import TransactionalInvalidationStore
from glassbox_invalidation.transactional_store import (
    SQLITE_STATE_SCHEMA_VERSION,
    SQLiteInvalidationStore,
)
from glassbox_policy import FieldCoverage, FieldLineageProof


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-invalidation-state")
    commands = parser.add_subparsers(dest="command", required=True)

    init = commands.add_parser("init", help="Initialize and verify a state database")
    init.add_argument("database", type=Path)
    _add_trust_options(init)

    verify = commands.add_parser("verify", help="Verify SQLite and all record checksums")
    verify.add_argument("database", type=Path)
    _add_trust_options(verify)

    status = commands.add_parser("status", help="Show bounded receipt and outbox status")
    status.add_argument("database", type=Path)
    _add_trust_options(status)

    register = commands.add_parser(
        "register-receipt",
        help="Verify and transactionally index one signed DBOM receipt",
    )
    register.add_argument("database", type=Path)
    register.add_argument("receipt", type=Path)
    _add_receipt_options(register)
    _add_trust_options(register)

    export_transfer = commands.add_parser(
        "export-transfer",
        help="Verify and sign a portable SQLite receipt-state transfer",
    )
    export_transfer.add_argument("database", type=Path)
    export_transfer.add_argument("bundle", type=Path)
    _add_trust_options(export_transfer)
    _add_transfer_trust_option(export_transfer)
    _add_transfer_signing_options(export_transfer)

    verify_transfer = commands.add_parser(
        "verify-transfer",
        help="Verify transfer integrity, authority, and current receipt trust",
    )
    verify_transfer.add_argument("bundle", type=Path)
    _add_trust_options(verify_transfer)
    _add_transfer_trust_option(verify_transfer)

    import_transfer = commands.add_parser(
        "import-transfer",
        help="Verify and atomically activate a receipt transfer in SQLite",
    )
    import_transfer.add_argument("database", type=Path)
    import_transfer.add_argument("bundle", type=Path)
    _add_trust_options(import_transfer)
    _add_transfer_trust_option(import_transfer)

    postgres_init = commands.add_parser(
        "postgres-init",
        help="Initialize and verify a PostgreSQL state schema",
    )
    _add_postgres_options(postgres_init)
    postgres_verify = commands.add_parser(
        "postgres-verify",
        help="Verify PostgreSQL state and every application checksum",
    )
    _add_postgres_options(postgres_verify)
    postgres_status = commands.add_parser(
        "postgres-status",
        help="Show bounded PostgreSQL receipt and outbox status",
    )
    _add_postgres_options(postgres_status)
    postgres_register = commands.add_parser(
        "postgres-register-receipt",
        help="Verify and transactionally index one signed DBOM receipt in PostgreSQL",
    )
    postgres_register.add_argument("receipt", type=Path)
    _add_postgres_options(postgres_register)
    _add_receipt_options(postgres_register)

    postgres_export = commands.add_parser(
        "postgres-export-transfer",
        help="Verify and sign a portable PostgreSQL receipt-state transfer",
    )
    postgres_export.add_argument("bundle", type=Path)
    _add_postgres_options(postgres_export)
    _add_transfer_trust_option(postgres_export)
    _add_transfer_signing_options(postgres_export)

    postgres_import = commands.add_parser(
        "postgres-import-transfer",
        help="Verify and atomically activate a receipt transfer in PostgreSQL",
    )
    postgres_import.add_argument("bundle", type=Path)
    _add_postgres_options(postgres_import)
    _add_transfer_trust_option(postgres_import)
    return parser


def _add_receipt_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--field-coverage",
        choices=[item.value for item in FieldCoverage],
        default=FieldCoverage.NONE.value,
    )
    parser.add_argument("--field-rule")
    parser.add_argument(
        "--wildcard-query",
        choices=("true", "false", "unknown"),
        default="unknown",
    )
    parser.add_argument("--superseded-by")


def _add_postgres_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dsn-env",
        default="GLASSBOX_STATE_POSTGRES_DSN",
        help="Environment variable containing the PostgreSQL DSN",
    )
    parser.add_argument("--schema", default="glassbox")
    _add_trust_options(parser)


def _add_trust_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--signer-trust-policy",
        type=Path,
        default=None,
        help=("trusted-signer policy path (or GLASSBOX_SIGNER_TRUST_POLICY_PATH)"),
    )
    parser.add_argument(
        "--allow-untrusted-signers",
        action="store_true",
        help="development-only: verify signatures without an operator trust anchor",
    )


def _add_transfer_trust_option(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--transfer-trust-policy",
        type=Path,
        default=None,
        help=(
            "state-transfer authority policy path (or GLASSBOX_STATE_TRANSFER_TRUST_POLICY_PATH)"
        ),
    )


def _add_transfer_signing_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--transfer-signing-key",
        action="append",
        required=True,
        metavar="KEY_ID=ENVIRONMENT_VARIABLE",
        help="transfer signing key ID and environment variable containing its private key",
    )


def _store(
    path: Path,
    signer_trust_policy: SignerTrustPolicy | None,
) -> SQLiteInvalidationStore:
    if not path.parent.is_dir():
        raise ValueError(f"database parent directory does not exist: {path.parent}")
    return SQLiteInvalidationStore(path, signer_trust_policy=signer_trust_policy)


def _postgres_store(
    dsn_env: str,
    schema: str,
    *,
    initialize_schema: bool,
    signer_trust_policy: SignerTrustPolicy | None,
) -> TransactionalInvalidationStore:
    dsn = os.getenv(dsn_env)
    if dsn is None or not dsn:
        raise ValueError("configured PostgreSQL DSN environment variable is unset")
    from glassbox_invalidation.postgres_store import PostgresInvalidationStore

    return PostgresInvalidationStore(
        dsn,
        schema=schema,
        initialize_schema=initialize_schema,
        signer_trust_policy=signer_trust_policy,
    )


def _read_receipt(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"receipt path is not a regular file: {path}")
    try:
        value = json.loads(path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("receipt file is not valid JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("receipt file must contain a JSON object")
    return value


def _wildcard(value: str) -> bool | None:
    if value == "true":
        return True
    if value == "false":
        return False
    return None


def _transfer_signing_keys(values: Sequence[str]) -> tuple[SigningKey, ...]:
    keys: list[SigningKey] = []
    for value in values:
        key_id, separator, environment_name = value.partition("=")
        if (
            not separator
            or not key_id
            or key_id != key_id.strip()
            or not environment_name
            or environment_name != environment_name.strip()
        ):
            raise ValueError("transfer signing key must use KEY_ID=ENVIRONMENT_VARIABLE syntax")
        encoded = os.getenv(environment_name)
        if encoded is None or not encoded:
            raise ValueError("configured transfer signing-key environment variable is unset")
        keys.append(signing_key_from_base64url(key_id, encoded))
    return tuple(keys)


def _transfer_policy_path_from_environment() -> Path | None:
    value = os.getenv("GLASSBOX_STATE_TRANSFER_TRUST_POLICY_PATH")
    return Path(value) if value else None


def _load_transfer_policy(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
) -> SignerTrustPolicy:
    path = args.transfer_trust_policy or _transfer_policy_path_from_environment()
    if path is None:
        parser.error(
            "--transfer-trust-policy or GLASSBOX_STATE_TRANSFER_TRUST_POLICY_PATH is required"
        )
    return load_signer_trust_policy(path)


def _transfer_result(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    signer_trust_policy: SignerTrustPolicy,
) -> dict[str, Any]:
    transfer_policy = _load_transfer_policy(args, parser)
    if args.command == "verify-transfer":
        bundle = load_state_transfer_bundle(args.bundle)
        return verify_state_transfer_bundle(
            bundle,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=signer_trust_policy,
        ).to_dict()

    postgres = args.command.startswith("postgres-")
    if args.command in {"import-transfer", "postgres-import-transfer"}:
        bundle = load_state_transfer_bundle(args.bundle)
        verification = verify_state_transfer_bundle(
            bundle,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=signer_trust_policy,
        )
        if not verification.valid:
            raise StateTransferError(
                "state-transfer import verification failed (" + ",".join(verification.errors) + ")"
            )
        store = (
            _postgres_store(
                args.dsn_env,
                args.schema,
                initialize_schema=True,
                signer_trust_policy=signer_trust_policy,
            )
            if postgres
            else _store(args.database, signer_trust_policy)
        )
        return import_state_transfer_bundle(
            store,
            bundle,
            bundle_trust_policy=transfer_policy,
            receipt_trust_policy=signer_trust_policy,
        ).to_dict()

    if args.command not in {"export-transfer", "postgres-export-transfer"}:
        raise AssertionError("unsupported state-transfer command")
    store = (
        _postgres_store(
            args.dsn_env,
            args.schema,
            initialize_schema=False,
            signer_trust_policy=signer_trust_policy,
        )
        if postgres
        else _store(args.database, signer_trust_policy)
    )
    schema_version = SQLITE_STATE_SCHEMA_VERSION
    source_engine = "SQLITE"
    if postgres:
        from glassbox_invalidation.postgres_store import POSTGRES_STATE_SCHEMA_VERSION

        schema_version = POSTGRES_STATE_SCHEMA_VERSION
        source_engine = "POSTGRESQL"
    bundle = build_state_transfer_bundle(
        store,
        source_engine=source_engine,
        source_schema_version=schema_version,
        signing_keys=_transfer_signing_keys(args.transfer_signing_key),
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=signer_trust_policy,
    )
    write_state_transfer_bundle(args.bundle, bundle)
    verification = verify_state_transfer_bundle(
        bundle,
        bundle_trust_policy=transfer_policy,
        receipt_trust_policy=signer_trust_policy,
    )
    source = bundle["source"]
    return {
        "valid": verification.valid,
        "bundle_id": bundle["bundle_id"],
        "source": {
            "engine": source["engine"],
            "schema_version": source["schema_version"],
            "receipts": source["counts"]["receipts"],
        },
        "trusted_signature_count": verification.trusted_signature_count,
        "signatures": [item.to_dict() for item in verification.signatures],
        "raw_content_returned": False,
    }


def _status(store: TransactionalInvalidationStore) -> dict[str, Any]:
    integrity = store.verify_integrity()
    tasks = store.list_tasks()
    routing_tasks = store.list_owner_routing_tasks()
    publication_tasks = store.list_receipt_publication_tasks()
    return {
        "valid": True,
        "database": {
            "receipts": integrity.receipts,
            "dependencies": integrity.dependencies,
            "campaigns": integrity.campaigns,
            "audit_records": integrity.audit_records,
            "owner_routing_tasks": integrity.owner_routing_tasks,
            "receipt_publication_tasks": integrity.receipt_publication_tasks,
        },
        "receipt_publication_outbox": [
            {
                "receipt_id": task.receipt_id,
                "status": task.status.value,
                "attempt_count": task.attempt_count,
                "last_error_type": task.last_error_type,
                "document_urn": (
                    task.publication_evidence.document_urn
                    if task.publication_evidence is not None
                    else None
                ),
            }
            for task in publication_tasks
        ],
        "outbox": [
            {
                "campaign_id": task.campaign.campaign_id,
                "status": task.status.value,
                "attempt_count": task.attempt_count,
                "last_error_type": task.last_error_type,
            }
            for task in tasks
        ],
        "owner_routing_outbox": [
            {
                "campaign_id": task.campaign_id,
                "status": task.status.value,
                "attempt_count": task.attempt_count,
                "last_error_type": task.last_error_type,
                "destination_count": (
                    task.delivery_evidence.destination_count
                    if task.delivery_evidence is not None
                    else None
                ),
            }
            for task in routing_tasks
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    trust_path = args.signer_trust_policy or _trust_path_from_environment()
    transfer_command = "transfer" in args.command
    if trust_path is None and (transfer_command or not args.allow_untrusted_signers):
        parser.error(
            "--signer-trust-policy or GLASSBOX_SIGNER_TRUST_POLICY_PATH is required; "
            "use --allow-untrusted-signers only for development"
        )
    signer_trust_policy = load_signer_trust_policy(trust_path) if trust_path is not None else None
    if transfer_command:
        if signer_trust_policy is None:  # pragma: no cover - parser gate
            raise AssertionError("state transfer requires signer trust")
        transfer_result = _transfer_result(
            args,
            parser,
            signer_trust_policy=signer_trust_policy,
        )
        print(json.dumps(transfer_result, indent=2, sort_keys=True))
        return 0
    postgres = args.command.startswith("postgres-")
    store: TransactionalInvalidationStore = (
        _postgres_store(
            args.dsn_env,
            args.schema,
            initialize_schema=args.command == "postgres-init",
            signer_trust_policy=signer_trust_policy,
        )
        if postgres
        else _store(args.database, signer_trust_policy)
    )
    result: dict[str, Any]
    if args.command in {
        "init",
        "verify",
        "status",
        "postgres-init",
        "postgres-verify",
        "postgres-status",
    }:
        result = _status(store)
    elif args.command in {"register-receipt", "postgres-register-receipt"}:
        receipt = _read_receipt(args.receipt)
        proof = FieldLineageProof(
            coverage=FieldCoverage(args.field_coverage),
            rule_id=args.field_rule,
            wildcard_query=_wildcard(args.wildcard_query),
        )
        inserted = store.register(
            receipt,
            field_lineage=proof,
            superseded_by=args.superseded_by,
        )
        result = _status(store)
        result["registration"] = {
            "receipt_id": receipt.get("receipt_id"),
            "inserted": inserted,
        }
    else:  # pragma: no cover - argparse owns the closed command set
        raise AssertionError("unsupported state command")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def _trust_path_from_environment() -> Path | None:
    value = os.getenv("GLASSBOX_SIGNER_TRUST_POLICY_PATH")
    return Path(value) if value else None


if __name__ == "__main__":
    raise SystemExit(main())
