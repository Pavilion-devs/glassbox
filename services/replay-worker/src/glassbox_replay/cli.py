"""Guarded CLI for replay-bundle creation, planning, and no-side-effect rendering."""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey
from glassbox_replay.bundle import (
    ReplayBundleError,
    build_replay_bundle,
    verify_replay_bundle,
)
from glassbox_replay.dry_run import DryRunExecutor
from glassbox_replay.models import (
    ContextReplacement,
    ModelDeterminism,
    ModelReplayConfig,
    ReplayInputError,
    ReplayMode,
    ReplaySupplement,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
)
from glassbox_replay.planner import plan_replay


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-replay")
    commands = parser.add_subparsers(dest="command", required=True)

    bundle = commands.add_parser("bundle", help="build a signed replay bundle from one DBOM")
    bundle.add_argument("receipt", type=Path)
    _add_bundle_options(bundle)

    verify = commands.add_parser("verify-bundle", help="verify a bundle and source binding")
    verify.add_argument("bundle", type=Path)
    verify.add_argument("source_receipt", type=Path)
    verify.add_argument("--allow-unsigned-bundle", action="store_true")
    verify.add_argument("--allow-unsigned-source", action="store_true")

    dry = commands.add_parser(
        "dry-run",
        help="build, plan, and render a replay without invoking any tool",
    )
    dry.add_argument("receipt", type=Path)
    dry.add_argument("--inventory", type=Path, required=True)
    dry.add_argument("--evaluated-at", required=True)
    _add_bundle_options(dry)
    return parser


def _add_bundle_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--mode", choices=[item.value for item in ReplayMode], required=True)
    parser.add_argument("--supplement", type=Path)
    parser.add_argument("--context-replacements", type=Path)
    parser.add_argument("--signing-key-env", default="GLASSBOX_REPLAY_SIGNING_KEY")
    parser.add_argument("--signing-key-id", default="glassbox-replay-operator")
    parser.add_argument("--allow-unsigned-source", action="store_true")


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify-bundle":
            verification = verify_replay_bundle(
                _object(args.bundle),
                require_signature=not args.allow_unsigned_bundle,
                source_receipt=_object(args.source_receipt),
                require_source_signature=not args.allow_unsigned_source,
            )
            print(json.dumps(verification.to_dict(), indent=2, sort_keys=True))
            return 0 if verification.valid else 1

        receipt = _object(args.receipt)
        bundle = build_replay_bundle(
            receipt,
            mode=ReplayMode(args.mode),
            supplement=_supplement(args.supplement),
            context_replacements=_replacements(args.context_replacements),
            signing_keys=(_signing_key(args.signing_key_env, args.signing_key_id),),
            require_source_signature=not args.allow_unsigned_source,
        )
        if args.command == "bundle":
            print(json.dumps(bundle, indent=2, sort_keys=True))
            return 0
        if args.command == "dry-run":
            plan = plan_replay(
                bundle,
                source_receipt=receipt,
                inventory=_inventory(args.inventory),
                evaluated_at=args.evaluated_at,
                require_source_signature=not args.allow_unsigned_source,
            )
            dry_report = DryRunExecutor().render(
                bundle,
                plan,
                source_receipt=receipt,
                require_source_signature=not args.allow_unsigned_source,
            )
            print(
                json.dumps(
                    {
                        "bundle": bundle,
                        "plan": plan.to_dict(),
                        "dry_run": dry_report.to_dict(),
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        raise AssertionError("unsupported replay command")  # pragma: no cover
    except (OSError, json.JSONDecodeError, ReplayBundleError, ReplayInputError, ValueError) as exc:
        print(f"glassbox-replay: {exc}", file=sys.stderr)
        return 2


def _object(path: Path) -> dict[str, Any]:
    loaded = json.loads(path.read_bytes())
    if not isinstance(loaded, dict):
        raise ReplayInputError(f"{path.name} must contain a JSON object")
    return loaded


def _supplement(path: Path | None) -> ReplaySupplement:
    if path is None:
        return ReplaySupplement()
    value = _object(path)
    raw_configs = value.get("model_configs", [])
    if not isinstance(raw_configs, list) or not all(
        isinstance(item, Mapping) for item in raw_configs
    ):
        raise ReplayInputError("model_configs must be an array of objects")
    configs = tuple(
        ModelReplayConfig(
            model_id=_text(item, "model_id"),
            provider_id=_text(item, "provider_id"),
            parameters_digest=_text(item, "parameters_digest"),
            determinism=ModelDeterminism(_text(item, "determinism")),
            verification_authority=_text(item, "verification_authority"),
        )
        for item in raw_configs
    )
    return ReplaySupplement(
        input_digest=_optional_text(value, "input_digest"),
        input_reference=_optional_text(value, "input_reference"),
        feature_flags_digest=_optional_text(value, "feature_flags_digest"),
        model_configs=configs,
    )


def _replacements(path: Path | None) -> tuple[ContextReplacement, ...]:
    if path is None:
        return ()
    loaded = json.loads(path.read_bytes())
    if not isinstance(loaded, list) or not all(isinstance(item, Mapping) for item in loaded):
        raise ReplayInputError("context replacements must be a JSON array of objects")
    return tuple(
        ContextReplacement(
            evidence_id=_text(item, "evidence_id"),
            representation_digest=_text(item, "representation_digest"),
            verification_authority=_optional_text(item, "verification_authority"),
        )
        for item in loaded
    )


def _inventory(path: Path) -> ResourceInventory:
    value = _object(path)
    raw = value.get("resources")
    if not isinstance(raw, list) or not all(isinstance(item, Mapping) for item in raw):
        raise ReplayInputError("resources must be an array of objects")
    return ResourceInventory(
        tuple(
            ResourceAvailability(
                kind=ResourceKind(_text(item, "kind")),
                resource_id=_text(item, "resource_id"),
                version=_text(item, "version"),
                source_digest=_optional_text(item, "source_digest"),
                schema_digest=_optional_text(item, "schema_digest"),
                rollback_contract_digest=_optional_text(item, "rollback_contract_digest"),
            )
            for item in raw
        )
    )


def _signing_key(environment_name: str, key_id: str) -> SigningKey:
    encoded = os.getenv(environment_name)
    if encoded is None or not encoded:
        raise ReplayInputError("configured replay signing-key environment variable is unset")
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), altchars=b"-_", validate=True)
        private = Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, TypeError) as exc:
        raise ReplayInputError(
            "configured replay signing key must be a base64url Ed25519 private key"
        ) from exc
    return SigningKey(key_id, private)


def _text(value: Mapping[str, Any], key: str) -> str:
    selected = value.get(key)
    if not isinstance(selected, str) or not selected:
        raise ReplayInputError(f"{key} must be a non-empty string")
    return selected


def _optional_text(value: Mapping[str, Any], key: str) -> str | None:
    selected = value.get(key)
    if selected is not None and (not isinstance(selected, str) or not selected):
        raise ReplayInputError(f"{key} must be null or a non-empty string")
    return selected


if __name__ == "__main__":
    raise SystemExit(main())
