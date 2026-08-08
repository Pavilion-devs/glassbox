"""Offline packaging and configuration checks for the DataHub Actions plugin."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping
from importlib.metadata import entry_points
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from glassbox_invalidation.datahub_action import GlassBoxInvalidationActionConfig

PLUGIN_NAME = "glassbox_invalidation"
PLUGIN_CLASS = "glassbox_invalidation.datahub_action:GlassBoxInvalidationAction"
_ALLOWED_PLUGIN_TYPES = frozenset({PLUGIN_NAME, PLUGIN_CLASS})


class ActionPluginConfigurationError(ValueError):
    """Raised when a pipeline cannot safely configure this plugin."""


def validate_pipeline_file(path: Path) -> dict[str, object]:
    """Validate one Actions pipeline without connecting to DataHub or exposing values."""

    if not path.is_file():
        raise ActionPluginConfigurationError("pipeline path must be a regular file")
    try:
        parsed = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ActionPluginConfigurationError("pipeline is not readable YAML") from exc
    return validate_pipeline_config(parsed)


def validate_pipeline_config(value: object) -> dict[str, object]:
    """Return a bounded no-secret summary for a structurally valid pipeline mapping."""

    pipeline = _mapping(value, "pipeline")
    action = _mapping(pipeline.get("action"), "action")
    plugin_type = action.get("type")
    if plugin_type not in _ALLOWED_PLUGIN_TYPES:
        raise ActionPluginConfigurationError(
            "action.type must select the installed GlassBox invalidation plugin"
        )
    raw_config = action.get("config", {})
    config_mapping = _mapping(raw_config, "action.config")
    try:
        config = GlassBoxInvalidationActionConfig.model_validate(config_mapping)
    except ValidationError as exc:
        raise ActionPluginConfigurationError("action.config failed closed validation") from exc

    datahub = _mapping(pipeline.get("datahub"), "datahub")
    server = datahub.get("server")
    if not isinstance(server, str) or not server.strip():
        raise ActionPluginConfigurationError("datahub.server must be a non-empty string")
    source = _mapping(pipeline.get("source"), "source")
    source_type = source.get("type")
    if not isinstance(source_type, str) or not source_type.strip():
        raise ActionPluginConfigurationError("source.type must be a non-empty string")

    return {
        "valid": True,
        "plugin_name": PLUGIN_NAME,
        "plugin_class": PLUGIN_CLASS,
        "state_profile": _state_profile(config),
        "signature_required": config.require_receipt_signature,
        "trusted_signer_enforced": config.signer_trust_policy_path is not None,
        "owner_routing_configured": config.owner_webhook_url is not None,
        "datahub_connection_configured": True,
        "event_source_type": source_type,
        "network_calls_performed": 0,
        "sensitive_values_returned": False,
    }


def inspect_installation() -> dict[str, object]:
    """Inspect only package metadata to prove DataHub can discover the plugin."""

    matches = tuple(
        item
        for item in entry_points(group="datahub_actions.action.plugins")
        if item.name == PLUGIN_NAME and item.value == PLUGIN_CLASS
    )
    distributions = sorted(
        {item.dist.name for item in matches if item.dist is not None and item.dist.name is not None}
    )
    return {
        "valid": len(matches) == 1,
        "plugin_name": PLUGIN_NAME,
        "plugin_class": PLUGIN_CLASS,
        "matching_entry_points": len(matches),
        "distributions": distributions,
        "imports_executed": 0,
        "network_calls_performed": 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-config",
        help="validate a pipeline locally without connecting to DataHub",
    )
    validate.add_argument("pipeline", type=Path)
    subparsers.add_parser(
        "inspect-install",
        help="verify the plugin entry point is installed exactly once",
    )
    args = parser.parse_args()

    try:
        if args.command == "validate-config":
            result = validate_pipeline_file(args.pipeline)
        else:
            result = inspect_installation()
    except ActionPluginConfigurationError:
        result = {
            "valid": False,
            "error_code": "ACTION_PLUGIN_CONFIGURATION_INVALID",
            "network_calls_performed": 0,
            "sensitive_values_returned": False,
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        raise SystemExit(2) from None
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    if not result["valid"]:
        raise SystemExit(1)


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ActionPluginConfigurationError(f"{label} must be an object")
    return value


def _state_profile(config: GlassBoxInvalidationActionConfig) -> str:
    if config.state_database_path is not None:
        return "SQLITE"
    if config.state_postgres_dsn_env is not None:
        return "POSTGRESQL"
    return "JSONL_COMPATIBILITY"


if __name__ == "__main__":
    main()
