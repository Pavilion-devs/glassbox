"""Standalone DataHub Actions plugin packaging and config-doctor tests."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from glassbox_invalidation.plugin_cli import (
    ActionPluginConfigurationError,
    inspect_installation,
    main,
    validate_pipeline_config,
    validate_pipeline_file,
)


def _pipeline() -> dict[str, object]:
    return {
        "name": "glassbox_invalidation",
        "source": {"type": "kafka", "config": {}},
        "action": {
            "type": "glassbox_invalidation",
            "config": {
                "state_database_path": ".glassbox/invalidation.sqlite3",
                "require_receipt_signature": True,
                "signer_trust_policy_path": "config/trusted-signers.json",
            },
        },
        "datahub": {"server": "https://datahub.example.invalid"},
    }


def test_config_doctor_returns_only_bounded_operational_facts() -> None:
    pipeline = _pipeline()
    pipeline["datahub"]["token"] = "never-return-this-token"

    report = validate_pipeline_config(pipeline)

    assert report == {
        "valid": True,
        "plugin_name": "glassbox_invalidation",
        "plugin_class": "glassbox_invalidation.datahub_action:GlassBoxInvalidationAction",
        "state_profile": "SQLITE",
        "signature_required": True,
        "trusted_signer_enforced": True,
        "owner_routing_configured": False,
        "datahub_connection_configured": True,
        "event_source_type": "kafka",
        "network_calls_performed": 0,
        "sensitive_values_returned": False,
    }
    assert "never-return-this-token" not in repr(report)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(action={"type": "hello_world", "config": {}}),
        lambda value: value["action"]["config"].update(unknown_option="secret"),
        lambda value: value.pop("datahub"),
        lambda value: value["datahub"].update(server=""),
        lambda value: value.pop("source"),
    ],
)
def test_config_doctor_fails_closed_on_wrong_plugin_or_incomplete_pipeline(mutation) -> None:
    pipeline = _pipeline()
    mutation(pipeline)

    with pytest.raises(ActionPluginConfigurationError):
        validate_pipeline_config(pipeline)


def test_example_pipeline_and_installed_entry_point_are_valid() -> None:
    root = Path(__file__).parents[2]

    config_report = validate_pipeline_file(root / "examples/datahub-actions-invalidation.yml")
    install_report = inspect_installation()

    assert config_report["valid"] is True
    assert install_report["valid"] is True
    assert install_report["matching_entry_points"] == 1
    assert install_report["distributions"] == ["glassbox-core"]


def test_cli_error_is_machine_readable_and_does_not_echo_invalid_content(tmp_path: Path) -> None:
    pipeline = tmp_path / "invalid.yml"
    pipeline.write_text("token: never-echo-this\n", encoding="utf-8")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "glassbox_invalidation.plugin_cli",
            "validate-config",
            str(pipeline),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 2
    report = json.loads(completed.stdout)
    assert report["error_code"] == "ACTION_PLUGIN_CONFIGURATION_INVALID"
    assert "never-echo-this" not in completed.stdout
    assert completed.stderr == ""


def test_cli_main_covers_success_invalid_config_and_missing_install(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    valid = tmp_path / "valid.yml"
    valid.write_text(
        """
source:
  type: kafka
action:
  type: glassbox_invalidation
  config:
    state_database_path: state.sqlite3
    signer_trust_policy_path: trusted-signers.json
datahub:
  server: http://localhost:8080
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["glassbox-datahub-action", "validate-config", str(valid)])
    main()
    assert json.loads(capsys.readouterr().out)["valid"] is True

    invalid = tmp_path / "invalid-main.yml"
    invalid.write_text("not: a-pipeline", encoding="utf-8")
    monkeypatch.setattr(
        sys,
        "argv",
        ["glassbox-datahub-action", "validate-config", str(invalid)],
    )
    with pytest.raises(SystemExit) as invalid_exit:
        main()
    assert invalid_exit.value.code == 2
    assert json.loads(capsys.readouterr().out)["valid"] is False

    monkeypatch.setattr(sys, "argv", ["glassbox-datahub-action", "inspect-install"])
    monkeypatch.setattr(
        "glassbox_invalidation.plugin_cli.inspect_installation",
        lambda: {"valid": False},
    )
    with pytest.raises(SystemExit) as missing_exit:
        main()
    assert missing_exit.value.code == 1
