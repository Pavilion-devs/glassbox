"""Contracts for the isolated one-command flagship estate."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import pytest
from examples.flagship_demo import (
    _REQUIRED_COMPOSE_MARKERS,
    EstatePorts,
    EstateRunError,
    _compose_base,
    _load_upstream_compose,
    _parse_last_json_object,
    _validate_flagship_report,
    run_flagship_estate,
)

ROOT = Path(__file__).resolve().parents[2]
LIVE_REPORT = ROOT / "docs" / "compatibility" / "datahub-1.6.0-flagship-causal-recovery.live.json"
ONE_COMMAND_REPORT = (
    ROOT / "docs" / "compatibility" / "datahub-1.6.0-one-command-flagship.live.json"
)


def _compose_fixture() -> bytes:
    return b"\n".join(_REQUIRED_COMPOSE_MARKERS) + b"\n"


def _args(tmp_path: Path, compose_file: Path, output: Path) -> argparse.Namespace:
    return argparse.Namespace(
        allow_live=True,
        state_dir=tmp_path / "state",
        output=output,
        compose_file=compose_file,
        docker=Path("/bin/echo"),
        uvx=Path("/bin/echo"),
        keep_estate=False,
        wait_timeout_seconds=30,
        proof_run_offset_ms=0,
        gms_port=18080,
        frontend_port=19002,
        otlp_port=14319,
        kafka_port=19092,
        mysql_port=13306,
        opensearch_port=19200,
        postgres_port=15432,
    )


def test_estate_ports_reject_invalid_or_overlapping_publications() -> None:
    assert EstatePorts().gms == 18080
    with pytest.raises(ValueError, match="between 1 and 65535"):
        EstatePorts(gms=0)
    with pytest.raises(ValueError, match="must be unique"):
        EstatePorts(gms=19002)


def test_local_compose_override_is_validated_hashed_and_copied(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    destination = tmp_path / "runtime" / "datahub.yml"
    value = _compose_fixture()
    source.write_bytes(value)

    source_kind, digest = _load_upstream_compose(
        destination,
        local_override=source,
    )

    assert source_kind == "LOCAL_OVERRIDE"
    assert digest == hashlib.sha256(value).hexdigest()
    assert destination.read_bytes() == value

    source.write_text("services: {}\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="missing required service contracts"):
        _load_upstream_compose(destination, local_override=source)


def test_compose_command_uses_exact_project_and_both_files(tmp_path: Path) -> None:
    command = _compose_base(
        Path("/bin/echo"),
        tmp_path / "upstream.yml",
        tmp_path / "overlay.yml",
    )

    assert command[:4] == ("/bin/echo", "compose", "--project-name", "glassbox-flagship")
    assert command.count("--file") == 2
    assert command[-2:] == ("--profile", "quickstart")


def test_child_json_parser_ignores_build_logs_but_requires_final_object() -> None:
    assert _parse_last_json_object('build {not-json}\n{"valid": true}\n') == {"valid": True}
    with pytest.raises(RuntimeError, match="did not finish with a JSON object"):
        _parse_last_json_object("build complete")


def test_committed_live_report_satisfies_one_command_acceptance_boundary() -> None:
    report = json.loads(LIVE_REPORT.read_text(encoding="utf-8"))
    _validate_flagship_report(report)

    report["runtime"]["datahub_core_commit"] = "0" * 40
    with pytest.raises(RuntimeError, match="runtime drifted"):
        _validate_flagship_report(report)


def test_committed_one_command_report_is_raw_free_and_records_cleanup() -> None:
    report = json.loads(ONE_COMMAND_REPORT.read_text(encoding="utf-8"))

    assert report["valid"]
    assert report["scenario"] == "GLASSBOX_ONE_COMMAND_FLAGSHIP_ESTATE"
    assert report["estate"]["compose_project"] == "glassbox-flagship"
    assert report["estate"]["compose_source"] == "LOCAL_OVERRIDE"
    assert report["estate"]["cleanup_succeeded"] is True
    assert report["estate"]["kept_running"] is False
    assert len(report["estate"]["service_images"]) == 8
    _validate_flagship_report(report["flagship"])
    rendered = json.dumps(report, sort_keys=True)
    assert "/" + "Users/" not in rendered
    assert "postgresql://" not in rendered
    assert "glassbox-local-only" not in rendered


def test_orchestrator_runs_real_flagship_contract_and_always_cleans_its_project(
    tmp_path: Path,
) -> None:
    compose_file = tmp_path / "upstream.yml"
    compose_file.write_bytes(_compose_fixture())
    output = tmp_path / "one-command.json"
    live = LIVE_REPORT.read_text(encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def fake_runner(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        del cwd
        commands.append(command)
        assert environment["DATAHUB_VERSION"] == "v1.6.0"
        assert "GLASSBOX_STATE_POSTGRES_DSN" not in environment or (
            environment["GLASSBOX_STATE_POSTGRES_DSN"].startswith("postgresql://glassbox:")
        )
        if "images" in command:
            stdout = json.dumps(
                [
                    {
                        "ContainerName": "glassbox-flagship-datahub-gms-quickstart-1",
                        "Repository": "acryldata/datahub-gms",
                        "Tag": "v1.6.0",
                        "ID": "sha256:synthetic",
                    }
                ]
            )
        elif "scripts.build_replay_sandbox" in command:
            stdout = json.dumps(
                {
                    "valid": True,
                    "image_digest": "sha256:" + "a" * 64,
                    "raw_values_retained": False,
                }
            )
        elif "examples.end_to_end_flagship" in command:
            stdout = live
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    report = run_flagship_estate(
        _args(tmp_path, compose_file, output),
        command_runner=fake_runner,
    )

    assert report["valid"]
    assert report["estate"]["compose_source"] == "LOCAL_OVERRIDE"
    assert report["estate"]["cleanup_succeeded"] is True
    assert report["flagship"]["valid"]
    assert output.exists()
    assert any("up" in command for command in commands)
    assert any("down" in command and "--volumes" in command for command in commands)
    rendered = output.read_text(encoding="utf-8")
    assert "glassbox-local-only" not in rendered
    assert "postgresql://" not in rendered


def test_kept_estate_retains_the_exact_live_state_schema(tmp_path: Path) -> None:
    compose_file = tmp_path / "upstream.yml"
    compose_file.write_bytes(_compose_fixture())
    args = _args(tmp_path, compose_file, tmp_path / "kept.json")
    args.keep_estate = True
    live = LIVE_REPORT.read_text(encoding="utf-8")
    commands: list[tuple[str, ...]] = []

    def fake_runner(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        del cwd, environment
        commands.append(command)
        if "images" in command:
            stdout = json.dumps([])
        elif "scripts.build_replay_sandbox" in command:
            stdout = json.dumps({"valid": True, "image_digest": "sha256:" + "a" * 64})
        elif "examples.end_to_end_flagship" in command:
            stdout = live
        else:
            stdout = ""
        return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

    report = run_flagship_estate(args, command_runner=fake_runner)

    schema = report["estate"]["state_postgres_schema"]
    assert isinstance(schema, str) and schema.startswith("gbx_console_")
    child = next(command for command in commands if "examples.end_to_end_flagship" in command)
    assert child[child.index("--state-postgres-schema") + 1] == schema
    assert "--keep-state-schema" in child
    assert not any("down" in command for command in commands)


def test_failed_estate_start_is_bounded_and_still_cleans_the_exact_project(
    tmp_path: Path,
) -> None:
    compose_file = tmp_path / "upstream.yml"
    compose_file.write_bytes(_compose_fixture())
    commands: list[tuple[str, ...]] = []

    def failing_runner(
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: dict[str, str],
    ) -> subprocess.CompletedProcess[str]:
        del cwd, environment
        commands.append(command)
        if "up" in command:
            raise subprocess.CalledProcessError(
                17,
                command,
                output="forbidden-child-output",
                stderr="forbidden-child-error",
            )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    with pytest.raises(EstateRunError) as raised:
        run_flagship_estate(
            _args(tmp_path, compose_file, tmp_path / "failure.json"),
            command_runner=failing_runner,
        )

    assert raised.value.stage == "estate-start-and-health"
    assert "forbidden-child-output" not in str(raised.value)
    assert "forbidden-child-error" not in str(raised.value)
    assert any("down" in command and "--volumes" in command for command in commands)
