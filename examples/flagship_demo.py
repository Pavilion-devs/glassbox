"""Bootstrap, prove, and tear down the complete GlassBox flagship estate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.request import Request, urlopen

DATAHUB_CORE_VERSION = "v1.6.0"
DATAHUB_CORE_COMMIT = "059a36c0b035a6057de00114ccac0ea9003d6bc2"
DATAHUB_SDK_VERSION = "1.6.0.15"
DATAHUB_COMPOSE_URL = (
    "https://raw.githubusercontent.com/datahub-project/datahub/"
    f"{DATAHUB_CORE_COMMIT}/docker/quickstart/docker-compose.quickstart-profile.yml"
)
COMPOSE_PROJECT = "glassbox-flagship"
SANDBOX_TAG = "glassbox-flagship-replay-sandbox:0.1.0"
_MAX_COMPOSE_BYTES = 1_000_000
_REQUIRED_COMPOSE_MARKERS = (
    b"datahub-gms-quickstart:",
    b"frontend-quickstart:",
    b"system-update-quickstart:",
    b"acryldata/datahub-gms:${DATAHUB_VERSION}",
)


class CommandRunner(Protocol):
    """Narrow subprocess boundary used by the live runner and its unit tests."""

    def __call__(
        self,
        command: tuple[str, ...],
        *,
        cwd: Path,
        environment: Mapping[str, str],
    ) -> subprocess.CompletedProcess[str]: ...


class EstateRunError(RuntimeError):
    """Bounded command failure that never includes child output or credentials."""

    def __init__(self, stage: str, error_type: str) -> None:
        super().__init__(f"flagship estate stage {stage} failed with {error_type}")
        self.stage = stage
        self.error_type = error_type


@dataclass(frozen=True)
class EstatePorts:
    """Host ports published only by the disposable flagship compose project."""

    gms: int = 18080
    frontend: int = 19002
    otlp: int = 14319
    kafka: int = 19092
    mysql: int = 13306
    opensearch: int = 19200
    postgres: int = 15432

    def __post_init__(self) -> None:
        values = tuple(self.to_dict().values())
        if any(value < 1 or value > 65535 for value in values):
            raise ValueError("flagship estate ports must be between 1 and 65535")
        if len(values) != len(set(values)):
            raise ValueError("flagship estate ports must be unique")

    def to_dict(self) -> dict[str, int]:
        return {
            "gms": self.gms,
            "frontend": self.frontend,
            "otlp": self.otlp,
            "kafka": self.kafka,
            "mysql": self.mysql,
            "opensearch": self.opensearch,
            "postgres": self.postgres,
        }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="glassbox-flagship-demo")
    parser.add_argument("--allow-live", action="store_true", required=True)
    parser.add_argument(
        "--state-dir",
        type=Path,
        default=None,
        help="Disposable runtime directory; defaults to .glassbox/flagship.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional path for the complete raw-free one-command report.",
    )
    parser.add_argument(
        "--compose-file",
        type=Path,
        default=None,
        help=(
            "Explicit local upstream compose override for offline development. "
            "Omit this for the commit-pinned official DataHub compose."
        ),
    )
    parser.add_argument("--docker", type=Path, default=None)
    parser.add_argument("--uvx", type=Path, default=None)
    parser.add_argument("--keep-estate", action="store_true")
    parser.add_argument("--wait-timeout-seconds", type=int, default=600)
    parser.add_argument("--proof-run-offset-ms", type=int, default=0)
    parser.add_argument("--gms-port", type=int, default=EstatePorts.gms)
    parser.add_argument("--frontend-port", type=int, default=EstatePorts.frontend)
    parser.add_argument("--otlp-port", type=int, default=EstatePorts.otlp)
    parser.add_argument("--kafka-port", type=int, default=EstatePorts.kafka)
    parser.add_argument("--mysql-port", type=int, default=EstatePorts.mysql)
    parser.add_argument("--opensearch-port", type=int, default=EstatePorts.opensearch)
    parser.add_argument("--postgres-port", type=int, default=EstatePorts.postgres)
    return parser


def _default_command_runner(
    command: tuple[str, ...],
    *,
    cwd: Path,
    environment: Mapping[str, str],
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=dict(environment),
        check=True,
        capture_output=True,
        text=True,
    )


def _run_stage(
    stage: str,
    command: tuple[str, ...],
    *,
    root: Path,
    environment: Mapping[str, str],
    command_runner: CommandRunner,
) -> subprocess.CompletedProcess[str]:
    try:
        return command_runner(command, cwd=root, environment=environment)
    except subprocess.CalledProcessError as error:
        raise EstateRunError(stage, type(error).__name__) from None


def _absolute_executable(configured: Path | None, name: str) -> Path:
    found = shutil.which(name)
    selected = configured or (Path(found) if found is not None else None)
    if selected is None or not selected.is_absolute() or not selected.is_file():
        raise ValueError(f"an absolute {name} executable is required")
    return selected


def _validate_compose_bytes(value: bytes) -> None:
    if not value or len(value) > _MAX_COMPOSE_BYTES:
        raise RuntimeError("official DataHub compose response has an invalid size")
    missing = [marker.decode() for marker in _REQUIRED_COMPOSE_MARKERS if marker not in value]
    if missing:
        raise RuntimeError("official DataHub compose is missing required service contracts")


def _load_upstream_compose(
    destination: Path,
    *,
    local_override: Path | None,
    timeout_seconds: int = 30,
) -> tuple[str, str]:
    if local_override is not None:
        source = local_override.resolve()
        value = source.read_bytes()
        source_kind = "LOCAL_OVERRIDE"
    else:
        request = Request(
            DATAHUB_COMPOSE_URL,
            headers={"User-Agent": "glassbox-flagship/0.1.0"},
        )
        with urlopen(request, timeout=timeout_seconds) as response:
            value = response.read(_MAX_COMPOSE_BYTES + 1)
        source_kind = "PINNED_UPSTREAM_COMMIT"
    _validate_compose_bytes(value)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".tmp")
    temporary.write_bytes(value)
    temporary.replace(destination)
    return source_kind, hashlib.sha256(value).hexdigest()


def _compose_base(
    docker: Path,
    compose_file: Path,
    overlay_file: Path,
) -> tuple[str, ...]:
    return (
        str(docker),
        "compose",
        "--project-name",
        COMPOSE_PROJECT,
        "--file",
        str(compose_file),
        "--file",
        str(overlay_file),
        "--profile",
        "quickstart",
    )


def _estate_environment(root: Path, state_dir: Path, ports: EstatePorts) -> dict[str, str]:
    environment = dict(os.environ)
    isolated_home = state_dir / "home"
    isolated_home.mkdir(parents=True, exist_ok=True)
    environment.update(
        {
            "DATAHUB_VERSION": DATAHUB_CORE_VERSION,
            "UI_INGESTION_DEFAULT_CLI_VERSION": DATAHUB_SDK_VERSION,
            "METADATA_SERVICE_AUTH_ENABLED": "false",
            "DATAHUB_TOKEN_SERVICE_SIGNING_KEY": hashlib.sha256(
                b"glassbox-flagship-token-signing-key"
            ).hexdigest(),
            "DATAHUB_TOKEN_SERVICE_SALT": hashlib.sha256(
                b"glassbox-flagship-token-service-salt"
            ).hexdigest(),
            "GLASSBOX_GMS_PORT": str(ports.gms),
            "GLASSBOX_FRONTEND_PORT": str(ports.frontend),
            "GLASSBOX_OTLP_PORT": str(ports.otlp),
            "GLASSBOX_KAFKA_PORT": str(ports.kafka),
            "GLASSBOX_MYSQL_PORT": str(ports.mysql),
            "GLASSBOX_OPENSEARCH_PORT": str(ports.opensearch),
            "GLASSBOX_POSTGRES_PORT": str(ports.postgres),
            "GLASSBOX_REPOSITORY_ROOT": str(root),
            "GLASSBOX_ESTATE_HOME": str(isolated_home),
        }
    )
    return environment


def _parse_last_json_object(value: str) -> Mapping[str, Any]:
    decoder = json.JSONDecoder()
    for index in reversed(
        [position for position, character in enumerate(value) if character == "{"]
    ):
        try:
            parsed, end = decoder.raw_decode(value[index:])
        except json.JSONDecodeError:
            continue
        if not value[index + end :].strip() and isinstance(parsed, Mapping):
            return parsed
    raise RuntimeError("child command did not finish with a JSON object")


def _report_mapping(value: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    selected = value.get(key)
    if not isinstance(selected, Mapping):
        raise RuntimeError(f"flagship report {key} must be an object")
    return selected


def _validate_flagship_report(report: Mapping[str, Any]) -> None:
    if not report.get("valid") or report.get("scenario") != "GLASSBOX_DATAHUB_CAUSAL_RECOVERY":
        raise RuntimeError("flagship causal recovery report is invalid")
    runtime = _report_mapping(report, "runtime")
    scope = _report_mapping(report, "scope")
    privacy = _report_mapping(report, "privacy")
    source = _report_mapping(report, "source_decision")
    invalidation = _report_mapping(report, "invalidation")
    replay = _report_mapping(report, "corrected_replay")
    closure = _report_mapping(report, "incident_closure")
    if (
        runtime.get("datahub_core_version") != DATAHUB_CORE_VERSION
        or runtime.get("datahub_core_commit") != DATAHUB_CORE_COMMIT
        or runtime.get("datahub_sdk_version") != DATAHUB_SDK_VERSION
    ):
        raise RuntimeError("flagship DataHub runtime drifted from the pinned compatibility target")
    if not isinstance(scope, Mapping) or any(
        scope.get(key) != "PROVEN"
        for key in (
            "live_datahub_core",
            "live_postgresql",
            "official_datahub_mcp_stdio",
            "glassbox_mcp_stdio",
            "real_datahub_mutation_and_direct_readback",
            "corrected_action_input_execution",
            "process_level_capability_sandbox",
            "incident_resolution_after_recovery",
        )
    ):
        raise RuntimeError("flagship report did not prove every required live boundary")
    if not isinstance(privacy, Mapping) or any(privacy.values()):
        raise RuntimeError("flagship report retained a forbidden raw-value class")
    source_publication = _report_mapping(_report_mapping(source, "publication"), "publication")
    replay_publication = _report_mapping(_report_mapping(replay, "publication"), "publication")
    if (
        source_publication.get("datahub_write_performed") is not True
        or source["completed_redelivery_datahub_write_performed"] is not False
        or invalidation["datahub_writeback_verified"] is not True
        or invalidation["redelivery_emissions"] != 0
        or replay_publication.get("datahub_write_performed") is not True
        or replay["completed_redelivery_datahub_write_performed"] is not False
        or closure["valid"] is not True
    ):
        raise RuntimeError("flagship write/readback or idempotency evidence is incomplete")


def _compose_images(value: str) -> list[dict[str, str]]:
    try:
        parsed: Any = json.loads(value)
        items = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        items = [json.loads(line) for line in value.splitlines() if line.strip()]
    result: list[dict[str, str]] = []
    for item in items:
        if not isinstance(item, Mapping):
            raise RuntimeError("Docker Compose image inventory returned an invalid item")
        result.append(
            {
                key: selected
                for key in ("ContainerName", "Repository", "Tag", "ID")
                if isinstance((selected := item.get(key)), str)
            }
        )
    return sorted(result, key=lambda item: item.get("ContainerName", ""))


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_flagship_estate(
    args: argparse.Namespace,
    *,
    command_runner: CommandRunner = _default_command_runner,
) -> dict[str, Any]:
    """Run the real flagship in an isolated, disposable service estate."""

    if args.wait_timeout_seconds < 1:
        raise ValueError("wait-timeout-seconds must be positive")
    if args.proof_run_offset_ms < 0:
        raise ValueError("proof-run-offset-ms must be non-negative")
    ports = EstatePorts(
        gms=args.gms_port,
        frontend=args.frontend_port,
        otlp=args.otlp_port,
        kafka=args.kafka_port,
        mysql=args.mysql_port,
        opensearch=args.opensearch_port,
        postgres=args.postgres_port,
    )
    root = Path(__file__).resolve().parents[1]
    state_dir = (args.state_dir or (root / ".glassbox" / "flagship")).resolve()
    output = args.output.resolve() if args.output is not None else None
    docker = _absolute_executable(args.docker, "docker")
    uvx = _absolute_executable(args.uvx, "uvx")
    compose_file = state_dir / "datahub.compose.yml"
    overlay_file = root / "examples" / "flagship-estate.compose.yml"
    source_kind, compose_sha256 = _load_upstream_compose(
        compose_file,
        local_override=args.compose_file,
    )
    environment = _estate_environment(root, state_dir, ports)
    compose = _compose_base(docker, compose_file, overlay_file)
    started_at = time.perf_counter()
    retained_state_schema = f"gbx_console_{uuid.uuid4().hex}" if args.keep_estate else None
    estate_started = False
    cleanup_succeeded: bool | None = None
    report: dict[str, Any] | None = None
    try:
        _run_stage(
            "compose-config",
            (*compose, "config", "--quiet"),
            root=root,
            environment=environment,
            command_runner=command_runner,
        )
        estate_started = True
        _run_stage(
            "estate-start-and-health",
            (
                *compose,
                "up",
                "--detach",
                "--pull",
                "missing",
                "--wait",
                "--wait-timeout",
                str(args.wait_timeout_seconds),
            ),
            root=root,
            environment=environment,
            command_runner=command_runner,
        )
        image_process = _run_stage(
            "service-image-inventory",
            (*compose, "images", "--format", "json"),
            root=root,
            environment=environment,
            command_runner=command_runner,
        )
        sandbox_process = _run_stage(
            "replay-sandbox-build",
            (
                sys.executable,
                "-m",
                "scripts.build_replay_sandbox",
                "--docker",
                str(docker),
                "--tag",
                SANDBOX_TAG,
            ),
            root=root,
            environment=environment,
            command_runner=command_runner,
        )
        sandbox = _parse_last_json_object(sandbox_process.stdout)
        image_digest = sandbox.get("image_digest")
        if not sandbox.get("valid") or not isinstance(image_digest, str):
            raise RuntimeError("replay sandbox build did not produce a verified image digest")
        flagship_environment = dict(environment)
        flagship_environment["GLASSBOX_STATE_POSTGRES_DSN"] = (
            f"postgresql://glassbox:glassbox-local-only@localhost:{ports.postgres}/glassbox"
        )
        flagship_command = [
            sys.executable,
            "-m",
            "examples.end_to_end_flagship",
            "--server",
            f"http://localhost:{ports.gms}",
            "--state-postgres-dsn-env",
            "GLASSBOX_STATE_POSTGRES_DSN",
            "--uvx",
            str(uvx),
            "--sandbox-image-digest",
            image_digest,
            "--proof-run-offset-ms",
            str(args.proof_run_offset_ms),
            "--allow-live",
        ]
        if retained_state_schema is not None:
            flagship_command.extend(
                (
                    "--state-postgres-schema",
                    retained_state_schema,
                    "--keep-state-schema",
                )
            )
        flagship_process = _run_stage(
            "causal-flagship",
            tuple(flagship_command),
            root=root,
            environment=flagship_environment,
            command_runner=command_runner,
        )
        flagship = _parse_last_json_object(flagship_process.stdout)
        _validate_flagship_report(flagship)
        report = {
            "valid": True,
            "scenario": "GLASSBOX_ONE_COMMAND_FLAGSHIP_ESTATE",
            "contract_version": "0.1.0",
            "elapsed_seconds": round(time.perf_counter() - started_at, 3),
            "estate": {
                "compose_project": COMPOSE_PROJECT,
                "compose_source": source_kind,
                "compose_url": DATAHUB_COMPOSE_URL
                if source_kind == "PINNED_UPSTREAM_COMMIT"
                else None,
                "compose_sha256": compose_sha256,
                "datahub_core_target": DATAHUB_CORE_VERSION,
                "datahub_core_commit_target": DATAHUB_CORE_COMMIT,
                "published_ports": ports.to_dict(),
                "service_images": _compose_images(image_process.stdout),
                "kept_running": bool(args.keep_estate),
                "state_postgres_schema": retained_state_schema,
            },
            "sandbox": dict(sandbox),
            "flagship": dict(flagship),
            "privacy": {
                "credentials_reported": False,
                "raw_prompts_reported": False,
                "raw_evidence_reported": False,
                "raw_action_inputs_reported": False,
                "raw_outputs_reported": False,
                "private_keys_reported": False,
            },
        }
    finally:
        if estate_started and not args.keep_estate:
            try:
                command_runner(
                    (*compose, "down", "--volumes", "--remove-orphans"),
                    cwd=root,
                    environment=environment,
                )
                cleanup_succeeded = True
            except subprocess.CalledProcessError:
                cleanup_succeeded = False
    if report is None:
        raise RuntimeError("flagship estate completed without a report")
    estate = _report_mapping(report, "estate")
    if isinstance(estate, dict):
        estate["cleanup_succeeded"] = cleanup_succeeded
    if cleanup_succeeded is False:
        report["valid"] = False
        if output is not None:
            _write_report(output, report)
        raise EstateRunError("estate-cleanup", "CalledProcessError")
    if output is not None:
        _write_report(output, report)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        report = run_flagship_estate(args)
    except EstateRunError as error:
        print(
            json.dumps(
                {
                    "valid": False,
                    "scenario": "GLASSBOX_ONE_COMMAND_FLAGSHIP_ESTATE",
                    "failed_stage": error.stage,
                    "error_type": error.error_type,
                    "raw_child_output_returned": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(
            json.dumps(
                {
                    "valid": False,
                    "scenario": "GLASSBOX_ONE_COMMAND_FLAGSHIP_ESTATE",
                    "error_type": type(error).__name__,
                    "raw_child_output_returned": False,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    summary = {
        "valid": report["valid"],
        "scenario": report["scenario"],
        "elapsed_seconds": report["elapsed_seconds"],
        "datahub_core_version": report["flagship"]["runtime"]["datahub_core_version"],
        "datahub_core_commit": report["flagship"]["runtime"]["datahub_core_commit"],
        "causal_recovery_valid": report["flagship"]["valid"],
        "complete_report": str(args.output.resolve()) if args.output is not None else None,
    }
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
