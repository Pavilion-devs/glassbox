"""Fail-closed OCI isolation for one digest-pinned read-only capability."""

from __future__ import annotations

import hashlib
import json
import os
import selectors
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from glassbox_dbom.canonical import canonicalize

ISOLATION_PROFILE_VERSION = "glassbox.oci-read-only.v1"
_ATTESTATION_DOMAIN = b"glassbox.replay.isolation-attestation.v1\0"
_IMAGE_DIGEST_PREFIX = "sha256:"


class IsolationExecutionError(RuntimeError):
    """Raised when an isolated capability cannot prove the required controls."""


@dataclass(frozen=True)
class ContainerIsolationProfile:
    """Exact OCI image, entry point, and non-negotiable runtime ceilings."""

    image_digest: str
    command: tuple[str, ...]
    capability_source_digest: str
    capability_schema_digest: str
    timeout_seconds: float = 10.0
    memory_bytes: int = 134_217_728
    pids_limit: int = 32
    cpus: float = 0.5
    tmpfs_bytes: int = 16_777_216
    max_input_bytes: int = 1_048_576
    max_output_bytes: int = 1_048_576
    profile_version: str = ISOLATION_PROFILE_VERSION

    def __post_init__(self) -> None:
        digest = self.image_digest.removeprefix(_IMAGE_DIGEST_PREFIX)
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise IsolationExecutionError("image_digest must be an exact sha256 OCI image ID")
        if not self.command or any(not item for item in self.command):
            raise IsolationExecutionError("isolated capability command must be non-empty")
        for digest_value, name in (
            (self.capability_source_digest, "capability_source_digest"),
            (self.capability_schema_digest, "capability_schema_digest"),
        ):
            if len(digest_value) != 64 or any(
                character not in "0123456789abcdef" for character in digest_value
            ):
                raise IsolationExecutionError(f"{name} must be a lowercase SHA-256 digest")
        if self.timeout_seconds <= 0 or self.timeout_seconds > 300:
            raise IsolationExecutionError("timeout_seconds must be between 0 and 300")
        if self.memory_bytes < 16_777_216:
            raise IsolationExecutionError("memory_bytes must be at least 16 MiB")
        if self.pids_limit < 1 or self.pids_limit > 256:
            raise IsolationExecutionError("pids_limit must be between 1 and 256")
        if self.cpus <= 0 or self.cpus > 4:
            raise IsolationExecutionError("cpus must be greater than 0 and at most 4")
        for byte_limit, name in (
            (self.tmpfs_bytes, "tmpfs_bytes"),
            (self.max_input_bytes, "max_input_bytes"),
            (self.max_output_bytes, "max_output_bytes"),
        ):
            if byte_limit <= 0:
                raise IsolationExecutionError(f"{name} must be greater than 0")

    @property
    def command_digest(self) -> str:
        return hashlib.sha256(canonicalize(list(self.command))).hexdigest()


@dataclass(frozen=True)
class IsolationAttestation:
    """Host-created, content-addressed proof of the exact enforced boundary."""

    attestation_id: str
    profile_version: str
    runtime: str
    image_digest: str
    command_digest: str
    capability_source_digest: str
    capability_schema_digest: str
    network_access: str
    root_filesystem: str
    host_environment: str
    linux_capabilities: str
    no_new_privileges: bool
    timeout_seconds: float
    memory_bytes: int
    pids_limit: int
    cpus: float
    tmpfs_bytes: int
    exit_code: int
    stdout_digest: str
    network_probe_denied: bool
    root_write_probe_denied: bool
    host_environment_probe_absent: bool
    image_identity_verified: bool
    capability_labels_verified: bool

    @property
    def valid(self) -> bool:
        return (
            self.attestation_id == _attestation_id(self._material())
            and self.runtime == "OCI_CONTAINER"
            and self.network_access == "DENIED"
            and self.root_filesystem == "READ_ONLY"
            and self.host_environment == "NOT_INHERITED"
            and self.linux_capabilities == "ALL_DROPPED"
            and self.no_new_privileges
            and self.exit_code == 0
            and self.network_probe_denied
            and self.root_write_probe_denied
            and self.host_environment_probe_absent
            and self.image_identity_verified
            and self.capability_labels_verified
        )

    def to_dict(self) -> dict[str, Any]:
        return {"attestation_id": self.attestation_id, **self._material()}

    def _material(self) -> dict[str, Any]:
        return {
            "profile_version": self.profile_version,
            "runtime": self.runtime,
            "image_digest": self.image_digest,
            "command_digest": self.command_digest,
            "capability_source_digest": self.capability_source_digest,
            "capability_schema_digest": self.capability_schema_digest,
            "network_access": self.network_access,
            "root_filesystem": self.root_filesystem,
            "host_environment": self.host_environment,
            "linux_capabilities": self.linux_capabilities,
            "no_new_privileges": self.no_new_privileges,
            "timeout_seconds": self.timeout_seconds,
            "memory_bytes": self.memory_bytes,
            "pids_limit": self.pids_limit,
            "cpus": self.cpus,
            "tmpfs_bytes": self.tmpfs_bytes,
            "exit_code": self.exit_code,
            "stdout_digest": self.stdout_digest,
            "network_probe_denied": self.network_probe_denied,
            "root_write_probe_denied": self.root_write_probe_denied,
            "host_environment_probe_absent": self.host_environment_probe_absent,
            "image_identity_verified": self.image_identity_verified,
            "capability_labels_verified": self.capability_labels_verified,
            "raw_values_retained": False,
        }


@dataclass(frozen=True)
class IsolatedCapabilityOutput:
    """Transient child output plus its serializable, raw-free host attestation."""

    output: object = field(repr=False, compare=False)
    attestation: IsolationAttestation

    def __post_init__(self) -> None:
        if not self.attestation.valid:
            raise IsolationExecutionError("isolated capability attestation is invalid")


@dataclass(frozen=True)
class ProcessOutcome:
    """Bounded process result returned by the injectable execution seam."""

    returncode: int
    stdout: bytes
    stderr: bytes


class ProcessRunner(Protocol):
    """Narrow process boundary used by the OCI runner and deterministic tests."""

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessOutcome: ...


class BoundedSubprocessRunner:
    """Execute without inherited environment or descriptors and cap captured output."""

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessOutcome:
        process = subprocess.Popen(
            tuple(argv),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd="/",
            env={},
            close_fds=True,
            start_new_session=True,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        try:
            process.stdin.write(stdin)
            process.stdin.close()
            return _read_bounded_process(
                process,
                timeout_seconds=timeout_seconds,
                max_output_bytes=max_output_bytes,
            )
        except BaseException:
            _terminate_process(process)
            raise


class ContainerCapabilityRunner:
    """Invoke one fixed capability in a hardened, digest-pinned OCI container."""

    def __init__(
        self,
        profile: ContainerIsolationProfile,
        *,
        docker_executable: str | None = None,
        process_runner: ProcessRunner | None = None,
    ) -> None:
        selected = docker_executable or shutil.which("docker")
        if selected is None or not Path(selected).is_absolute():
            raise IsolationExecutionError("an absolute Docker executable is required")
        self.profile = profile
        self._docker = selected
        self._runner = process_runner or BoundedSubprocessRunner()

    def __call__(self, action_input: object) -> IsolatedCapabilityOutput:
        self._verify_image()
        request = canonicalize(
            {
                "protocol_version": "glassbox.isolated-capability.v1",
                "input": action_input,
            }
        )
        if len(request) > self.profile.max_input_bytes:
            raise IsolationExecutionError("isolated capability input exceeds its byte limit")
        outcome = self._runner.run(
            self._argv(),
            stdin=request,
            timeout_seconds=self.profile.timeout_seconds,
            max_output_bytes=self.profile.max_output_bytes,
        )
        if outcome.returncode != 0:
            raise IsolationExecutionError(
                f"isolated capability exited with status {outcome.returncode}"
            )
        response = _parse_response(outcome.stdout)
        probes = response["probes"]
        assert isinstance(probes, Mapping)
        network_denied = probes.get("network_denied") is True
        root_write_denied = probes.get("root_write_denied") is True
        host_environment_absent = probes.get("host_environment_absent") is True
        if not (network_denied and root_write_denied and host_environment_absent):
            raise IsolationExecutionError("isolated capability runtime probes did not all pass")
        material: dict[str, Any] = {
            "profile_version": self.profile.profile_version,
            "runtime": "OCI_CONTAINER",
            "image_digest": self.profile.image_digest,
            "command_digest": self.profile.command_digest,
            "capability_source_digest": self.profile.capability_source_digest,
            "capability_schema_digest": self.profile.capability_schema_digest,
            "network_access": "DENIED",
            "root_filesystem": "READ_ONLY",
            "host_environment": "NOT_INHERITED",
            "linux_capabilities": "ALL_DROPPED",
            "no_new_privileges": True,
            "timeout_seconds": self.profile.timeout_seconds,
            "memory_bytes": self.profile.memory_bytes,
            "pids_limit": self.profile.pids_limit,
            "cpus": self.profile.cpus,
            "tmpfs_bytes": self.profile.tmpfs_bytes,
            "exit_code": outcome.returncode,
            "stdout_digest": hashlib.sha256(outcome.stdout).hexdigest(),
            "network_probe_denied": network_denied,
            "root_write_probe_denied": root_write_denied,
            "host_environment_probe_absent": host_environment_absent,
            "image_identity_verified": True,
            "capability_labels_verified": True,
            "raw_values_retained": False,
        }
        attestation = IsolationAttestation(
            attestation_id=_attestation_id(material),
            **{key: value for key, value in material.items() if key != "raw_values_retained"},
        )
        return IsolatedCapabilityOutput(response["output"], attestation)

    def _verify_image(self) -> None:
        outcome = self._runner.run(
            (self._docker, "image", "inspect", self.profile.image_digest),
            stdin=b"",
            timeout_seconds=self.profile.timeout_seconds,
            max_output_bytes=self.profile.max_output_bytes,
        )
        if outcome.returncode != 0:
            raise IsolationExecutionError("OCI image inspection failed")
        try:
            response = json.loads(outcome.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IsolationExecutionError("OCI image inspection returned invalid JSON") from exc
        if (
            not isinstance(response, list)
            or len(response) != 1
            or not isinstance(response[0], Mapping)
        ):
            raise IsolationExecutionError("OCI image inspection returned an invalid result")
        image = response[0]
        config = image.get("Config")
        labels = config.get("Labels") if isinstance(config, Mapping) else None
        if image.get("Id") != self.profile.image_digest:
            raise IsolationExecutionError("OCI image identity does not match its pinned digest")
        expected_labels = {
            "org.glassbox.capability.protocol": "glassbox.isolated-capability.v1",
            "org.glassbox.capability.source-sha256": self.profile.capability_source_digest,
            "org.glassbox.capability.schema-sha256": self.profile.capability_schema_digest,
        }
        if not isinstance(labels, Mapping) or any(
            labels.get(key) != value for key, value in expected_labels.items()
        ):
            raise IsolationExecutionError("OCI capability labels do not match exact tool pins")

    def _argv(self) -> tuple[str, ...]:
        profile = self.profile
        return (
            self._docker,
            "run",
            "--rm",
            "--interactive",
            "--network",
            "none",
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(profile.pids_limit),
            "--memory",
            str(profile.memory_bytes),
            "--cpus",
            str(profile.cpus),
            "--tmpfs",
            f"/tmp:rw,noexec,nosuid,nodev,size={profile.tmpfs_bytes}",
            profile.image_digest,
            *profile.command,
        )


def _parse_response(raw: bytes) -> Mapping[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IsolationExecutionError("isolated capability returned invalid JSON") from exc
    if not isinstance(value, Mapping):
        raise IsolationExecutionError("isolated capability response must be an object")
    if value.get("protocol_version") != "glassbox.isolated-capability.v1":
        raise IsolationExecutionError("isolated capability protocol version mismatch")
    if "output" not in value or not isinstance(value.get("probes"), Mapping):
        raise IsolationExecutionError("isolated capability response is incomplete")
    return value


def _read_bounded_process(
    process: subprocess.Popen[bytes],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> ProcessOutcome:
    assert process.stdout is not None
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    deadline = time.monotonic() + timeout_seconds
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise IsolationExecutionError("isolated capability exceeded its timeout")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, 65_536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                selected = buffers[key.data]
                selected.extend(chunk)
                if len(selected) > max_output_bytes:
                    raise IsolationExecutionError(
                        f"isolated capability {key.data} exceeded its byte limit"
                    )
        remaining = deadline - time.monotonic()
        try:
            returncode = process.wait(timeout=max(remaining, 0.001))
        except subprocess.TimeoutExpired as exc:
            raise IsolationExecutionError("isolated capability exceeded its timeout") from exc
        return ProcessOutcome(returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))
    finally:
        selector.close()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        return
    process.wait()


def _attestation_id(material: Mapping[str, Any]) -> str:
    digest = hashlib.sha256(_ATTESTATION_DOMAIN + canonicalize(material)).hexdigest()
    return f"gbx:isolation-attestation:sha256:{digest}"


__all__ = [
    "ISOLATION_PROFILE_VERSION",
    "BoundedSubprocessRunner",
    "ContainerCapabilityRunner",
    "ContainerIsolationProfile",
    "IsolatedCapabilityOutput",
    "IsolationAttestation",
    "IsolationExecutionError",
    "ProcessOutcome",
    "ProcessRunner",
]
