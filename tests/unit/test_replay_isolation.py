"""Digest-pinned OCI replay isolation and execution-binding tests."""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey
from glassbox_replay import (
    BoundedSubprocessRunner,
    ContainerCapabilityRunner,
    ContainerIsolationProfile,
    IsolationExecutionError,
    ProcessOutcome,
    build_replay_receipt,
)
from glassbox_replay.isolation import _parse_response
from tests.unit.test_replay_execution import _bundle, _execute, _source


class FakeProcessRunner:
    def __init__(
        self,
        response: object,
        *,
        returncode: int = 0,
        capability_source_digest: str = "b" * 64,
        capability_schema_digest: str = "c" * 64,
    ) -> None:
        self.response = response
        self.returncode = returncode
        self.capability_source_digest = capability_source_digest
        self.capability_schema_digest = capability_schema_digest
        self.calls: list[tuple[tuple[str, ...], bytes, float, int]] = []

    def run(
        self,
        argv: Any,
        *,
        stdin: bytes,
        timeout_seconds: float,
        max_output_bytes: int,
    ) -> ProcessOutcome:
        self.calls.append((tuple(argv), stdin, timeout_seconds, max_output_bytes))
        if tuple(argv)[1:3] == ("image", "inspect"):
            inspected = [
                {
                    "Id": _profile().image_digest,
                    "Config": {
                        "Labels": {
                            "org.glassbox.capability.protocol": ("glassbox.isolated-capability.v1"),
                            "org.glassbox.capability.source-sha256": (
                                self.capability_source_digest
                            ),
                            "org.glassbox.capability.schema-sha256": (
                                self.capability_schema_digest
                            ),
                        }
                    },
                }
            ]
            return ProcessOutcome(0, json.dumps(inspected).encode(), b"")
        return ProcessOutcome(
            self.returncode,
            json.dumps(self.response, sort_keys=True).encode(),
            b"private child diagnostic",
        )


def _response(*, probes: dict[str, bool] | None = None) -> dict[str, object]:
    return {
        "protocol_version": "glassbox.isolated-capability.v1",
        "output": {"price": 42, "private": "transient-output"},
        "probes": probes
        or {
            "network_denied": True,
            "root_write_denied": True,
            "host_environment_absent": True,
        },
    }


def _profile(
    source_digest: str = "b" * 64,
    schema_digest: str = "c" * 64,
) -> ContainerIsolationProfile:
    return ContainerIsolationProfile(
        "sha256:" + "a" * 64,
        ("python", "/capability/worker.py"),
        source_digest,
        schema_digest,
        timeout_seconds=3,
        memory_bytes=67_108_864,
        pids_limit=8,
        cpus=0.25,
        tmpfs_bytes=1_048_576,
    )


def test_container_runner_enforces_exact_boundary_and_emits_raw_free_attestation() -> None:
    process = FakeProcessRunner(_response())
    runner = ContainerCapabilityRunner(
        _profile(),
        docker_executable="/usr/local/bin/docker",
        process_runner=process,
    )
    result = runner({"customer": "private-input"})

    assert result.attestation.valid
    assert result.output == {"price": 42, "private": "transient-output"}
    assert process.calls[0][0] == (
        "/usr/local/bin/docker",
        "image",
        "inspect",
        "sha256:" + "a" * 64,
    )
    argv, stdin, timeout, output_limit = process.calls[1]
    assert argv == (
        "/usr/local/bin/docker",
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
        "8",
        "--memory",
        "67108864",
        "--cpus",
        "0.25",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=1048576",
        "sha256:" + "a" * 64,
        "python",
        "/capability/worker.py",
    )
    assert b"private-input" in stdin
    assert timeout == 3 and output_limit == 1_048_576
    projection = json.dumps(result.attestation.to_dict(), sort_keys=True)
    assert "private-input" not in projection
    assert "transient-output" not in projection
    assert "private child diagnostic" not in projection
    assert result.attestation.network_access == "DENIED"
    assert result.attestation.root_filesystem == "READ_ONLY"
    assert result.attestation.linux_capabilities == "ALL_DROPPED"


@pytest.mark.parametrize(
    ("response", "returncode", "message"),
    [
        (_response(probes={"network_denied": False}), 0, "probes"),
        (_response(), 23, "status 23"),
        ({"protocol_version": "wrong", "output": {}, "probes": {}}, 0, "version"),
    ],
)
def test_container_runner_fails_closed_on_runtime_or_protocol_drift(
    response: object,
    returncode: int,
    message: str,
) -> None:
    runner = ContainerCapabilityRunner(
        _profile(),
        docker_executable="/usr/local/bin/docker",
        process_runner=FakeProcessRunner(response, returncode=returncode),
    )
    with pytest.raises(IsolationExecutionError, match=message):
        runner({"private": "input"})


def test_container_runner_refuses_image_whose_labels_do_not_match_tool_pins() -> None:
    runner = ContainerCapabilityRunner(
        _profile(),
        docker_executable="/usr/local/bin/docker",
        process_runner=FakeProcessRunner(
            _response(),
            capability_source_digest="d" * 64,
        ),
    )
    with pytest.raises(IsolationExecutionError, match="labels"):
        runner({"private": "input"})


class StaticProcessRunner:
    def __init__(self, outcome: ProcessOutcome) -> None:
        self.outcome = outcome

    def run(self, argv: Any, **kwargs: Any) -> ProcessOutcome:
        del argv, kwargs
        return self.outcome


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        (ProcessOutcome(1, b"", b""), "inspection failed"),
        (ProcessOutcome(0, b"not-json", b""), "invalid JSON"),
        (ProcessOutcome(0, b"[]", b""), "invalid result"),
        (
            ProcessOutcome(
                0,
                json.dumps([{"Id": "sha256:" + "d" * 64, "Config": {}}]).encode(),
                b"",
            ),
            "identity",
        ),
    ],
)
def test_container_runner_fails_closed_on_image_inspection_drift(
    outcome: ProcessOutcome,
    message: str,
) -> None:
    runner = ContainerCapabilityRunner(
        _profile(),
        docker_executable="/usr/local/bin/docker",
        process_runner=StaticProcessRunner(outcome),
    )
    with pytest.raises(IsolationExecutionError, match=message):
        runner({"private": "input"})


@pytest.mark.parametrize(
    ("raw", "message"),
    [
        (b"not-json", "invalid JSON"),
        (b"[]", "must be an object"),
        (
            json.dumps(
                {
                    "protocol_version": "glassbox.isolated-capability.v1",
                    "probes": {},
                }
            ).encode(),
            "incomplete",
        ),
    ],
)
def test_isolated_protocol_parser_rejects_malformed_responses(raw: bytes, message: str) -> None:
    with pytest.raises(IsolationExecutionError, match=message):
        _parse_response(raw)


def test_container_runner_rejects_oversized_input_and_invalid_attestation() -> None:
    profile = replace(_profile(), max_input_bytes=1)
    process = FakeProcessRunner(_response())
    runner = ContainerCapabilityRunner(
        profile,
        docker_executable="/usr/local/bin/docker",
        process_runner=process,
    )
    with pytest.raises(IsolationExecutionError, match="input exceeds"):
        runner({"private": "input"})
    valid = ContainerCapabilityRunner(
        _profile(),
        docker_executable="/usr/local/bin/docker",
        process_runner=FakeProcessRunner(_response()),
    )({"private": "input"})
    with pytest.raises(IsolationExecutionError, match="attestation is invalid"):
        type(valid)(valid.output, replace(valid.attestation, network_access="ALLOWED"))


def test_bounded_subprocess_runner_closes_environment_and_captures_both_streams(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GLASSBOX_HOST_SECRET", "must-not-cross")
    outcome = BoundedSubprocessRunner().run(
        (
            sys.executable,
            "-c",
            "import os,sys; data=sys.stdin.buffer.read(); "
            "sys.stdout.buffer.write(data.upper()); "
            "sys.stderr.write(os.environ.get('GLASSBOX_HOST_SECRET', 'absent'))",
        ),
        stdin=b"bounded input",
        timeout_seconds=2,
        max_output_bytes=1_024,
    )
    assert outcome.returncode == 0
    assert outcome.stdout == b"BOUNDED INPUT"
    assert outcome.stderr == b"absent"


@pytest.mark.parametrize(
    ("program", "timeout", "limit", "message"),
    [
        ("import sys; sys.stdout.write('x' * 4096)", 2, 64, "byte limit"),
        ("import time; time.sleep(2)", 0.02, 64, "timeout"),
    ],
)
def test_bounded_subprocess_runner_kills_timeout_and_output_overflow(
    program: str,
    timeout: float,
    limit: int,
    message: str,
) -> None:
    with pytest.raises(IsolationExecutionError, match=message):
        BoundedSubprocessRunner().run(
            (sys.executable, "-c", program),
            stdin=b"",
            timeout_seconds=timeout,
            max_output_bytes=limit,
        )


def test_isolation_attestation_is_bound_into_execution_and_new_receipt() -> None:
    action_input = {"query": "private-orders"}
    replay_input = {"customer": "private-customer"}
    source = _source(action_input=action_input, source_output={"price": 40})
    bundle = _bundle(source, replay_input=replay_input)
    tool = source["tools"][0]
    runner = ContainerCapabilityRunner(
        _profile(tool["source_digest"]["value"], tool["schema_digest"]["value"]),
        docker_executable="/usr/local/bin/docker",
        process_runner=FakeProcessRunner(
            _response(),
            capability_source_digest=tool["source_digest"]["value"],
            capability_schema_digest=tool["schema_digest"]["value"],
        ),
    )
    plan, execution, inputs = _execute(
        source,
        bundle,
        replay_input=replay_input,
        action_input=action_input,
        handler=runner,
        projector=lambda _input, outputs: outputs[source["actions"][0]["action_id"]],
    )

    action = execution.actions[0]
    assert execution.valid and action.isolation_attestation is not None
    assert action.isolation_attestation.valid
    assert "isolation" in action.to_dict()
    assert (
        replace(
            action.isolation_attestation,
            network_access="ALLOWED",
        ).valid
        is False
    )
    receipt = build_replay_receipt(
        execution,
        bundle,
        plan,
        source_receipt=source,
        inputs=inputs,
        signing_keys=(SigningKey("isolated-replay", Ed25519PrivateKey.generate()),),
    )
    assert receipt["extensions"]["glassbox.replay.isolation_attestation_ids"] == [
        action.isolation_attestation.attestation_id
    ]
    serialized = json.dumps(execution.to_dict(), sort_keys=True)
    assert "private-orders" not in serialized
    assert "private-customer" not in serialized
    assert "transient-output" not in serialized


@pytest.mark.parametrize(
    "profile",
    [
        lambda: ContainerIsolationProfile("latest", ("worker",), "b" * 64, "c" * 64),
        lambda: ContainerIsolationProfile("sha256:" + "a" * 64, (), "b" * 64, "c" * 64),
        lambda: ContainerIsolationProfile(
            "sha256:" + "a" * 64,
            ("worker",),
            "b" * 64,
            "c" * 64,
            pids_limit=0,
        ),
        lambda: ContainerIsolationProfile(
            "sha256:" + "a" * 64,
            ("worker",),
            "b" * 64,
            "c" * 64,
            memory_bytes=1,
        ),
        lambda: replace(_profile(), capability_source_digest="bad"),
        lambda: replace(_profile(), timeout_seconds=0),
        lambda: replace(_profile(), cpus=0),
        lambda: replace(_profile(), max_output_bytes=0),
    ],
)
def test_container_profile_rejects_weak_or_unpinned_configuration(profile: Any) -> None:
    with pytest.raises(IsolationExecutionError):
        profile()
