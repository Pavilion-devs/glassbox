from __future__ import annotations

from collections.abc import Mapping

import pytest

import glassbox_datahub.capability_probe as probe_module
from glassbox_datahub.capability_probe import (
    CapabilityStatus,
    EntitySpec,
    ProbeRunner,
    build_compatibility_probe_plan,
    build_probe_plan,
    main,
    validate_probe_sdk_version,
    validate_probe_target,
)


class FakeBackend:
    sdk_version = "1.6.0.15"

    def __init__(
        self,
        *,
        connection_error: Exception | None = None,
        failing_kind: str | None = None,
        change_second_urn_for: str | None = None,
        wrong_urn_for: str | None = None,
        empty_readback: bool = False,
    ) -> None:
        self.connection_error = connection_error
        self.failing_kind = failing_kind
        self.change_second_urn_for = change_second_urn_for
        self.wrong_urn_for = wrong_urn_for
        self.empty_readback = empty_readback
        self.calls: dict[str, int] = {}

    def test_connection(self) -> None:
        if self.connection_error is not None:
            raise self.connection_error

    def emit(self, spec: EntitySpec, emitted_urns: Mapping[str, str]) -> str:
        del emitted_urns
        if spec.kind == self.failing_kind:
            raise RuntimeError("synthetic emission failure")
        self.calls[spec.kind] = self.calls.get(spec.kind, 0) + 1
        if spec.kind == self.change_second_urn_for and self.calls[spec.kind] == 2:
            return spec.expected_urn + ".duplicate"
        if spec.kind == self.wrong_urn_for:
            return spec.expected_urn + ".wrong"
        return spec.expected_urn

    def direct_read_aspects(self, urn: str) -> tuple[str, ...]:
        del urn
        if self.empty_readback:
            return ()
        return ("status", "properties")


def test_probe_plan_is_dependency_ordered_and_version_pinned() -> None:
    plan = build_probe_plan()
    positions = {spec.kind: index for index, spec in enumerate(plan.entities)}

    assert plan.server_version == "1.6.0"
    assert plan.sdk_version == "1.6.0.15"
    assert [spec.kind for spec in plan.entities] == [
        "dataset",
        "ml_model",
        "agent_run",
        "api_tool",
        "agent_skill",
        "ai_agent",
        "receipt_document",
    ]
    for spec in plan.entities:
        assert all(positions[dependency] < positions[spec.kind] for dependency in spec.dependencies)
    assert plan.to_dict()["mode"] == "PLAN_ONLY"


def test_compatibility_plan_replaces_only_unavailable_registry_entities() -> None:
    plan = build_compatibility_probe_plan()

    assert [spec.kind for spec in plan.entities] == [
        "dataset",
        "ml_model",
        "agent_run",
        "api_tool_compat",
        "agent_skill_compat",
        "ai_agent_compat",
        "receipt_document",
    ]
    assert all(
        spec.expected_urn.startswith("urn:li:document:")
        for spec in plan.entities
        if spec.kind.endswith("_compat")
    )
    assert plan.entities[-1].dependencies[-1] == "ai_agent_compat"


def test_probe_proves_idempotency_and_direct_readback() -> None:
    backend = FakeBackend()
    report = ProbeRunner(backend, target="http://localhost:8080").run(build_probe_plan())

    assert report.valid
    assert report.connection is CapabilityStatus.PROVEN
    assert all(result.status is CapabilityStatus.PROVEN for result in report.results)
    assert all(call_count == 2 for call_count in backend.calls.values())
    assert report.to_dict()["valid"] is True


def test_connection_failure_blocks_every_entity() -> None:
    backend = FakeBackend(connection_error=ConnectionError("offline"))
    report = ProbeRunner(backend, target="http://localhost:8080").run(build_probe_plan())

    assert not report.valid
    assert report.connection is CapabilityStatus.FAILED
    assert all(result.status is CapabilityStatus.BLOCKED for result in report.results)


def test_probe_diagnostics_remove_credentials_and_personal_home_paths() -> None:
    backend = FakeBackend(
        connection_error=ConnectionError(
            "Bearer abc.def token=top-secret file=/Users/alice/private/config.json"
        )
    )
    report = ProbeRunner(backend, target="http://localhost:8080").run(build_probe_plan())
    detail = report.results[0].detail

    assert "abc.def" not in detail
    assert "top-secret" not in detail
    assert "/Users/alice" not in detail
    assert detail.count("[REDACTED]") == 2
    assert "$HOME/private/config.json" in detail


def test_failed_tool_blocks_registry_dependents_but_not_stable_entities() -> None:
    backend = FakeBackend(failing_kind="api_tool")
    report = ProbeRunner(backend, target="http://localhost:8080").run(build_probe_plan())
    statuses = {result.kind: result.status for result in report.results}

    assert statuses["dataset"] is CapabilityStatus.PROVEN
    assert statuses["ml_model"] is CapabilityStatus.PROVEN
    assert statuses["agent_run"] is CapabilityStatus.PROVEN
    assert statuses["api_tool"] is CapabilityStatus.FAILED
    assert statuses["agent_skill"] is CapabilityStatus.BLOCKED
    assert statuses["ai_agent"] is CapabilityStatus.BLOCKED
    assert statuses["receipt_document"] is CapabilityStatus.PROVEN


def test_non_idempotent_entity_is_failed() -> None:
    backend = FakeBackend(change_second_urn_for="dataset")
    report = ProbeRunner(backend, target="http://localhost:8080").run(build_probe_plan())

    assert report.results[0].status is CapabilityStatus.FAILED
    assert "non-idempotent URNs" in report.results[0].detail


def test_unexpected_urn_is_failed() -> None:
    backend = FakeBackend(wrong_urn_for="dataset")
    report = ProbeRunner(backend, target="http://localhost:8080").run(build_probe_plan())

    assert report.results[0].status is CapabilityStatus.FAILED
    assert "did not equal" in report.results[0].detail


def test_empty_direct_readback_is_failed() -> None:
    backend = FakeBackend(empty_readback=True)
    report = ProbeRunner(backend, target="http://localhost:8080").run(build_probe_plan())

    assert report.results[0].status is CapabilityStatus.FAILED
    assert "no persisted aspects" in report.results[0].detail


@pytest.mark.parametrize(
    "server",
    ["http://localhost:8080", "https://127.0.0.1:8080/", "http://[::1]:8080"],
)
def test_local_targets_are_accepted(server: str) -> None:
    assert validate_probe_target(server, allow_remote=False) == server.rstrip("/")


@pytest.mark.parametrize(
    "server",
    [
        "localhost:8080",
        "ftp://localhost:8080",
        "http://user:password@localhost:8080",
        "http://localhost:8080?token=secret",
        "http://localhost:8080#fragment",
    ],
)
def test_malformed_or_credential_bearing_targets_are_rejected(server: str) -> None:
    with pytest.raises(ValueError):
        validate_probe_target(server, allow_remote=False)


def test_remote_target_requires_an_explicit_second_opt_in() -> None:
    server = "https://datahub.example.invalid"

    with pytest.raises(ValueError, match="--allow-remote"):
        validate_probe_target(server, allow_remote=False)
    assert validate_probe_target(server, allow_remote=True) == server


def test_stable_sdk_pin_requires_no_extra_opt_in() -> None:
    assert validate_probe_sdk_version("1.6.0.15", allow_prerelease=False) == "1.6.0.15"


def test_inspected_agent_registry_rc_requires_explicit_opt_in() -> None:
    with pytest.raises(ValueError, match="--allow-prerelease-sdk"):
        validate_probe_sdk_version("1.6.0.16rc3", allow_prerelease=False)
    assert validate_probe_sdk_version("1.6.0.16rc3", allow_prerelease=True) == "1.6.0.16rc3"


def test_uninspected_sdk_version_is_rejected_even_with_prerelease_opt_in() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        validate_probe_sdk_version("1.6.0.16rc4", allow_prerelease=True)


def test_plan_cli_has_no_live_side_effects(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["plan"]) == 0
    output = capsys.readouterr().out
    assert '"mode": "PLAN_ONLY"' in output
    assert "glassbox.probe.pricing-agent" in output


def test_live_cli_emits_json_report_with_injected_backend(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(probe_module, "DataHubSdkBackend", lambda **kwargs: FakeBackend())

    assert main(["live", "--allow-live", "--json"]) == 0
    assert '"valid": true' in capsys.readouterr().out


def test_live_cli_can_build_an_explicit_rc_plan(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    backend = FakeBackend()
    backend.sdk_version = "1.6.0.16rc3"
    monkeypatch.setattr(probe_module, "DataHubSdkBackend", lambda **kwargs: backend)

    assert (
        main(
            [
                "live",
                "--allow-live",
                "--json",
                "--expected-sdk-version",
                "1.6.0.16rc3",
                "--allow-prerelease-sdk",
            ]
        )
        == 0
    )
    assert '"sdk_version": "1.6.0.16rc3"' in capsys.readouterr().out


def test_compatibility_live_cli_uses_stable_document_projection(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(probe_module, "DataHubSdkBackend", lambda **kwargs: FakeBackend())

    assert main(["compatibility-live", "--allow-live", "--json"]) == 0
    output = capsys.readouterr().out
    assert '"kind": "api_tool_compat"' in output
    assert '"kind": "ai_agent_compat"' in output


def test_live_cli_human_output_returns_one_for_failed_probe(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        probe_module,
        "DataHubSdkBackend",
        lambda **kwargs: FakeBackend(connection_error=ConnectionError("offline")),
    )

    assert main(["live", "--allow-live"]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_live_cli_reports_missing_sdk_without_traceback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing_sdk(**kwargs: object) -> FakeBackend:
        raise ImportError("acryl-datahub is not installed")

    monkeypatch.setattr(probe_module, "DataHubSdkBackend", missing_sdk)

    assert main(["live", "--allow-live"]) == 2
    assert "acryl-datahub is not installed" in capsys.readouterr().err
