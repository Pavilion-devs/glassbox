"""Append-only operational event-log tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from examples.deterministic_pricing_agent import build_pricing_agent

from glassbox import GlassBox
from glassbox_compiler import (
    AppendOnlyEventLog,
    CompilationProfile,
    Environment,
    EventLogError,
    compile_events,
)
from glassbox_dbom import verify_receipt


def test_append_only_log_round_trips_private_runtime_events(tmp_path: Path) -> None:
    path = tmp_path / "runtime-events.jsonl"
    log = AppendOnlyEventLog(path)
    runtime = GlassBox(log)

    build_pricing_agent(runtime)("private-log-customer")

    restored = log.read_events()
    assert len(restored) == 5
    assert [event.sequence for event in restored] == [1, 2, 3, 4, 5]
    assert restored[1].run == restored[0].run
    assert restored[2].run == restored[0].run
    assert "private-log-customer" not in path.read_text()
    assert path.stat().st_mode & 0o777 == 0o600

    receipt = compile_events(
        restored,
        profile=CompilationProfile(
            environment=Environment.DEV,
            output_kind="recommendation",
            output_mime_type="application/json",
        ),
    )
    assert verify_receipt(receipt).valid


def test_nested_run_context_survives_event_log_round_trip(tmp_path: Path) -> None:
    log = AppendOnlyEventLog(tmp_path / "nested.jsonl", sync=False)
    runtime = GlassBox(log)
    with runtime.run(agent_id="parent", workflow_id="orchestrate") as parent:
        with runtime.run(agent_id="child", workflow_id="analyze") as child:
            child.record_output({"child": "done"})
        parent.record_output({"parent": "done"})

    events = log.read_events()
    child_events = [event for event in events if event.run.agent_id == "child"]
    assert child_events[0].run.parent_run_id == events[0].run.run_id
    assert child_events[0].run.parent_span_id == events[0].run.span_id
    assert child_events[0].run == child_events[1].run


def test_missing_log_reads_as_empty_and_parent_must_exist(tmp_path: Path) -> None:
    assert AppendOnlyEventLog(tmp_path / "missing.jsonl").read_events() == ()
    with pytest.raises(EventLogError, match="parent directory does not exist"):
        AppendOnlyEventLog(tmp_path / "missing" / "events.jsonl")
    with pytest.raises(EventLogError, match="not a regular file"):
        AppendOnlyEventLog(tmp_path)


def test_checksum_tampering_and_truncated_tail_fail_visibly(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    log = AppendOnlyEventLog(path)
    runtime = GlassBox(log)
    with runtime.run(agent_id="agent", workflow_id="workflow") as handle:
        handle.record_output({"status": "done"})

    records = path.read_text().splitlines()
    envelope = json.loads(records[0])
    envelope["event"]["agent.id"] = "tampered-agent"
    records[0] = json.dumps(envelope)
    path.write_text("\n".join(records) + "\n")
    with pytest.raises(EventLogError, match="failed its checksum"):
        log.read_events()

    path.write_bytes(path.read_bytes().rstrip(b"\n"))
    with pytest.raises(EventLogError, match="truncated trailing record"):
        log.read_events()


@pytest.mark.parametrize("content", [b"[]\n", b"not-json\n", b'{"event":{}}\n'])
def test_malformed_envelopes_are_rejected(tmp_path: Path, content: bytes) -> None:
    path = tmp_path / "malformed.jsonl"
    path.write_bytes(content)
    with pytest.raises(EventLogError):
        AppendOnlyEventLog(path).read_events()
