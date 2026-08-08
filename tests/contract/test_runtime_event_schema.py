"""Contract tests for the normalized runtime event envelope."""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from glassbox import ActionEffect, EvidenceRole, EvidenceState, GlassBox, InMemorySink

SCHEMA_PATH = Path(__file__).parents[2] / "schemas" / "runtime-event" / "0.1.0" / "schema.json"


def test_all_runtime_event_kinds_validate_against_normative_envelope() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    sink = InMemorySink()
    runtime = GlassBox(sink)

    with runtime.run(agent_id="agent", workflow_id="workflow") as handle:
        runtime.observe_evidence(
            entity_type="dataset",
            state=EvidenceState.OBSERVED,
            role=EvidenceRole.INPUT,
            representation={"count": 1},
        )
        result = runtime.call_tool("lookup", lambda: {"count": 1}, effect=ActionEffect.READ_ONLY)
        handle.record_output(result)

    for event in sink.events:
        validator.validate(event.to_dict())


def test_runtime_event_schema_rejects_invalid_trace_id() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    sink = InMemorySink()
    runtime = GlassBox(sink)
    with runtime.run(agent_id="agent", workflow_id="workflow"):
        pass
    event = sink.events[0].to_dict()
    event["trace_id"] = "not-a-trace-id"

    errors = list(jsonschema.Draft202012Validator(schema).iter_errors(event))

    assert errors
    assert any(error.json_path == "$.trace_id" for error in errors)
