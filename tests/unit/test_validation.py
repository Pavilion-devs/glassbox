from __future__ import annotations

import json
from pathlib import Path

import pytest

from glassbox_dbom.errors import SchemaValidationError
from glassbox_dbom.validation import load_schema, validate_receipt


def test_schema_can_be_loaded_from_an_explicit_path(tmp_path: Path) -> None:
    path = tmp_path / "schema.json"
    path.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    assert load_schema(path) == {"type": "object"}


def test_explicit_schema_root_must_be_an_object(tmp_path: Path) -> None:
    path = tmp_path / "schema.json"
    path.write_text("[]", encoding="utf-8")

    with pytest.raises(SchemaValidationError, match="schema root"):
        load_schema(path)


def test_custom_schema_reports_all_failures_with_json_locations() -> None:
    schema = {
        "type": "object",
        "required": ["name", "count"],
        "properties": {"name": {"type": "string"}, "count": {"type": "integer"}},
    }

    with pytest.raises(SchemaValidationError) as exc_info:
        validate_receipt({"name": 42}, schema=schema)

    assert len(exc_info.value.errors) == 2
    assert any(error.startswith("/name:") for error in exc_info.value.errors)
