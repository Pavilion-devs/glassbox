"""DBOM JSON Schema loading and validation."""

from __future__ import annotations

import json
from collections.abc import Mapping
from importlib import resources
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from glassbox_dbom.errors import SchemaValidationError

SCHEMA_VERSION = "0.1.0"
_SCHEMA_RELATIVE_PATH = Path("schemas") / SCHEMA_VERSION / "schema.json"


def _repository_schema_path() -> Path:
    repository_root = Path(__file__).resolve().parents[4]
    return repository_root / "schemas" / "dbom" / SCHEMA_VERSION / "schema.json"


def load_schema(path: Path | None = None) -> dict[str, Any]:
    """Load the normative schema from an explicit path, source tree, or wheel."""

    if path is not None:
        return _read_schema(path)

    repository_path = _repository_schema_path()
    if repository_path.is_file():
        return _read_schema(repository_path)

    package_schema = resources.files("glassbox_dbom").joinpath(str(_SCHEMA_RELATIVE_PATH))
    with package_schema.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise SchemaValidationError(("DBOM schema root must be an object",))
    return loaded


def _read_schema(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as handle:
        loaded = json.load(handle)
    if not isinstance(loaded, dict):
        raise SchemaValidationError((f"schema root at {path} must be an object",))
    return loaded


def validate_receipt(
    receipt: Mapping[str, Any], *, schema: Mapping[str, Any] | None = None
) -> None:
    """Validate a receipt and raise one error containing every deterministic failure."""

    selected_schema = dict(schema) if schema is not None else load_schema()
    validator = Draft202012Validator(selected_schema, format_checker=FormatChecker())
    failures: list[str] = []
    for error in sorted(validator.iter_errors(receipt), key=lambda item: list(item.path)):
        location = "/" + "/".join(str(part) for part in error.absolute_path)
        failures.append(f"{location}: {error.message}")
    if failures:
        raise SchemaValidationError(tuple(failures))
