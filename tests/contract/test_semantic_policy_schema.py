"""Normative semantic-policy JSON Schema contract tests."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from glassbox_policy import (
    SemanticPolicyError,
    SemanticRulePack,
    load_semantic_policy_schema,
    validate_semantic_policy_document,
)

_ROOT = Path(__file__).resolve().parents[2]
_FIXTURE = _ROOT / "examples" / "semantic-policies" / "pricing-recommendation-v1.json"


def test_semantic_policy_schema_accepts_the_canonical_reference_pack() -> None:
    document = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    schema = load_semantic_policy_schema()

    validate_semantic_policy_document(document, schema=schema)
    assert SemanticRulePack.from_dict(document).valid
    assert schema["$id"].endswith("/semantic-policy/0.1.0/schema.json")


@pytest.mark.parametrize(
    ("path", "value"),
    (
        (("unexpected",), True),
        (("contract",), "untrusted.policy"),
        (("rules", 0, "kind"), "EXECUTE_PYTHON"),
        (("rules", 0, "absolute_tolerance"), -1),
        (("raw_content_returned",), True),
    ),
)
def test_semantic_policy_schema_rejects_open_or_executable_drift(
    path: tuple[str | int, ...],
    value: object,
) -> None:
    document = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    target = document
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value

    with pytest.raises(SemanticPolicyError):
        validate_semantic_policy_document(document)


def test_semantic_policy_schema_loader_rejects_non_object_root(tmp_path: Path) -> None:
    path = tmp_path / "schema.json"
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(SemanticPolicyError, match="root"):
        load_semantic_policy_schema(path)

    valid = json.loads(_FIXTURE.read_text(encoding="utf-8"))
    duplicate = copy.deepcopy(valid)
    duplicate["rules"].append(copy.deepcopy(duplicate["rules"][0]))
    with pytest.raises(SemanticPolicyError):
        SemanticRulePack.from_dict(duplicate)
