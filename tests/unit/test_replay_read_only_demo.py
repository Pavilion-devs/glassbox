"""Offline closed-loop replay example contract."""

from __future__ import annotations

import json

import pytest
from examples.replay_read_only import main


def test_offline_replay_chain_is_repeatable_private_and_history_preserving(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main() == 0
    first_text = capsys.readouterr().out
    assert main() == 0
    second_text = capsys.readouterr().out
    first = json.loads(first_text)
    second = json.loads(second_text)

    assert first == second
    assert first["valid"] is True
    assert first["decision"] == "ALLOW"
    assert first["semantic_result"] == "CHANGED"
    assert first["source_history_mutations"] == 0
    assert first["raw_values_retained"] is False
    assert first["source_receipt_id"] != first["replay_receipt_id"]
    assert "synthetic-customer" not in first_text
    assert "synthetic-replay" not in first_text
