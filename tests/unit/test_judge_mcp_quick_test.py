"""One-command judge MCP proof tests."""

from __future__ import annotations

import asyncio
from pathlib import Path

from examples.judge_mcp_quick_test import run_judge_mcp_quick_test


def test_judge_mcp_quick_test_runs_fresh_closed_protocol_proof(tmp_path: Path) -> None:
    report = asyncio.run(run_judge_mcp_quick_test(tmp_path))

    assert report["valid"] is True
    assert report["agent_run_executed"] is True
    assert report["external_datahub_contacted"] is False
    assert report["mcp"] == {
        "tools_discovered": 7,
        "tools_called": 7,
        "read_only_contract": True,
    }
    assert report["verification_state"] == "VERIFIED_NOW"
    assert report["impact_state"] == "STALE"
    assert report["affected_decisions"] == 1
    assert report["publication_state"] == "READY"
    assert report["raw_content_returned"] is False
