"""Raw-free CLI for building and evaluating agent narration contracts."""

from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from glassbox_forensics.narration import (
    NARRATION_EVALUATION_CONTRACT_VERSION,
    NarrationContractError,
    build_narration_brief,
    evaluate_agent_narration,
)


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI parser."""

    parser = argparse.ArgumentParser(
        prog="glassbox-agent-narration",
        description="Build or evaluate a raw-free agent narration over dual-MCP evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    brief = subparsers.add_parser("brief", help="Project dual-MCP evidence into bounded facts")
    brief.add_argument("evidence", type=Path)
    brief.add_argument("--pretty", action="store_true", help="Indent JSON output")
    evaluate = subparsers.add_parser("evaluate", help="Evaluate one structured agent response")
    evaluate.add_argument("evidence", type=Path)
    evaluate.add_argument("response", type=Path)
    evaluate.add_argument("--pretty", action="store_true", help="Indent JSON output")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the narration brief/evaluation command."""

    args = build_parser().parse_args(argv)
    try:
        evidence = _read_object(args.evidence)
        brief = build_narration_brief(evidence)
        if args.command == "brief":
            report = brief
            exit_code = 0
        else:
            response = _read_object(args.response)
            report = evaluate_agent_narration(brief, response)
            exit_code = 0 if report["valid"] is True else 1
    except (NarrationContractError, OSError, UnicodeError, json.JSONDecodeError, ValueError):
        report = {
            "contract": NARRATION_EVALUATION_CONTRACT_VERSION,
            "valid": False,
            "reason_codes": ["INPUT_INVALID"],
            "raw_content_returned": False,
        }
        exit_code = 2
    print(
        json.dumps(
            report,
            ensure_ascii=True,
            indent=2 if args.pretty else None,
            separators=None if args.pretty else (",", ":"),
            sort_keys=True,
        )
    )
    return exit_code


def _read_object(path: Path) -> Mapping[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value


if __name__ == "__main__":  # pragma: no cover - console entry point
    raise SystemExit(main())
