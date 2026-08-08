"""Closed stdin/stdout worker for the flagship OCI replay capability."""

from __future__ import annotations

import json
import os
import socket
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from pricing_policy import apply_replayable_pricing_policy

_PROTOCOL = "glassbox.isolated-capability.v1"


def _network_denied() -> bool:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    try:
        probe.connect(("1.1.1.1", 53))
    except OSError:
        return True
    finally:
        probe.close()
    return False


def _root_write_denied() -> bool:
    target = Path("/glassbox-root-write-probe")
    try:
        target.write_text("must-not-succeed", encoding="utf-8")
    except OSError:
        return True
    target.unlink(missing_ok=True)
    return False


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, Mapping) or request.get("protocol_version") != _PROTOCOL:
            raise ValueError("protocol mismatch")
        action_input = request.get("input")
        if not isinstance(action_input, dict):
            raise ValueError("input must be an object")
        output = apply_replayable_pricing_policy(action_input)
        response: dict[str, Any] = {
            "protocol_version": _PROTOCOL,
            "output": output,
            "probes": {
                "network_denied": _network_denied(),
                "root_write_denied": _root_write_denied(),
                "host_environment_absent": "GLASSBOX_HOST_SECRET" not in os.environ,
            },
        }
        json.dump(response, sys.stdout, sort_keys=True, separators=(",", ":"))
        return 0
    except Exception as exc:
        print(type(exc).__qualname__, file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
