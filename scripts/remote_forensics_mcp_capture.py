"""Run the fixed MCP forensics capture against the private hosted service."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

SSH_KEY = Path.home() / ".ssh" / "id_ed25519"
SSH_HOST = "root@57.129.106.133"
SSH_PORT = "4442"
REMOTE_COMMAND = (
    "cd /opt/glassbox/app/deploy/production && "
    "docker compose --env-file /opt/glassbox/secrets/.env.production "
    "run --rm --no-deps -T "
    "-v /opt/glassbox/app/scripts:/opt/operator:ro "
    "forensics /opt/glassbox/.venv/bin/python "
    "/opt/operator/forensics_mcp_capture.py"
)


def main(argv: Sequence[str] | None = None) -> int:
    if argv:
        print("This fixed filming helper accepts no arguments.", file=sys.stderr)
        return 2
    if not SSH_KEY.is_file():
        print("GlassBox VPS SSH key is unavailable.", file=sys.stderr)
        return 1
    completed = subprocess.run(
        [
            "ssh",
            "-i",
            str(SSH_KEY),
            "-p",
            SSH_PORT,
            SSH_HOST,
            REMOTE_COMMAND,
        ],
        check=False,
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
