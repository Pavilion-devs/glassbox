"""Run the fixed guarded schema-change helper on the hosted Devpost estate."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

SSH_KEY = Path.home() / ".ssh" / "id_ed25519"
SSH_HOST = "root@57.129.106.133"
SSH_PORT = "4442"
DATAHUB_GMS_CONTAINER = "glassbox-datahub-datahub-gms-quickstart-1"
REMOTE_COMMAND = (
    f"datahub_operator_id=$(docker exec {DATAHUB_GMS_CONTAINER} "
    "printenv DATAHUB_SYSTEM_CLIENT_ID) && "
    f"datahub_operator_secret=$(docker exec {DATAHUB_GMS_CONTAINER} "
    "printenv DATAHUB_SYSTEM_CLIENT_SECRET) && "
    'test -n "$datahub_operator_id" && '
    'test -n "$datahub_operator_secret" && '
    "cd /opt/glassbox/app/deploy/production && "
    "docker compose --env-file /opt/glassbox/secrets/.env.production "
    "run --rm --no-deps -T "
    "-e GLASSBOX_ORGANIZATION=glassbox-demo "
    "-e GLASSBOX_CONTROL_MASTER_KEY_ID=control-v1 "
    '-e GLASSBOX_DATAHUB_OPERATOR_CLIENT_ID="$datahub_operator_id" '
    '-e GLASSBOX_DATAHUB_OPERATOR_CLIENT_SECRET="$datahub_operator_secret" '
    "-v /opt/glassbox/app/scripts:/opt/operator:ro "
    "receiver /opt/glassbox/.venv/bin/python "
    "/opt/operator/guarded_schema_change.py apply"
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
