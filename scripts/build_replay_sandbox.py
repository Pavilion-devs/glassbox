"""Build and verify the digest-pinned flagship replay sandbox image."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from examples.pricing_policy import pricing_policy_schema_digest, pricing_policy_source_digest


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="build-replay-sandbox")
    parser.add_argument("--tag", default="glassbox-replay-sandbox:0.1.0")
    parser.add_argument("--docker", type=Path, default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    found = shutil.which("docker")
    docker = args.docker or (Path(found) if found is not None else None)
    if docker is None or not docker.is_absolute():
        raise ValueError("an absolute Docker executable is required")
    root = Path(__file__).resolve().parents[1]
    source_digest = pricing_policy_source_digest()
    schema_digest = pricing_policy_schema_digest()
    subprocess.run(
        (
            str(docker),
            "build",
            "--file",
            "examples/Dockerfile.replay-sandbox",
            "--build-arg",
            f"CAPABILITY_SOURCE_DIGEST={source_digest}",
            "--build-arg",
            f"CAPABILITY_SCHEMA_DIGEST={schema_digest}",
            "--tag",
            args.tag,
            ".",
        ),
        cwd=root,
        check=True,
    )
    inspected = subprocess.run(
        (str(docker), "image", "inspect", args.tag),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    value = json.loads(inspected.stdout)
    image = _single_mapping(value)
    image_id = image.get("Id")
    config = image.get("Config")
    labels = config.get("Labels") if isinstance(config, Mapping) else None
    expected = {
        "org.glassbox.capability.protocol": "glassbox.isolated-capability.v1",
        "org.glassbox.capability.source-sha256": source_digest,
        "org.glassbox.capability.schema-sha256": schema_digest,
    }
    if (
        not isinstance(image_id, str)
        or not image_id.startswith("sha256:")
        or not isinstance(labels, Mapping)
        or any(labels.get(key) != expected_value for key, expected_value in expected.items())
    ):
        raise RuntimeError("built sandbox image identity or capability labels did not verify")
    print(
        json.dumps(
            {
                "valid": True,
                "image_digest": image_id,
                "capability_source_digest": source_digest,
                "capability_schema_digest": schema_digest,
                "protocol": "glassbox.isolated-capability.v1",
                "raw_values_retained": False,
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


def _single_mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], Mapping):
        raise RuntimeError("Docker image inspection returned an invalid result")
    return value[0]


if __name__ == "__main__":
    raise SystemExit(main())
