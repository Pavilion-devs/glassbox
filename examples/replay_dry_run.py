"""Build, plan, and render a signed read-only replay without external calls."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from glassbox_dbom import SigningKey, seal_receipt
from glassbox_replay import (
    DryRunExecutor,
    ModelDeterminism,
    ModelReplayConfig,
    ReplayMode,
    ReplaySupplement,
    ResourceAvailability,
    ResourceInventory,
    ResourceKind,
    build_replay_bundle,
    plan_replay,
)

FIXTURE = Path(__file__).parents[1] / "tests" / "fixtures" / "dbom" / "valid-read-only.json"
EVALUATED_AT = "2026-08-06T12:30:00Z"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _value(value: dict[str, str] | None) -> str | None:
    return value["value"] if value is not None else None


def _inventory(receipt: dict[str, Any]) -> ResourceInventory:
    agent = receipt["agent"]
    workflow = receipt["workflow"]
    model = receipt["models"][0]
    skill = receipt["skills"][0]
    tool = receipt["tools"][0]
    return ResourceInventory(
        (
            ResourceAvailability(
                ResourceKind.AGENT,
                agent["id"],
                agent["version"],
                source_digest=_value(agent["source_digest"]),
            ),
            ResourceAvailability(ResourceKind.WORKFLOW, workflow["id"], workflow["version"]),
            ResourceAvailability(
                ResourceKind.MODEL,
                model["id"],
                model["version"],
                source_digest=_value(model["source_digest"]),
            ),
            ResourceAvailability(
                ResourceKind.SKILL,
                skill["id"],
                skill["version"],
                source_digest=_value(skill["source_digest"]),
            ),
            ResourceAvailability(
                ResourceKind.TOOL,
                tool["id"],
                tool["version"],
                source_digest=_value(tool["source_digest"]),
                schema_digest=_value(tool["schema_digest"]),
            ),
        )
    )


def main() -> int:
    source_payload = json.loads(FIXTURE.read_bytes())
    source_payload.pop("receipt_id")
    source_payload.pop("integrity")
    receipt = seal_receipt(
        source_payload,
        signing_keys=(SigningKey("ephemeral-source-key", Ed25519PrivateKey.generate()),),
    )
    model = receipt["models"][0]
    supplement = ReplaySupplement(
        input_digest=_digest("example-replay-input"),
        input_reference="artifact://glassbox/example-replay-input",
        feature_flags_digest=_digest("example-feature-flags"),
        model_configs=(
            ModelReplayConfig(
                model["id"],
                "example-provider",
                _digest("temperature=0"),
                ModelDeterminism.DETERMINISTIC,
                "example-artifact-store",
            ),
        ),
    )
    bundle = build_replay_bundle(
        receipt,
        mode=ReplayMode.PINNED,
        supplement=supplement,
        signing_keys=(SigningKey("ephemeral-example-key", Ed25519PrivateKey.generate()),),
    )
    plan = plan_replay(
        bundle,
        source_receipt=receipt,
        inventory=_inventory(receipt),
        evaluated_at=EVALUATED_AT,
    )
    report = DryRunExecutor().render(bundle, plan, source_receipt=receipt)
    result = {
        "valid": plan.valid and report.valid,
        "bundle_id": bundle["bundle_id"],
        "plan": plan.to_dict(),
        "dry_run": report.to_dict(),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
