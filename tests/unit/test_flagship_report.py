"""Contract checks for the committed raw-free causal flagship evidence."""

from __future__ import annotations

import json
from pathlib import Path

REPORT = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "compatibility"
    / "datahub-1.6.0-flagship-causal-recovery.live.json"
)


def test_committed_flagship_report_is_one_exact_raw_free_causal_chain() -> None:
    report = json.loads(REPORT.read_text(encoding="utf-8"))
    source = report["source_decision"]["receipt_id"]
    invalidation = report["invalidation"]
    authorization = report["recovery_authorization"]
    replay = report["corrected_replay"]
    mcp = report["dual_mcp_forensics"]

    assert report["valid"] is True
    assert report["scenario"] == "GLASSBOX_DATAHUB_CAUSAL_RECOVERY"
    assert invalidation["source_receipt_id"] == source
    assert authorization["source_receipt_id"] == source
    assert mcp["cross_plane_binding"]["receipt_id"] == source
    assert authorization["campaign_id"] == invalidation["campaign_id"]
    assert mcp["cross_plane_binding"]["campaign_id"] == invalidation["campaign_id"]
    assert authorization["bundle_id"] == replay["bundle_id"]

    assert report["negative_control"] == {
        "campaign_id": report["negative_control"]["campaign_id"],
        "datahub_mutation_required": False,
        "finding": "UNAFFECTED",
        "first_delivery_emissions": 0,
        "reason_code": "COMPLETE_FIELD_LINEAGE_PROVES_FIELD_UNUSED",
        "redelivery_emissions": 0,
    }
    assert invalidation["finding"] == "STALE"
    assert invalidation["workflow_status"] == "COMPLETED"
    assert invalidation["datahub_writeback_verified"] is True
    assert invalidation["first_delivery_emissions"] == 2
    assert invalidation["redelivery_emissions"] == 0
    assert invalidation["redelivery_reused_completion"] is True
    assert mcp["valid"] is True
    assert mcp["glassbox_mcp"]["mutation_tools"] == 0
    assert mcp["datahub_mcp"]["non_read_only_tools"] == []

    assert authorization["finding_state"] == "STALE"
    assert authorization["mode"] == "CORRECTED"
    assert authorization["verification"]["valid"] is True
    assert authorization["verification"]["trusted_signer_present"] is True
    assert replay["decision"] == "ALLOW"
    assert replay["execution_status"] == "SUCCEEDED"
    assert replay["action_input_digest_changed"] is True
    assert replay["semantic_result"] == "CHANGED"
    assert replay["source_history_mutations"] == 0
    assert replay["replay_receipt_id"] != source
    assert replay["completed_redelivery_datahub_write_performed"] is False
    isolation = replay["isolation"]
    assert isolation["runtime"] == "OCI_CONTAINER"
    assert isolation["image_digest"].startswith("sha256:")
    assert isolation["image_identity_verified"] is True
    assert isolation["capability_labels_verified"] is True
    assert isolation["network_probe_denied"] is True
    assert isolation["root_write_probe_denied"] is True
    assert isolation["host_environment_probe_absent"] is True
    assert isolation["linux_capabilities"] == "ALL_DROPPED"
    assert isolation["no_new_privileges"] is True
    assert report["supersession"]["valid"] is True
    assert report["supersession"]["verified_property_count"] == 14
    closure = report["incident_closure"]
    assert closure["valid"] is True
    assert closure["campaign_id"] == invalidation["campaign_id"]
    assert closure["incident_urn"] == invalidation["incident_urn"]
    assert closure["target_summary_resolved"] is True
    assert closure["supersession_verified"] is True
    assert closure["receipt_documents_unchanged"] is True
    assert report["history_preservation"]["postgres_source_receipt_unchanged"] is True
    assert (
        report["history_preservation"]["direct_entity_digests_before"]
        == report["history_preservation"]["direct_entity_digests_after"]
    )

    assert set(report["privacy"].values()) == {False}
    assert report["scope"]["process_level_capability_sandbox"] == "PROVEN"
    assert report["scope"]["incident_resolution_after_recovery"] == "PROVEN"
    encoded = json.dumps(report, sort_keys=True)
    for forbidden in (
        "synthetic-live-customer",
        "postgresql://",
        "/Users/",
        "BEGIN PRIVATE KEY",
    ):
        assert forbidden not in encoded
