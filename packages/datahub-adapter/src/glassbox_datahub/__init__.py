"""DataHub integration boundary for GlassBox."""

from glassbox_datahub.capability_probe import (
    CapabilityReport,
    CapabilityStatus,
    EntitySpec,
    ProbePlan,
    ProbeRunner,
    build_probe_plan,
)
from glassbox_datahub.closure import (
    DataHubRecoveryClosureBackend,
    RecoveryClosureBackend,
    RecoveryClosureEmitter,
    RecoveryClosureError,
    RecoveryClosurePrerequisites,
    RecoveryClosureReadback,
    RecoveryClosureReport,
    merge_resolved_incident_summary,
)
from glassbox_datahub.invalidation import (
    DataHubInvalidationBackend,
    DataHubInvalidationError,
    merge_active_incident_summary,
)
from glassbox_datahub.receipt_emitter import (
    DataHubReceiptBackend,
    ReceiptEmissionError,
    ReceiptEmissionReport,
    ReceiptEmitter,
    ReceiptReadbackReport,
    merge_receipt_custom_properties,
    receipt_document_urn,
)
from glassbox_datahub.supersession import (
    DataHubSupersessionBackend,
    SupersessionEmissionError,
    SupersessionEmissionReport,
    SupersessionEmitter,
    SupersessionReadback,
    supersession_document_urn,
    supersession_properties,
)

__all__ = [
    "CapabilityReport",
    "CapabilityStatus",
    "DataHubInvalidationBackend",
    "DataHubInvalidationError",
    "DataHubReceiptBackend",
    "DataHubRecoveryClosureBackend",
    "DataHubSupersessionBackend",
    "EntitySpec",
    "ProbePlan",
    "ProbeRunner",
    "ReceiptEmissionError",
    "ReceiptEmissionReport",
    "ReceiptEmitter",
    "ReceiptReadbackReport",
    "RecoveryClosureBackend",
    "RecoveryClosureEmitter",
    "RecoveryClosureError",
    "RecoveryClosurePrerequisites",
    "RecoveryClosureReadback",
    "RecoveryClosureReport",
    "SupersessionEmissionError",
    "SupersessionEmissionReport",
    "SupersessionEmitter",
    "SupersessionReadback",
    "build_probe_plan",
    "merge_active_incident_summary",
    "merge_receipt_custom_properties",
    "merge_resolved_incident_summary",
    "receipt_document_urn",
    "supersession_document_urn",
    "supersession_properties",
]
