"""Read-only, proof-carrying agent-decision forensics."""

from glassbox_forensics.dual_mcp import (
    DUAL_MCP_CONTRACT_VERSION,
    DualMCPExpectation,
    DualMCPProofError,
    MCPToolContract,
    compose_dual_mcp_evidence,
)
from glassbox_forensics.narration import (
    NARRATION_BRIEF_CONTRACT_VERSION,
    NARRATION_EVALUATION_CONTRACT_VERSION,
    NARRATION_RESPONSE_CONTRACT_VERSION,
    NarrationContractError,
    build_narration_brief,
    evaluate_agent_narration,
)
from glassbox_forensics.service import (
    CampaignFindingReader,
    ForensicsInputError,
    ForensicsNotFoundError,
    ForensicsService,
    PersistedCampaign,
    PersistedReceiptPublication,
    ReceiptArtifactReader,
    ReceiptProfileReader,
    ReceiptPublicationReader,
)

__all__ = [
    "DUAL_MCP_CONTRACT_VERSION",
    "NARRATION_BRIEF_CONTRACT_VERSION",
    "NARRATION_EVALUATION_CONTRACT_VERSION",
    "NARRATION_RESPONSE_CONTRACT_VERSION",
    "CampaignFindingReader",
    "DualMCPExpectation",
    "DualMCPProofError",
    "ForensicsInputError",
    "ForensicsNotFoundError",
    "ForensicsService",
    "MCPToolContract",
    "NarrationContractError",
    "PersistedCampaign",
    "PersistedReceiptPublication",
    "ReceiptArtifactReader",
    "ReceiptProfileReader",
    "ReceiptPublicationReader",
    "build_narration_brief",
    "compose_dual_mcp_evidence",
    "evaluate_agent_narration",
]

__version__ = "0.1.0"
