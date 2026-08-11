export type ConnectionState = "connected" | "not-configured" | "offline";

export type ApiResult<T> = {
  connection: ConnectionState;
  data: T | null;
  message: string | null;
};

export type Overview = {
  availability: { receipt_index: string; campaign_store: string };
  counts: {
    receipts: number;
    dependencies: number;
    unresolved_dependencies: number;
    campaigns: number;
    review_required: number;
  };
  state_counts: Record<string, number>;
};

export type DecisionDependency = {
  evidence_id: string;
  datahub_urn: string | null;
  schema_field_urn: string | null;
  state: string;
  role: string;
};

export type DecisionSummary = {
  receipt_id: string;
  document_urn: string;
  ended_at: string;
  superseded_by: string | null;
  state: string;
  dependency_count: number;
  resolved_dependency_count: number;
  field_lineage_coverage: string;
  wildcard_query: boolean | null;
  dependencies: DecisionDependency[];
};

export type DecisionList = {
  availability: string;
  total: number;
  returned: number;
  truncated: boolean;
  decisions: DecisionSummary[];
};

export type Assessment = {
  receipt_id: string;
  document_urn: string;
  state: string;
  reason_code: string;
  matched_evidence_ids: string[];
  policy_version: string;
  quarantine_required: boolean;
};

export type Campaign = {
  campaign_id: string;
  incident_urn: string;
  change: {
    event_id: string;
    entity_urn: string;
    aspect_name: string;
    kind: string;
    occurred_at: string;
    schema_field_urn: string | null;
  };
  policy_version: string;
  assessments: Assessment[];
  processing: {
    workflow_status: string;
    attempt_count: number;
    datahub_writeback_state: string;
    last_error_recorded: boolean;
  };
};

export type CampaignList = {
  availability: string;
  total: number;
  returned: number;
  truncated: boolean;
  campaigns: Campaign[];
};

export type CampaignDetail = {
  availability: string;
  campaign: Campaign;
};

export type ReceiptDetail = {
  verification: {
    receipt_id: string;
    verification_state: string;
    valid: boolean | null;
    checks?: Record<string, boolean | number | null>;
    failure_codes?: string[];
  };
  influence: {
    receipt_id: string;
    document_urn: string;
    ended_at: string;
    superseded_by: string | null;
    integrity: { state: string; fresh_verification: boolean };
    completeness: {
      dependency_resolution: string;
      resolved_dependencies: number;
      recorded_dependencies: number;
      field_lineage_coverage: string;
      field_lineage_rule_id: string | null;
      wildcard_query: boolean | null;
    };
    dependencies: Array<DecisionDependency & { observed_at?: string | null }>;
  };
  publication: {
    receipt_id: string;
    availability: string;
    durability?: {
      authority: string;
      workflow_status: string;
      attempt_count: number;
      last_error_recorded: boolean;
      sealed_evidence: boolean;
    };
    datahub?: {
      document_urn: string | null;
      aspect_names: string[];
      aspect_count: number;
      emission_count: number | null;
    };
    raw_content_returned: false;
  };
};

export type FindingList = {
  availability: string;
  scan_complete: boolean;
  findings_total: number;
  findings: Array<{
    campaign_id: string;
    incident_urn: string;
    change: Campaign["change"];
    assessment: Assessment;
    processing: Campaign["processing"];
  }>;
};

function apiBase() {
  return process.env.GLASSBOX_FORENSICS_API_URL?.replace(/\/$/, "") ?? null;
}

async function request(path: string): Promise<ApiResult<unknown>> {
  const base = apiBase();
  if (base === null) {
    return {
      connection: "not-configured",
      data: null,
      message: "The GlassBox forensics service is not configured.",
    };
  }
  try {
    const bearer = process.env.GLASSBOX_FORENSICS_API_TOKEN;
    const response = await fetch(`${base}${path}`, {
      cache: "no-store",
      headers: {
        accept: "application/json",
        ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      },
    });
    const body: unknown = await response.json();
    if (!response.ok) {
      return {
        connection: "connected",
        data: null,
        message: apiError(body) ?? `The forensics service returned HTTP ${response.status}.`,
      };
    }
    return { connection: "connected", data: body, message: null };
  } catch {
    return {
      connection: "offline",
      data: null,
      message: "The configured GlassBox forensics service is unreachable.",
    };
  }
}

function apiError(value: unknown): string | null {
  const root = record(value);
  const error = root ? record(root.error) : null;
  return error && typeof error.message === "string" ? error.message : null;
}

function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function validOverview(value: unknown): value is Overview {
  const root = record(value);
  const availability = root ? record(root.availability) : null;
  const counts = root ? record(root.counts) : null;
  return Boolean(
    availability &&
      typeof availability.receipt_index === "string" &&
      typeof availability.campaign_store === "string" &&
      counts &&
      typeof counts.receipts === "number" &&
      typeof counts.dependencies === "number" &&
      typeof counts.unresolved_dependencies === "number" &&
      typeof counts.campaigns === "number" &&
      typeof counts.review_required === "number" &&
      record(root?.state_counts),
  );
}

function validDecisionList(value: unknown): value is DecisionList {
  const root = record(value);
  return Boolean(
    root &&
      typeof root.availability === "string" &&
      typeof root.total === "number" &&
      Array.isArray(root.decisions) &&
      root.decisions.every((item) => {
        const decision = record(item);
        return Boolean(
          decision &&
            typeof decision.receipt_id === "string" &&
            typeof decision.document_urn === "string" &&
            typeof decision.ended_at === "string" &&
            typeof decision.state === "string" &&
            typeof decision.dependency_count === "number" &&
            Array.isArray(decision.dependencies),
        );
      }),
  );
}

function validCampaignList(value: unknown): value is CampaignList {
  const root = record(value);
  return Boolean(
    root &&
      typeof root.availability === "string" &&
      typeof root.total === "number" &&
      Array.isArray(root.campaigns) &&
      root.campaigns.every((item) => {
        const campaign = record(item);
        return Boolean(
          campaign &&
            typeof campaign.campaign_id === "string" &&
            typeof campaign.incident_urn === "string" &&
            record(campaign.change) &&
            Array.isArray(campaign.assessments) &&
            record(campaign.processing),
        );
      }),
  );
}

function validCampaignDetail(value: unknown): value is CampaignDetail {
  const root = record(value);
  const campaign = root ? record(root.campaign) : null;
  return Boolean(
    root &&
      typeof root.availability === "string" &&
      campaign &&
      typeof campaign.campaign_id === "string" &&
      typeof campaign.incident_urn === "string" &&
      record(campaign.change) &&
      Array.isArray(campaign.assessments) &&
      record(campaign.processing),
  );
}

function validReceiptDetail(value: unknown): value is ReceiptDetail {
  const root = record(value);
  const verification = root ? record(root.verification) : null;
  const influence = root ? record(root.influence) : null;
  const publication = root ? record(root.publication) : null;
  return Boolean(
    verification &&
      typeof verification.receipt_id === "string" &&
      typeof verification.verification_state === "string" &&
      influence &&
      typeof influence.receipt_id === "string" &&
      typeof influence.document_urn === "string" &&
      record(influence.completeness) &&
      Array.isArray(influence.dependencies) &&
      publication &&
      typeof publication.receipt_id === "string" &&
      typeof publication.availability === "string" &&
      publication.raw_content_returned === false,
  );
}

function validFindingList(value: unknown): value is FindingList {
  const root = record(value);
  return Boolean(
    root &&
      typeof root.availability === "string" &&
      typeof root.scan_complete === "boolean" &&
      typeof root.findings_total === "number" &&
      Array.isArray(root.findings),
  );
}

function parsed<T>(
  result: ApiResult<unknown>,
  guard: (value: unknown) => value is T,
): ApiResult<T> {
  if (result.data === null) return result as ApiResult<T>;
  if (!guard(result.data)) {
    return {
      connection: result.connection,
      data: null,
      message: "The forensics service returned an unsupported response contract.",
    };
  }
  return { ...result, data: result.data };
}

export async function getConnectionState(): Promise<ConnectionState> {
  return (await request("/health")).connection;
}

export async function getOverview(): Promise<ApiResult<Overview>> {
  return parsed(await request("/api/v1/overview"), validOverview);
}

export async function getDecisions(query = ""): Promise<ApiResult<DecisionList>> {
  const suffix = query ? `?query=${encodeURIComponent(query)}` : "";
  return parsed(await request(`/api/v1/receipts${suffix}`), validDecisionList);
}

export async function getCampaigns(): Promise<ApiResult<CampaignList>> {
  return parsed(await request("/api/v1/campaigns"), validCampaignList);
}

export async function getCampaign(campaignId: string): Promise<ApiResult<CampaignDetail>> {
  return parsed(
    await request(`/api/v1/campaigns/${encodeURIComponent(campaignId)}`),
    validCampaignDetail,
  );
}

export async function getReceipt(receiptId: string): Promise<ApiResult<ReceiptDetail>> {
  return parsed(
    await request(`/api/v1/receipts/${encodeURIComponent(receiptId)}`),
    validReceiptDetail,
  );
}

export async function getFindings(receiptId: string): Promise<ApiResult<FindingList>> {
  return parsed(
    await request(`/api/v1/receipts/${encodeURIComponent(receiptId)}/findings`),
    validFindingList,
  );
}

export function configuredApiUrl(): string | null {
  return apiBase();
}
