import { headers } from "next/headers";

export type ConnectionProof = {
  connection: string;
  authentication: string;
  sdk_compatibility: string;
  sdk_version: string;
  server_version: string | null;
  write_proof: string;
  probe_document_urn: string | null;
};

export type DataHubConnectionSummary = {
  connection_id: string;
  server_url: string;
  ui_url: string | null;
  probe: ConnectionProof;
  verified_at: string;
  updated_at: string;
  updated_by: string;
  credential_state: "ENCRYPTED";
};

export type IngestionKeySummary = {
  key_id: string;
  name: string;
  display_prefix: string;
  created_at: string;
  created_by: string;
  revoked_at: string | null;
  revoked_by: string | null;
  state: "ACTIVE" | "REVOKED";
};

export type ControlSnapshot = {
  availability: "available" | "not-configured" | "offline" | "unauthenticated";
  connection: DataHubConnectionSummary | null;
  keys: IngestionKeySummary[];
  role: "viewer" | "operator" | "admin" | null;
  message: string | null;
};

export type PublicationReadback = {
  contract_version: "glassbox.publication-readback.v1";
  receipt_id: string;
  document_urn: string;
  verification_state: "VERIFIED_NOW";
  aspect_names: string[];
  aspect_count: number;
  raw_content_returned: false;
};

export type PublicationReadbackResult = {
  availability: "available" | "not-configured" | "offline" | "unauthenticated";
  data: PublicationReadback | null;
  message: string | null;
};

type Principal = { subject: string; role: "viewer" | "operator" | "admin" };

function controlBase() {
  return process.env.GLASSBOX_CONTROL_API_URL?.replace(/\/$/, "") ?? null;
}

function principalFromHeaders(requestHeaders: Headers): Principal | null {
  const email =
    requestHeaders.get("x-auth-request-email") ??
    requestHeaders.get("x-forwarded-email") ??
    requestHeaders.get("oai-authenticated-user-email");
  const username =
    requestHeaders.get("x-auth-request-user") ??
    requestHeaders.get("x-forwarded-user");
  const subject = email ?? username;
  const suppliedRole = requestHeaders.get("x-glassbox-role")?.toLowerCase();
  if (subject && ["viewer", "operator", "admin"].includes(suppliedRole ?? "")) {
    return { subject, role: suppliedRole as Principal["role"] };
  }
  if (subject) {
    const adminEmails = new Set(
      (process.env.GLASSBOX_ADMIN_EMAILS ?? "")
        .split(",")
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean),
    );
    const adminUsers = new Set(
      (process.env.GLASSBOX_ADMIN_USERS ?? "")
        .split(",")
        .map((value) => value.trim().toLowerCase())
        .filter(Boolean),
    );
    const isAdmin =
      (email !== null && adminEmails.has(email.toLowerCase())) ||
      (username !== null && adminUsers.has(username.toLowerCase()));
    return { subject, role: isAdmin ? "admin" : "viewer" };
  }
  if (process.env.GLASSBOX_ALLOW_LOCAL_OPERATOR === "true") {
    return { subject: "local-operator", role: "admin" };
  }
  return null;
}

export async function proxyControlRequest(
  path: string,
  request: Request,
): Promise<Response> {
  const base = controlBase();
  const internalToken = process.env.GLASSBOX_CONTROL_API_TOKEN;
  if (!base || !internalToken) {
    return apiError(503, "CONTROL_NOT_CONFIGURED", "The control plane is not configured.");
  }
  const principal = principalFromHeaders(request.headers);
  if (!principal) {
    return apiError(401, "UNAUTHENTICATED", "Sign in to manage this deployment.");
  }
  if (!allowedControlPath(path)) {
    return apiError(404, "NOT_FOUND", "Control route was not found.");
  }
  const body = ["POST", "PUT"].includes(request.method) ? await request.text() : undefined;
  if (body && new TextEncoder().encode(body).byteLength > 32 * 1024) {
    return apiError(413, "PAYLOAD_TOO_LARGE", "Control request exceeds 32 KiB.");
  }
  try {
    const upstream = await fetch(`${base}/api/v1/${path}`, {
      method: request.method,
      cache: "no-store",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${internalToken}`,
        "content-type": "application/json",
        "x-glassbox-subject": principal.subject,
        "x-glassbox-role": principal.role,
      },
      body,
    });
    return new Response(await upstream.text(), {
      status: upstream.status,
      headers: {
        "content-type": "application/json",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      },
    });
  } catch {
    return apiError(503, "CONTROL_OFFLINE", "The control plane is unreachable.");
  }
}

export async function getControlSnapshot(): Promise<ControlSnapshot> {
  const base = controlBase();
  const internalToken = process.env.GLASSBOX_CONTROL_API_TOKEN;
  if (!base || !internalToken) {
    return {
      availability: "not-configured",
      connection: null,
      keys: [],
      role: null,
      message: "The deployment control plane is not configured.",
    };
  }
  const principal = principalFromHeaders(await headers());
  if (!principal) {
    return {
      availability: "unauthenticated",
      connection: null,
      keys: [],
      role: null,
      message: "Sign in through the deployment identity provider to manage connections.",
    };
  }
  try {
    const sharedHeaders = {
      accept: "application/json",
      authorization: `Bearer ${internalToken}`,
      "x-glassbox-subject": principal.subject,
      "x-glassbox-role": principal.role,
    };
    const connectionResponse = await fetch(`${base}/api/v1/connection`, {
      cache: "no-store",
      headers: sharedHeaders,
    });
    const connectionBody = await connectionResponse.json();
    if (!connectionResponse.ok) {
      return {
        availability: connectionResponse.status === 401 ? "unauthenticated" : "offline",
        connection: null,
        keys: [],
        role: principal.role,
        message: apiMessage(connectionBody) ?? "The control plane rejected the request.",
      };
    }
    let keys: IngestionKeySummary[] = [];
    if (principal.role === "admin") {
      const keyResponse = await fetch(`${base}/api/v1/ingestion-keys`, {
        cache: "no-store",
        headers: sharedHeaders,
      });
      if (keyResponse.ok) {
        const keyBody = await keyResponse.json();
        if (Array.isArray(keyBody.keys)) keys = keyBody.keys;
      }
    }
    return {
      availability: "available",
      connection: connectionBody.connection ?? null,
      keys,
      role: principal.role,
      message: null,
    };
  } catch {
    return {
      availability: "offline",
      connection: null,
      keys: [],
      role: principal.role,
      message: "The configured control plane is unreachable.",
    };
  }
}

export async function getDataHubUiOrigin(): Promise<string | null> {
  const base = controlBase();
  const internalToken = process.env.GLASSBOX_CONTROL_API_TOKEN;
  if (!base || !internalToken) return null;
  const principal = principalFromHeaders(await headers());
  if (!principal) return null;
  try {
    const response = await fetch(`${base}/api/v1/connection`, {
      cache: "no-store",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${internalToken}`,
        "x-glassbox-subject": principal.subject,
        "x-glassbox-role": principal.role,
      },
    });
    if (!response.ok) return null;
    const body = await response.json();
    const uiUrl = body.connection?.ui_url;
    return typeof uiUrl === "string" ? uiUrl.replace(/\/$/, "") : null;
  } catch {
    return null;
  }
}

export async function getPublicationReadback(
  receiptId: string,
): Promise<PublicationReadbackResult> {
  const base = controlBase();
  const internalToken = process.env.GLASSBOX_CONTROL_API_TOKEN;
  if (!base || !internalToken) {
    return {
      availability: "not-configured",
      data: null,
      message: "The deployment control plane is not configured.",
    };
  }
  const principal = principalFromHeaders(await headers());
  if (!principal) {
    return {
      availability: "unauthenticated",
      data: null,
      message: "Sign in to verify the DataHub publication.",
    };
  }
  try {
    const response = await fetch(
      `${base}/api/v1/publications/${encodeURIComponent(receiptId)}/readback`,
      {
        cache: "no-store",
        headers: {
          accept: "application/json",
          authorization: `Bearer ${internalToken}`,
          "x-glassbox-subject": principal.subject,
          "x-glassbox-role": principal.role,
        },
      },
    );
    const body: unknown = await response.json();
    if (!response.ok) {
      return {
        availability: response.status === 401 ? "unauthenticated" : "offline",
        data: null,
        message: apiMessage(body) ?? "Fresh DataHub readback failed.",
      };
    }
    if (!validPublicationReadback(body)) {
      return {
        availability: "offline",
        data: null,
        message: "The control plane returned an unsupported readback contract.",
      };
    }
    return { availability: "available", data: body, message: null };
  } catch {
    return {
      availability: "offline",
      data: null,
      message: "The fresh DataHub readback is currently unavailable.",
    };
  }
}

function allowedControlPath(path: string) {
  return (
    path === "connection" ||
    path === "connection/test" ||
    path === "ingestion-keys" ||
    /^ingestion-keys\/ik_[0-9a-f]{32}$/.test(path)
  );
}

function apiMessage(value: unknown) {
  if (!value || typeof value !== "object") return null;
  const error = (value as { error?: unknown }).error;
  if (!error || typeof error !== "object") return null;
  const message = (error as { message?: unknown }).message;
  return typeof message === "string" ? message : null;
}

function validPublicationReadback(value: unknown): value is PublicationReadback {
  if (!value || typeof value !== "object") return false;
  const readback = value as Record<string, unknown>;
  return (
    readback.contract_version === "glassbox.publication-readback.v1" &&
    typeof readback.receipt_id === "string" &&
    typeof readback.document_urn === "string" &&
    readback.verification_state === "VERIFIED_NOW" &&
    Array.isArray(readback.aspect_names) &&
    readback.aspect_names.every((item) => typeof item === "string") &&
    typeof readback.aspect_count === "number" &&
    readback.raw_content_returned === false
  );
}

function apiError(status: number, code: string, message: string) {
  return Response.json(
    {
      contract_version: "glassbox.console-control-proxy.v1",
      error: { code, message },
      raw_content_returned: false,
    },
    { status, headers: { "cache-control": "no-store" } },
  );
}
