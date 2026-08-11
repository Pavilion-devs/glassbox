import Link from "next/link";
import type { ReactNode } from "react";
import type { ConnectionState } from "../lib/forensics-api";

export function PageHeader({
  eyebrow,
  title,
  description,
  action,
}: {
  eyebrow: string;
  title: string;
  description?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <header className="page-header">
      <div><p>{eyebrow}</p><h1>{title}</h1>{description && <span>{description}</span>}</div>
      {action}
    </header>
  );
}

export function ConnectionEmpty({
  connection,
  message,
}: {
  connection: ConnectionState;
  message: string | null;
}) {
  return (
    <section className="connection-empty">
      <span className="empty-visual" aria-hidden="true"><i /><i /><i /></span>
      <div>
        <p>{connection === "not-configured" ? "Connection required" : "Connection unavailable"}</p>
        <h2>{connection === "not-configured" ? "Connect your evidence plane" : "GlassBox cannot reach the evidence plane"}</h2>
        <span>{message ?? "No application data was loaded."}</span>
      </div>
      <Link className="primary-action" href="/settings">Open settings <span aria-hidden="true">→</span></Link>
    </section>
  );
}

export function EmptyRecords({ title, description }: { title: string; description: string }) {
  return <section className="records-empty"><span aria-hidden="true"><Icon name="target" /></span><h2>{title}</h2><p>{description}</p></section>;
}

/*
 * Service enums carry three different axes — decision trust, processing
 * progress, and store availability — through one pill. Mapping them
 * explicitly keeps an unrecognised enum visibly neutral rather than letting a
 * near-miss (FAILED vs FAIL) silently render as an unremarkable grey chip.
 */
const STATE_META: Record<string, { label: string; tone: string }> = {
  // Decision trust
  STALE: { label: "Stale", tone: "danger" },
  AT_RISK: { label: "At risk", tone: "danger" },
  UNKNOWN: { label: "Unknown", tone: "warn" },
  NO_RECORDED_FINDING: { label: "No findings", tone: "neutral" },
  UNAFFECTED: { label: "Unaffected", tone: "safe" },
  SUPERSEDED: { label: "Superseded", tone: "muted" },
  VERIFIED: { label: "Verified", tone: "safe" },
  VERIFIED_NOW: { label: "Verified", tone: "safe" },
  PROVEN: { label: "Proven", tone: "safe" },
  UNVERIFIED: { label: "Unverified", tone: "warn" },
  ACTIVE: { label: "Active", tone: "safe" },
  REVOKED: { label: "Revoked", tone: "danger" },
  // Processing
  COMPLETED: { label: "Completed", tone: "safe" },
  PENDING: { label: "Pending", tone: "warn" },
  AWAITING_AUTHORIZATION: { label: "Awaiting authorization", tone: "warn" },
  FAILED: { label: "Failed", tone: "danger" },
  NOT_REQUIRED: { label: "Not required", tone: "muted" },
  // Completeness and availability
  COMPLETE: { label: "Complete", tone: "safe" },
  INCOMPLETE: { label: "Incomplete", tone: "warn" },
  AVAILABLE: { label: "Available", tone: "safe" },
  UNAVAILABLE: { label: "Unavailable", tone: "danger" },
  OBSERVED: { label: "Observed", tone: "neutral" },
};

/** Ordering for triage surfaces: the least trustworthy decision sorts first. */
const RISK_RANK: Record<string, number> = {
  STALE: 4,
  AT_RISK: 4,
  UNKNOWN: 3,
  NO_RECORDED_FINDING: 2,
  UNAFFECTED: 1,
  SUPERSEDED: 0,
};

/** States that put a decision in the operator's work queue. */
export const REVIEW_STATES = ["STALE", "AT_RISK", "UNKNOWN"];

export function needsReview(state: string) {
  return REVIEW_STATES.includes(state);
}

export function byRisk<T extends { state: string; ended_at?: string }>(a: T, b: T) {
  const rank = (RISK_RANK[b.state] ?? 2) - (RISK_RANK[a.state] ?? 2);
  return rank !== 0 ? rank : (b.ended_at ?? "").localeCompare(a.ended_at ?? "");
}

export function StatusPill({ state }: { state: string }) {
  const meta = STATE_META[state] ?? { label: humanize(state), tone: "neutral" };
  return <span className={`status-pill ${meta.tone}`}><i aria-hidden="true" />{meta.label}</span>;
}

export function humanize(value: string) {
  return value.toLowerCase().replaceAll("_", " ").replace(/(^|\s)\S/g, (letter) => letter.toUpperCase());
}

/*
 * Identifier formatting.
 *
 * DataHub URNs and GlassBox receipt IDs share long constant prefixes, so
 * head-truncating them renders the segment every row has in common and hides
 * the one that tells them apart. These helpers keep the discriminating part.
 */

const DATASET_URN = /^urn:li:dataset:\(urn:li:dataPlatform:([^,]+),([^,]+),([^)]+)\)$/;
const SCHEMA_FIELD_URN = /^urn:li:schemaField:\((urn:li:dataset:\(.+\)),([^,)]+)\)$/;
const DOCUMENT_URN = /^urn:li:document:(.+?)\.([0-9a-f]{16,})$/;
const DIGEST_PREFIX = /^(?:gbx:(?:receipt|invalidation):sha256:|gbx:evidence:)/;

/** Collapses a DataHub URN to its readable, row-distinguishing parts. */
export function formatUrn(value: string): string {
  const field = SCHEMA_FIELD_URN.exec(value);
  if (field) return `${formatUrn(field[1])} → ${field[2]}`;

  const dataset = DATASET_URN.exec(value);
  if (dataset) return `${dataset[1]} · ${dataset[2]} · ${dataset[3]}`;

  const document = DOCUMENT_URN.exec(value);
  if (document) return `${document[1]}.${shortDigest(document[2])}`;

  return value;
}

/** Keeps the distinguishing dataset name and environment in narrow summaries. */
export function compactUrn(value: string): string {
  const dataset = DATASET_URN.exec(value);
  return dataset ? `${dataset[2]} · ${dataset[3]}` : formatUrn(value);
}

const COMPACT_CHANGE_LABELS: Record<string, string> = {
  SCHEMA_FIELD_TYPE_CHANGED: "Field type changed",
  SCHEMA_FIELD_ADDED: "Field added",
  SCHEMA_FIELD_REMOVED: "Field removed",
};

export function compactChangeLabel(value: string) {
  return COMPACT_CHANGE_LABELS[value] ?? humanize(value);
}

/** Drops the shared scheme prefix and keeps both ends of the digest. */
export function shortDigest(value: string, head = 10, tail = 8) {
  const digest = value.replace(DIGEST_PREFIX, "");
  return digest.length > head + tail + 1
    ? `${digest.slice(0, head)}…${digest.slice(-tail)}`
    : digest;
}

/** Generic middle-truncation, for identifiers with no known structure. */
export function shortId(value: string, head = 16, tail = 8) {
  return value.length > head + tail ? `${value.slice(0, head)}…${value.slice(-tail)}` : value;
}

export function formatDate(value: string) {
  try {
    return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
  } catch {
    return value;
  }
}

export function DateValue({ value }: { value: string }) {
  let day = value;
  let time: string | null = null;
  try {
    const date = new Date(value);
    day = new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(date);
    time = new Intl.DateTimeFormat("en", { timeStyle: "short" }).format(date);
  } catch {}
  return <time className="date-value" dateTime={value}><span>{day}</span>{time && <span>{time}</span>}</time>;
}

const PATHS = {
  alert: ["M12 9v4m0 4h.01M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z"],
  receipt: ["M4 2v20l2.5-2 2.5 2 2.5-2 2.5 2 2.5-2 2.5 2V2l-2.5 2L14 2l-2.5 2L9 2 6.5 4 4 2Zm4 7h8M8 13h5"],
  link: ["M10 13a5 5 0 0 0 7.5.5l3-3a5 5 0 0 0-7-7l-1.7 1.7M14 11a5 5 0 0 0-7.5-.5l-3 3a5 5 0 0 0 7 7l1.7-1.7"],
  trend: ["M22 7 13.5 15.5l-5-5L2 17M16 7h6v6"],
  target: ["M12 21a9 9 0 1 0 0-18 9 9 0 0 0 0 18Zm0-5a4 4 0 1 0 0-8 4 4 0 0 0 0 8Z"],
  shield: ["M20 13c0 5-3.5 7.5-7.7 8.9a1 1 0 0 1-.6 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.2-2.7a1 1 0 0 1 1.6 0C14.5 3.8 17 5 19 5a1 1 0 0 1 1 1v7Zm-11-1 2 2 4-4"],
  grid: ["M3 3h7v7H3zM14 3h7v7h-7zM14 14h7v7h-7zM3 14h7v7H3z"],
  search: ["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16Z", "m21 21-4.3-4.3"],
  pulse: ["M2 12h4l3 8 6-16 3 8h4"],
  replay: ["M3 12a9 9 0 1 0 3-6.7L3 8", "M3 3v5h5"],
  settings: ["M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6Z", "M19.6 14.5a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.5v.2a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.6 1.7 1.7 0 0 0-1.9.4l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.9 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.6-1.1 1.7 1.7 0 0 0-.4-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.9.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.9V9a1.7 1.7 0 0 0 1.5 1h.2a2 2 0 1 1 0 4H21a1.7 1.7 0 0 0-1.5 1Z"],
  refresh: ["M21 12a9 9 0 1 1-2.6-6.4L21 8", "M21 3v5h-5"],
  sun: ["M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10Z", "M12 1v2M12 21v2M4.2 4.2l1.4 1.4M18.4 18.4l1.4 1.4M1 12h2M21 12h2M4.2 19.8l1.4-1.4M18.4 5.6l1.4-1.4"],
  moon: ["M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"],
};

export type IconName = keyof typeof PATHS;

/** Inline so the console ships no icon font and makes no external request. */
export function Icon({ name }: { name: IconName }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {PATHS[name].map((d) => <path d={d} key={d} />)}
    </svg>
  );
}
