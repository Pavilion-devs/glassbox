import Link from "next/link";
import { IdentifierControl } from "../../../components/identifier-control";
import { DataHubEntityLink } from "../../../components/console-shell";
import { ConnectionEmpty, DateValue, EmptyRecords, Icon, PageHeader, StatusPill, formatDate, formatUrn, humanize, shortDigest } from "../../../components/ui";
import { getPublicationReadback, type PublicationReadback } from "../../../lib/control-api";
import { getFindings, getReceipt } from "../../../lib/forensics-api";

export default async function InvestigationDetailPage({ params }: { params: Promise<{ receiptId: string }> }) {
  const receiptId = decodeURIComponent((await params).receiptId);
  const [receipt, findings, readback] = await Promise.all([getReceipt(receiptId), getFindings(receiptId), getPublicationReadback(receiptId)]);
  const proof = receipt.data ? publicationProof(receipt.data.publication, receipt.data.influence.document_urn, readback.data) : null;
  return <>
    <PageHeader
      eyebrow="Investigation"
      title="Decision receipt"
      description={<IdentifierControl value={receiptId} compact={shortDigest(receiptId)} label="receipt ID" />}
      action={<div className="header-actions">{receipt.data && <DataHubEntityLink urn={receipt.data.influence.document_urn} />}<Link className="secondary-action" href="/investigations">← Back to investigations</Link></div>}
    />
    {receipt.data === null ? <ConnectionEmpty connection={receipt.connection} message={receipt.message} /> : (
      <div className="detail-layout">
        <div className="detail-main">
          <section className="app-panel receipt-hero">
            <div className="receipt-hero-top"><span className="record-mark large">D</span><div><p>Verification</p><h2>{humanize(receipt.data.verification.verification_state)}</h2><code>{formatUrn(receipt.data.influence.document_urn)}</code></div><StatusPill state={receipt.data.verification.verification_state} /></div>
            <div className="receipt-facts"><span className="date-fact"><small>Ended</small><strong><DateValue value={receipt.data.influence.ended_at} /></strong></span><span><small>Dependencies</small><strong>{receipt.data.influence.completeness.recorded_dependencies}</strong></span><span><small>Resolution</small><strong>{humanize(receipt.data.influence.completeness.dependency_resolution)}</strong></span><span><small>Field coverage</small><strong>{humanize(receipt.data.influence.completeness.field_lineage_coverage)}</strong></span></div>
          </section>
          {proof && <section className="app-panel detail-panel publication-proof">
            <div className="panel-heading"><div><p>Publication proof</p><h2>DataHub durability</h2></div><StatusPill state={proof.state} /></div>
            <div className="publication-proof-body">
              <div className="publication-proof-summary"><span aria-hidden="true"><Icon name="shield" /></span><div><p>{proof.verified ? "Cross-plane proof complete" : "Proof requires attention"}</p><h3>{proof.verified ? "Persisted and verified now" : humanize(proof.state)}</h3><code title={proof.documentUrn ?? undefined}>{proof.documentUrn ? formatUrn(proof.documentUrn) : "No sealed document URN"}</code></div></div>
              <dl className="publication-proof-facts"><div><dt>Durable state</dt><dd>{proof.workflowStatus}</dd><small>{proof.authority}</small></div><div><dt>Fresh readback</dt><dd>{proof.readbackState}</dd><small>Direct from DataHub</small></div><div><dt>Sealed aspects</dt><dd>{proof.matchedAspectCount}/{proof.sealedAspectCount}</dd><small>Present now</small></div><div><dt>Idempotent writes</dt><dd>{proof.emissionCount ?? "—"}</dd><small>Recorded emissions</small></div></dl>
              {proof.sealedAspects.length > 0 && <div className="publication-aspects" aria-label="Sealed DataHub aspects">{proof.sealedAspects.map((aspect) => <span key={aspect}>{aspect}</span>)}</div>}
              {!proof.verified && <p className="publication-proof-message">{readback.message ?? "The durable record and current DataHub state do not agree."}</p>}
            </div>
          </section>}
          <section className="app-panel detail-panel">
            <div className="panel-heading"><div><p>Runtime influence</p><h2>Dependencies</h2></div><span>{receipt.data.influence.dependencies.length} records</span></div>
            {receipt.data.influence.dependencies.length ? <div className="dependency-list">{receipt.data.influence.dependencies.map((dependency) => <article key={dependency.evidence_id}><span className="dependency-icon" aria-hidden="true" /><div><strong className="mono">{dependency.schema_field_urn || dependency.datahub_urn ? formatUrn((dependency.schema_field_urn ?? dependency.datahub_urn)!) : "Unresolved dependency"}</strong><code>{dependency.evidence_id}</code></div><StatusPill state={dependency.state} /><span className="role-chip">{dependency.role}</span></article>)}</div> : <EmptyRecords title="No dependencies recorded" description="This receipt contains no governed evidence projection." />}
          </section>
          <section className="app-panel detail-panel">
            <div className="panel-heading"><div><p>Action history</p><h2>Findings</h2></div><span>{findings.data?.findings_total ?? 0} findings</span></div>
            {findings.data?.findings.length ? <div className="finding-list">{findings.data.findings.map((finding) => <Link href={`/campaigns/${encodeURIComponent(finding.campaign_id)}`} key={finding.campaign_id}><span className="finding-symbol" aria-hidden="true" /><div><strong>{humanize(finding.change.kind)}</strong><small>{formatDate(finding.change.occurred_at)} · {humanize(finding.assessment.reason_code)}</small></div><StatusPill state={finding.assessment.state} /><span className="row-arrow">→</span></Link>)}</div> : <EmptyRecords title="No findings recorded" description={findings.message ?? "No persisted campaign currently references this receipt."} />}
          </section>
        </div>
        <aside className="detail-rail">
          <section className="app-panel evidence-health"><p>Evidence health</p><h2>{humanize(receipt.data.influence.completeness.dependency_resolution)}</h2><dl><div><dt>Fresh verification</dt><dd>{receipt.data.influence.integrity.fresh_verification ? "Yes" : "No"}</dd></div><div><dt>Resolved</dt><dd>{receipt.data.influence.completeness.resolved_dependencies}/{receipt.data.influence.completeness.recorded_dependencies}</dd></div><div><dt>Wildcard query</dt><dd>{receipt.data.influence.completeness.wildcard_query === null ? "Unknown" : receipt.data.influence.completeness.wildcard_query ? "Yes" : "No"}</dd></div><div><dt>Superseded</dt><dd>{receipt.data.influence.superseded_by ? "Yes" : "No"}</dd></div></dl></section>
          <section className="app-panel raw-free-card"><span aria-hidden="true"><Icon name="shield" /></span><div><p>Privacy boundary</p><h2>Raw content withheld</h2><small>Only digests, governed URNs, reason codes, and verification results are displayed.</small></div></section>
        </aside>
      </div>
    )}
  </>;
}

type PublicationState = {
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
};

function publicationProof(
  publication: PublicationState,
  influenceDocumentUrn: string,
  readback: PublicationReadback | null,
) {
  const sealedAspects = publication.datahub?.aspect_names ?? [];
  const currentAspects = new Set(readback?.aspect_names ?? []);
  const matchedAspectCount = sealedAspects.filter((aspect) => currentAspects.has(aspect)).length;
  const identifiersMatch = Boolean(
    readback &&
      readback.receipt_id === publication.receipt_id &&
      readback.document_urn === publication.datahub?.document_urn &&
      readback.document_urn === influenceDocumentUrn,
  );
  const durable = Boolean(
    publication.availability === "AVAILABLE" &&
      publication.durability?.authority === "POSTGRESQL" &&
      publication.durability.workflow_status === "COMPLETED" &&
      publication.durability.sealed_evidence &&
      !publication.durability.last_error_recorded &&
      publication.datahub?.emission_count === 2,
  );
  const verified = Boolean(
    durable &&
      identifiersMatch &&
      readback?.verification_state === "VERIFIED_NOW" &&
      sealedAspects.length > 0 &&
      matchedAspectCount === sealedAspects.length,
  );
  return {
    verified,
    state: verified ? "VERIFIED_NOW" : readback ? "MISMATCH" : "UNAVAILABLE",
    documentUrn: publication.datahub?.document_urn ?? null,
    workflowStatus: publication.durability?.workflow_status ?? humanize(publication.availability),
    authority: publication.durability?.authority ?? "No durable authority",
    readbackState: readback?.verification_state ?? "UNAVAILABLE",
    sealedAspects,
    sealedAspectCount: sealedAspects.length,
    matchedAspectCount,
    emissionCount: publication.datahub?.emission_count ?? null,
  };
}
