import Link from "next/link";
import { IdentifierControl } from "../../../components/identifier-control";
import { DataHubEntityLink } from "../../../components/console-shell";
import { ConnectionEmpty, DateValue, PageHeader, StatusPill, formatUrn, humanize, shortDigest, shortId } from "../../../components/ui";
import { getCampaign } from "../../../lib/forensics-api";

export default async function CampaignDetailPage({ params }: { params: Promise<{ campaignId: string }> }) {
  const campaignId = decodeURIComponent((await params).campaignId);
  const result = await getCampaign(campaignId);
  const campaign = result.data?.campaign;
  return <>
    <PageHeader eyebrow="Campaign" title="Impact scan" description={<IdentifierControl value={campaignId} compact={shortDigest(campaignId)} label="campaign ID" />} action={<div className="header-actions">{campaign && <DataHubEntityLink urn={campaign.incident_urn} label="Open incident" />}<Link className="secondary-action" href="/campaigns">← Back to campaigns</Link></div>} />
    {!campaign ? <ConnectionEmpty connection={result.connection} message={result.message} /> : (
      <div className="detail-layout campaign-detail">
        <div className="detail-main">
          <section className="app-panel change-hero"><div className="change-hero-top"><span className="record-mark campaign large">C</span><div><p>DataHub metadata change</p><h2>{humanize(campaign.change.kind)}</h2><code>{formatUrn(campaign.change.entity_urn)}</code></div><StatusPill state={campaign.processing.workflow_status} /></div><div className="receipt-facts"><span className="date-fact"><small>Occurred</small><strong><DateValue value={campaign.change.occurred_at} /></strong></span><span><small>Aspect</small><strong>{campaign.change.aspect_name}</strong></span><span><small>Assessments</small><strong>{campaign.assessments.length}</strong></span><span><small>Writeback</small><strong>{humanize(campaign.processing.datahub_writeback_state)}</strong></span></div></section>
          <section className="app-panel detail-panel"><div className="panel-heading"><div><p>Deterministic policy</p><h2>Decision findings</h2></div><span>{campaign.policy_version}</span></div><div className="assessment-list">{campaign.assessments.map((assessment) => <Link href={`/investigations/${encodeURIComponent(assessment.receipt_id)}`} key={assessment.receipt_id}><span className="record-mark">D</span><div><strong className="mono">{shortDigest(assessment.receipt_id)}</strong><small>{humanize(assessment.reason_code)}</small></div><StatusPill state={assessment.state} /><span className="row-arrow">→</span></Link>)}</div></section>
        </div>
        <aside className="detail-rail"><section className="app-panel evidence-health"><p>Processing</p><h2>{humanize(campaign.processing.workflow_status)}</h2><dl><div><dt>Attempts</dt><dd>{campaign.processing.attempt_count}</dd></div><div><dt>Writeback</dt><dd>{humanize(campaign.processing.datahub_writeback_state)}</dd></div><div><dt>Error recorded</dt><dd>{campaign.processing.last_error_recorded ? "Yes" : "No"}</dd></div><div><dt>Incident</dt><dd>{shortId(campaign.incident_urn, 18, 8)}</dd></div></dl></section></aside>
      </div>
    )}
  </>;
}
