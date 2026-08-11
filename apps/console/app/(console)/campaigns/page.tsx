import Link from "next/link";
import { ConnectionEmpty, EmptyRecords, PageHeader, StatusPill, formatDate, formatUrn, humanize } from "../../components/ui";
import { getCampaigns } from "../../lib/forensics-api";

export default async function CampaignsPage() {
  const result = await getCampaigns();
  return <>
    <PageHeader eyebrow="DataHub Action" title="Campaigns" description="Persisted impact scans created from metadata changes." />
    {result.data === null ? <ConnectionEmpty connection={result.connection} message={result.message} /> : (
      <section className="app-panel list-panel">
        <div className="list-toolbar"><div><strong>Invalidation history</strong><span>Direct Action state, not projected UI state</span></div><span>{result.data.total} campaigns</span></div>
        {result.data.campaigns.length ? <div className="data-table campaigns-table">
          <div className="table-head"><span>DataHub change</span><span>Findings</span><span>Writeback</span><span>Processed</span><span /></div>
          {result.data.campaigns.map((campaign) => <Link className="table-row" href={`/campaigns/${encodeURIComponent(campaign.campaign_id)}`} key={campaign.campaign_id}>
            <span className="table-primary"><b className="record-mark campaign">C</b><span><strong>{humanize(campaign.change.kind)}</strong><small className="mono">{formatUrn(campaign.change.entity_urn)}</small></span></span>
            <span className="finding-pills">{campaign.assessments.slice(0, 2).map((item) => <StatusPill state={item.state} key={item.receipt_id} />)}</span>
            <StatusPill state={campaign.processing.datahub_writeback_state} />
            <span><strong>{formatDate(campaign.change.occurred_at)}</strong></span><span className="row-arrow">→</span>
          </Link>)}
        </div> : <EmptyRecords title="No campaigns persisted" description="The DataHub Action has not processed a metadata change yet." />}
      </section>
    )}
  </>;
}
