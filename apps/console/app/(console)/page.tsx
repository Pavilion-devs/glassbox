import Link from "next/link";
import { ConnectionEmpty, EmptyRecords, Icon, PageHeader, StatusPill, byRisk, compactChangeLabel, compactUrn, formatDate, shortDigest } from "../components/ui";
import { getCampaigns, getDecisions, getOverview } from "../lib/forensics-api";

export default async function OverviewPage() {
  const [overview, decisions, campaigns] = await Promise.all([
    getOverview(),
    getDecisions(),
    getCampaigns(),
  ]);
  return (
    <>
      <PageHeader eyebrow="Workspace" title="Overview" description="Decision validity across your connected evidence plane." />
      {overview.data === null ? (
        <ConnectionEmpty connection={overview.connection} message={overview.message} />
      ) : (
        <>
          <section className="metric-row" aria-label="Evidence overview">
            <Link className="metric-link" href="/investigations"><article><span className="metric-icon review"><Icon name="alert" /></span><div><p>Needs review</p><strong>{overview.data.counts.review_required}</strong><small>Stale, at risk, or unknown</small></div></article></Link>
            <article><span className="metric-icon decisions"><Icon name="receipt" /></span><div><p>Decision receipts</p><strong>{overview.data.counts.receipts}</strong><small>In the configured index</small></div></article>
            <article><span className="metric-icon dependencies"><Icon name="link" /></span><div><p>Dependencies</p><strong>{overview.data.counts.dependencies}</strong><small>{overview.data.counts.unresolved_dependencies} unresolved</small></div></article>
            <article><span className="metric-icon campaigns"><Icon name="trend" /></span><div><p>Campaigns</p><strong>{overview.data.counts.campaigns}</strong><small>Persisted Action history</small></div></article>
          </section>
          <div className="overview-grid">
            <section className="app-panel">
              <div className="panel-heading"><div><p>Highest risk first</p><h2>Investigation queue</h2></div><Link href="/investigations">View all <span aria-hidden="true">→</span></Link></div>
              {decisions.data && decisions.data.decisions.length ? (
                <div className="record-list">
                  {[...decisions.data.decisions].sort(byRisk).slice(0, 5).map((decision) => (
                    <Link className="record-row" href={`/investigations/${encodeURIComponent(decision.receipt_id)}`} key={decision.receipt_id}>
                      <span className="record-mark">D</span>
                      <span className="record-main"><strong className="mono">{shortDigest(decision.receipt_id)}</strong><small>{decision.dependency_count} dependencies · {formatDate(decision.ended_at)}</small></span>
                      <StatusPill state={decision.state} /><span className="row-arrow">→</span>
                    </Link>
                  ))}
                </div>
              ) : <EmptyRecords title="No decision receipts yet" description="Receipts will appear after a connected agent run is admitted." />}
            </section>
            <section className="app-panel">
              <div className="panel-heading"><div><p>DataHub changes</p><h2>Latest campaigns</h2></div><Link href="/campaigns">View all <span>→</span></Link></div>
              {campaigns.data && campaigns.data.campaigns.length ? (
                <div className="compact-list">
                  {campaigns.data.campaigns.slice(0, 4).map((campaign) => (
                    <Link href={`/campaigns/${encodeURIComponent(campaign.campaign_id)}`} key={campaign.campaign_id}>
                      <span className="compact-symbol" aria-hidden="true" />
                      <span><strong title={compactChangeLabel(campaign.change.kind)}>{compactChangeLabel(campaign.change.kind)}</strong><small className="mono" title={compactUrn(campaign.change.entity_urn)}>{compactUrn(campaign.change.entity_urn)}</small></span>
                      <StatusPill state={campaign.processing.workflow_status} />
                    </Link>
                  ))}
                </div>
              ) : <EmptyRecords title="No campaigns recorded" description="Campaigns appear when the DataHub Action processes a metadata change." />}
            </section>
          </div>
        </>
      )}
    </>
  );
}
