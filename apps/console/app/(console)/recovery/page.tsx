import Link from "next/link";
import { ConnectionEmpty, EmptyRecords, PageHeader, StatusPill, formatUrn, humanize } from "../../components/ui";
import { getCampaigns } from "../../lib/forensics-api";

export default async function RecoveryPage() {
  const result = await getCampaigns();
  const recoverable = result.data?.campaigns.filter((campaign) => campaign.assessments.some((item) => item.quarantine_required)) ?? [];
  return <>
    <PageHeader eyebrow="Controlled execution" title="Recovery" description="Quarantined decisions eligible for a separate recovery workflow." />
    {result.data === null ? <ConnectionEmpty connection={result.connection} message={result.message} /> : recoverable.length ? (
      <section className="recovery-board">
        {recoverable.map((campaign) => <article className="recovery-item" key={campaign.campaign_id}>
          <div className="recovery-item-head"><span className="record-mark campaign">R</span><div><p>{humanize(campaign.change.kind)}</p><strong className="mono">{formatUrn(campaign.change.entity_urn)}</strong></div><StatusPill state="AWAITING_AUTHORIZATION" /></div>
          <div className="recovery-lane"><span><i>1</i><b>Impact classified</b></span><em /><span><i>2</i><b>Decision quarantined</b></span><em /><span className="pending"><i>3</i><b>Recovery authorization</b></span></div>
          <footer><span>Awaiting authorization · {campaign.assessments.filter((item) => item.quarantine_required).length} decision{campaign.assessments.filter((item) => item.quarantine_required).length === 1 ? "" : "s"}</span><Link href={`/campaigns/${encodeURIComponent(campaign.campaign_id)}`}>Review campaign <span>→</span></Link></footer>
        </article>)}
      </section>
    ) : <EmptyRecords title="Nothing is waiting for recovery" description="Quarantined decisions will appear here after a material change." />}
  </>;
}
