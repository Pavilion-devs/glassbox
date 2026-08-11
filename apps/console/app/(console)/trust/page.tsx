import { ConnectionEmpty, Icon, PageHeader, StatusPill } from "../../components/ui";
import { getOverview } from "../../lib/forensics-api";

export default async function TrustPage() {
  const result = await getOverview();
  return <>
    <PageHeader eyebrow="System" title="Trust & privacy" description="What the connected console can prove—and what it deliberately withholds." />
    {result.data === null ? <ConnectionEmpty connection={result.connection} message={result.message} /> : (
      <div className="trust-grid">
        <section className="app-panel trust-overview"><div className="trust-emblem" aria-hidden="true"><Icon name="shield" /></div><p>Evidence boundary</p><h2>Raw-free operator surface</h2><span>The console receives receipt projections, deterministic findings, and verified processing state. It does not receive prompts, outputs, tool bodies, credentials, or signing keys.</span></section>
        <section className="app-panel trust-list"><div><span>Receipt index</span><StatusPill state={result.data.availability.receipt_index} /></div><div><span>Campaign store</span><StatusPill state={result.data.availability.campaign_store} /></div><div><span>Unresolved dependencies</span><strong>{result.data.counts.unresolved_dependencies}</strong></div><div><span>Raw content returned</span><strong>Never</strong></div></section>
      </div>
    )}
  </>;
}
