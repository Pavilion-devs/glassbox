import Link from "next/link";
import { ConnectionEmpty, EmptyRecords, PageHeader, StatusPill, byRisk, formatDate, formatUrn, needsReview, shortDigest } from "../../components/ui";
import { getDecisions } from "../../lib/forensics-api";

export default async function InvestigationsPage({ searchParams }: { searchParams: Promise<{ query?: string; show?: string }> }) {
  const { query = "", show } = await searchParams;
  const result = await getDecisions(query);
  const showAll = show === "all";

  // `/receipts` is the complete append-only index. This page is the work
  // queue, so it defaults to the states that actually need an operator.
  const all = result.data?.decisions ?? [];
  const review = all.filter((decision) => needsReview(decision.state));
  const shown = [...(showAll ? all : review)].sort(byRisk);
  const suffix = query ? `&query=${encodeURIComponent(query)}` : "";

  return (
    <>
      <PageHeader eyebrow="Work zone" title="Investigations" description="Decisions that require operator attention." />
      {result.data === null ? <ConnectionEmpty connection={result.connection} message={result.message} /> : (
        <section className="app-panel list-panel">
          <div className="list-toolbar">
            <form><span className="search-symbol" aria-hidden="true" /><input name="query" defaultValue={query} placeholder="Search receipt or DataHub URN" />{showAll && <input type="hidden" name="show" value="all" />}<button type="submit">Search</button></form>
            <div className="filter-group" role="group" aria-label="Filter decisions">
              <Link className={showAll ? "" : "active"} href={`/investigations?show=review${suffix}`}>Needs review <b>{review.length}</b></Link>
              <Link className={showAll ? "active" : ""} href={`/investigations?show=all${suffix}`}>All decisions <b>{all.length}</b></Link>
            </div>
          </div>
          {shown.length ? <div className="data-table decisions-table">
            <div className="table-head"><span>Decision receipt</span><span>State</span><span>Dependencies</span><span>Ended</span><span /></div>
            {shown.map((decision) => <Link className="table-row" href={`/investigations/${encodeURIComponent(decision.receipt_id)}`} key={decision.receipt_id}>
              <span className="table-primary"><b className="record-mark">D</b><span><strong className="mono">{shortDigest(decision.receipt_id)}</strong><small className="mono">{formatUrn(decision.document_urn)}</small></span></span>
              <StatusPill state={decision.state} />
              <span><strong>{decision.resolved_dependency_count}/{decision.dependency_count}</strong><small>{decision.field_lineage_coverage.toLowerCase()} field coverage</small></span>
              <span><strong>{formatDate(decision.ended_at)}</strong></span><span className="row-arrow" aria-hidden="true">→</span>
            </Link>)}
          </div> : <EmptyRecords
            title={showAll ? "No matching decisions" : "Nothing needs review"}
            description={showAll
              ? "Try another receipt ID or DataHub URN."
              : `No decision is stale, at risk, or unknown. ${all.length} verified ${all.length === 1 ? "decision is" : "decisions are"} in the index.`}
          />}
        </section>
      )}
    </>
  );
}
