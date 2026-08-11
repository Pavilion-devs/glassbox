import Link from "next/link";
import { ConnectionEmpty, DateValue, EmptyRecords, PageHeader, StatusPill, formatUrn, shortDigest } from "../../components/ui";
import { getDecisions } from "../../lib/forensics-api";

export default async function ReceiptsPage() {
  const result = await getDecisions();
  return <>
    <PageHeader eyebrow="Evidence" title="Receipts" description="Signed, append-only decision records." />
    {result.data === null ? <ConnectionEmpty connection={result.connection} message={result.message} /> : (
      <section className="app-panel list-panel">
        <div className="list-toolbar"><div><strong>Receipt index</strong><span>Raw content is never returned</span></div><span>{result.data.total} receipts</span></div>
        {result.data.decisions.length ? <div className="receipt-grid">
          {result.data.decisions.map((receipt) => <Link href={`/investigations/${encodeURIComponent(receipt.receipt_id)}`} key={receipt.receipt_id}>
            <div className="receipt-card-top"><span className="record-mark">R</span><StatusPill state={receipt.state} /></div>
            <strong className="mono">{shortDigest(receipt.receipt_id)}</strong><code>{formatUrn(receipt.document_urn)}</code>
            <dl><div><dt>Dependencies</dt><dd>{receipt.dependency_count}</dd></div><div><dt>Resolved</dt><dd>{receipt.resolved_dependency_count}</dd></div><div className="receipt-date"><dt>Ended</dt><dd><DateValue value={receipt.ended_at} /></dd></div></dl>
          </Link>)}
        </div> : <EmptyRecords title="No receipts admitted" description="Instrumented agent runs will appear here after verification." />}
      </section>
    )}
  </>;
}
