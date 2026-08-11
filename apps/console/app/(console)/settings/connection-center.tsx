"use client";

import { FormEvent, useState, useTransition } from "react";
import type {
  ConnectionProof,
  ControlSnapshot,
  DataHubConnectionSummary,
  IngestionKeySummary,
} from "../../lib/control-api";
import { DateValue, StatusPill } from "../../components/ui";

type Notice = { tone: "success" | "error" | "neutral"; text: string } | null;

export function ConnectionCenter({ snapshot }: { snapshot: ControlSnapshot }) {
  const [tab, setTab] = useState<"datahub" | "agents">("datahub");
  const [connection, setConnection] = useState(snapshot.connection);
  const [keys, setKeys] = useState(snapshot.keys);
  const [report, setReport] = useState<ConnectionProof | null>(null);
  const [oneTimeSecret, setOneTimeSecret] = useState<string | null>(null);
  const [notice, setNotice] = useState<Notice>(
    snapshot.message ? { tone: "neutral", text: snapshot.message } : null,
  );
  const [pending, startTransition] = useTransition();
  const canManage = snapshot.role === "admin";

  async function connectionAction(form: HTMLFormElement, persist: boolean) {
    const values = new FormData(form);
    const payload = {
      server_url: String(values.get("server_url") ?? ""),
      ui_url: String(values.get("ui_url") ?? ""),
      token: String(values.get("token") ?? ""),
      write_proof: values.get("write_proof") === "on",
    };
    setNotice(null);
    startTransition(async () => {
      const response = await fetch(`/api/control/${persist ? "connection" : "connection/test"}`, {
        method: persist ? "PUT" : "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(payload),
      });
      const body = await response.json();
      if (!response.ok) {
        setNotice({ tone: "error", text: errorMessage(body) });
        return;
      }
      const nextReport = (body.report ?? body.connection?.probe) as ConnectionProof;
      setReport(nextReport);
      if (persist) {
        setConnection(body.connection as DataHubConnectionSummary);
        form.reset();
        setNotice({
          tone: "success",
          text: "DataHub is verified and encrypted. Runtime services can now reload this connection.",
        });
      } else {
        setNotice({ tone: "success", text: "The live DataHub verification completed." });
      }
    });
  }

  async function createKey(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = String(new FormData(form).get("name") ?? "");
    setNotice(null);
    startTransition(async () => {
      const response = await fetch("/api/control/ingestion-keys", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ name }),
      });
      const body = await response.json();
      if (!response.ok) {
        setNotice({ tone: "error", text: errorMessage(body) });
        return;
      }
      setKeys((current) => [body.key as IngestionKeySummary, ...current]);
      setOneTimeSecret(body.secret as string);
      setNotice({ tone: "success", text: "Ingestion key created. Copy it now; it is shown once." });
      form.reset();
    });
  }

  function revokeKey(keyId: string) {
    setNotice(null);
    startTransition(async () => {
      const response = await fetch(`/api/control/ingestion-keys/${keyId}`, { method: "DELETE" });
      const body = await response.json();
      if (!response.ok) {
        setNotice({ tone: "error", text: errorMessage(body) });
        return;
      }
      setKeys((current) => current.map((key) =>
        key.key_id === keyId ? { ...key, state: "REVOKED" as const } : key,
      ));
      setNotice({ tone: "success", text: "The ingestion key is revoked." });
    });
  }

  return (
    <section className="connection-center">
      <div className="connection-tabs" role="tablist" aria-label="Connection settings">
        <button className={tab === "datahub" ? "active" : ""} role="tab" aria-selected={tab === "datahub"} onClick={() => setTab("datahub")}>DataHub</button>
        <button className={tab === "agents" ? "active" : ""} role="tab" aria-selected={tab === "agents"} onClick={() => setTab("agents")}>Agent keys <span>{keys.filter((key) => key.state === "ACTIVE").length}</span></button>
      </div>

      {notice && <div className={`control-notice ${notice.tone}`} role="status">{notice.text}</div>}

      {tab === "datahub" ? <div className="connection-layout">
        <section className="app-panel connection-form-card">
          <div className="connection-card-heading"><div><p>Organization connection</p><h2>{connection ? "Update DataHub" : "Connect DataHub"}</h2></div>{connection && <StatusPill state="VERIFIED" />}</div>
          <p className="connection-intro">Use a scoped DataHub service account. The token travels to the private control plane, is verified against DataHub, and is stored encrypted.</p>
          <form onSubmit={(event) => { event.preventDefault(); void connectionAction(event.currentTarget, true); }}>
            <label><span>GMS URL</span><input name="server_url" type="url" required placeholder="https://datahub-gms.example.com" defaultValue={connection?.server_url ?? ""} disabled={!canManage || pending} /></label>
            <label><span>DataHub UI URL</span><input name="ui_url" type="url" placeholder="https://datahub.example.com" defaultValue={connection?.ui_url ?? ""} disabled={!canManage || pending} /></label>
            <label><span>Service-account token</span><input name="token" type="password" required autoComplete="new-password" placeholder={connection ? "Enter a new token to replace the connection" : "Paste token"} disabled={!canManage || pending} /></label>
            <label className="proof-consent"><input name="write_proof" type="checkbox" defaultChecked disabled={!canManage || pending} /><span><strong>Prove write permission</strong><small>Upsert and read back one deterministic synthetic Document.</small></span></label>
            <div className="connection-actions"><button className="secondary-action" type="button" disabled={!canManage || pending} onClick={(event) => { if (event.currentTarget.form) void connectionAction(event.currentTarget.form, false); }}>Test only</button><button className="primary-action" type="submit" disabled={!canManage || pending}>{pending ? "Verifying…" : "Verify & save"}</button></div>
          </form>
        </section>
        <ConnectionProofCard connection={connection} report={report} />
      </div> : <div className="agent-key-layout">
        <section className="app-panel key-create-card"><p>Agent authentication</p><h2>Create an ingestion key</h2><span>Give each agent or environment its own key. GlassBox stores only a keyed digest, and the receiver checks revocation on every request.</span><form onSubmit={createKey}><label><span>Key name</span><input name="name" required minLength={2} maxLength={80} placeholder="Production pricing agent" disabled={!canManage || pending} /></label><button className="primary-action" type="submit" disabled={!canManage || pending}>{pending ? "Working…" : "Create key"}</button></form></section>
        {oneTimeSecret && <section className="one-time-secret"><div><p>Copy this key now</p><code>{oneTimeSecret}</code><span>It cannot be recovered after you leave this page.</span></div><button type="button" onClick={() => navigator.clipboard.writeText(oneTimeSecret)}>Copy key</button></section>}
        <section className="app-panel key-list-card"><div className="key-list-head"><div><p>Issued credentials</p><h2>Ingestion keys</h2></div><span>{keys.filter((key) => key.state === "ACTIVE").length} active</span></div>{keys.length ? <div className="key-list">{keys.map((key) => <article key={key.key_id}><span className="key-glyph" aria-hidden="true" /><div><strong>{key.name}</strong><code>{key.display_prefix}••••••••</code><small>Created <DateValue value={key.created_at} /> by {key.created_by}</small></div><StatusPill state={key.state} />{key.state === "ACTIVE" && <button type="button" disabled={pending} onClick={() => revokeKey(key.key_id)}>Revoke</button>}</article>)}</div> : <div className="inline-empty">No ingestion keys have been issued.</div>}</section>
      </div>}
    </section>
  );
}

function ConnectionProofCard({ connection, report }: { connection: DataHubConnectionSummary | null; report: ConnectionProof | null }) {
  const proof = report ?? connection?.probe ?? null;
  return <aside className="app-panel proof-card"><div><p>Live verification</p><h2>Connection proof</h2></div>{proof ? <dl><ProofRow label="Connection" value={proof.connection} /><ProofRow label="Authentication" value={proof.authentication} /><ProofRow label="SDK compatibility" value={proof.sdk_compatibility} /><ProofRow label="Write + readback" value={proof.write_proof} /><div><dt>SDK</dt><dd className="mono">{proof.sdk_version}</dd></div>{proof.server_version && <div><dt>DataHub</dt><dd className="mono">{proof.server_version}</dd></div>}</dl> : <div className="proof-empty"><span aria-hidden="true" /><p>No live proof yet</p><small>Test the connection to establish reachability, authentication, compatibility, and permission.</small></div>}{connection && <footer><span>Credential encrypted</span><small>Verified <DateValue value={connection.verified_at} /></small></footer>}</aside>;
}

function ProofRow({ label, value }: { label: string; value: string }) {
  return <div><dt>{label}</dt><dd><StatusPill state={value} /></dd></div>;
}

function errorMessage(body: unknown) {
  if (body && typeof body === "object") {
    const error = (body as { error?: unknown }).error;
    if (error && typeof error === "object") {
      const message = (error as { message?: unknown }).message;
      if (typeof message === "string") return message;
    }
  }
  return "The operation did not complete.";
}
