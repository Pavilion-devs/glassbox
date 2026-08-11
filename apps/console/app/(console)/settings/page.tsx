import { PageHeader, StatusPill } from "../../components/ui";
import { configuredApiUrl, getConnectionState } from "../../lib/forensics-api";
import { getControlSnapshot } from "../../lib/control-api";
import { ConnectionCenter } from "./connection-center";

export default async function SettingsPage() {
  const [connection, control] = await Promise.all([getConnectionState(), getControlSnapshot()]);
  const endpoint = configuredApiUrl();
  return <>
    <PageHeader eyebrow="System" title="Connections" description="Connect DataHub and issue scoped credentials without exposing service secrets to the browser." />
    <ConnectionCenter snapshot={control} />
    <section className="app-panel evidence-service-strip"><div className="settings-service-mark">G</div><div><p>GlassBox evidence plane</p><h2>{connection === "connected" ? "Connected" : "Unavailable"}</h2></div><StatusPill state={connection === "connected" ? "AVAILABLE" : "OFFLINE"} /><dl><div><dt>Endpoint</dt><dd><code>{endpoint ? "Private service network" : "Not configured"}</code></dd></div><div><dt>Policy</dt><dd>Read only · raw free</dd></div></dl></section>
  </>;
}
