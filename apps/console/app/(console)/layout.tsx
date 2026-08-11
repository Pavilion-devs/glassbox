import { ConsoleShell } from "../components/console-shell";
import { getConnectionState } from "../lib/forensics-api";
import { getDataHubUiOrigin } from "../lib/control-api";

// Operator routes depend on authenticated request headers and runtime service
// configuration. Rendering this route group at build time would freeze an
// anonymous, unconfigured snapshot into the production image.
export const dynamic = "force-dynamic";

/**
 * Wraps every operator route in the console shell. Scoped to this route group
 * so `/docs` and `/architecture` render without the sidebar and topbar.
 */
export default async function ConsoleLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  const [connection, datahubUiOrigin] = await Promise.all([
    getConnectionState(),
    getDataHubUiOrigin(),
  ]);
  return (
    <ConsoleShell connection={connection} datahubUiOrigin={datahubUiOrigin}>
      {children}
    </ConsoleShell>
  );
}
