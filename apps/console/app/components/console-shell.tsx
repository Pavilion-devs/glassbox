"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { createContext, FormEvent, ReactNode, useContext, useState, useSyncExternalStore, useTransition } from "react";
import { Icon, type IconName } from "./ui";
import type { ConnectionState } from "../lib/forensics-api";

const primary: ReadonlyArray<{ href: string; label: string; icon: IconName }> = [
  { href: "/", label: "Overview", icon: "grid" },
  { href: "/investigations", label: "Investigations", icon: "search" },
  { href: "/receipts", label: "Receipts", icon: "receipt" },
  { href: "/campaigns", label: "Campaigns", icon: "pulse" },
  { href: "/recovery", label: "Recovery", icon: "replay" },
];

const system: ReadonlyArray<{ href: string; label: string; icon: IconName }> = [
  { href: "/trust", label: "Trust & privacy", icon: "shield" },
  { href: "/settings", label: "Connections", icon: "settings" },
];

const EXACT_RECEIPT_ID = /^gbx:receipt:sha256:[0-9a-f]{64}$/i;
const DataHubUiContext = createContext<string | null>(null);

/*
 * The theme lives on <html>, written by the pre-paint script in the layout
 * before React exists. Reading it through an external store keeps the server
 * snapshot at the light default while the client reads the real attribute, so
 * a stored dark preference resolves without a hydration mismatch.
 */
const themeListeners = new Set<() => void>();

function subscribeTheme(onChange: () => void) {
  themeListeners.add(onChange);
  return () => void themeListeners.delete(onChange);
}

function readTheme(): "light" | "dark" {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

function applyTheme(next: "light" | "dark") {
  if (next === "dark") document.documentElement.dataset.theme = "dark";
  else delete document.documentElement.dataset.theme;
  try {
    localStorage.setItem("gbx-theme", next);
  } catch {
    // A blocked storage backend still gets the toggle for this session.
  }
  themeListeners.forEach((notify) => notify());
}

export function ConsoleShell({
  connection,
  datahubUiOrigin,
  children,
}: {
  connection: ConnectionState;
  datahubUiOrigin: string | null;
  children: ReactNode;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const [menuOpen, setMenuOpen] = useState(false);
  const [lookup, setLookup] = useState("");
  const [refreshing, startRefresh] = useTransition();
  const theme = useSyncExternalStore(subscribeTheme, readTheme, () => "light" as const);

  function active(href: string) {
    return href === "/" ? pathname === "/" : pathname.startsWith(href);
  }

  // Exact receipt IDs open directly. Partial IDs and URNs use the filterable
  // list so an inexact operator search never turns into a detail-page 404.
  function navigateLookup(rawTerm: string) {
    const term = rawTerm.trim();
    if (!term) return;
    setLookup("");
    router.push(
      EXACT_RECEIPT_ID.test(term)
        ? `/investigations/${encodeURIComponent(term)}`
        : `/investigations?show=all&query=${encodeURIComponent(term)}`,
    );
  }

  function submitLookup(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Read the submitted DOM value instead of relying on the latest React
    // render. This keeps rapid type-then-Enter lookup deterministic.
    navigateLookup(String(new FormData(event.currentTarget).get("lookup") ?? ""));
  }

  function toggleTheme() {
    applyTheme(theme === "dark" ? "light" : "dark");
  }

  return <DataHubUiContext.Provider value={datahubUiOrigin}>
    <div className="app-shell">
      <aside className={`app-sidebar ${menuOpen ? "open" : ""}`}>
        <Link className="app-brand" href="/" onClick={() => setMenuOpen(false)}>
          <span className="app-mark" aria-hidden="true"><i /><i /></span>
          <span><strong>GlassBox</strong><small>Forensics</small></span>
        </Link>
        <nav aria-label="GlassBox navigation">
          <p>Workspace</p>
          {primary.map((item) => (
            <Link
              className={`app-nav-link ${active(item.href) ? "active" : ""}`}
              href={item.href}
              key={item.href}
              onClick={() => setMenuOpen(false)}
            >
              <span className="app-nav-icon"><Icon name={item.icon} /></span>
              {item.label}
            </Link>
          ))}
          <p className="system-label">System</p>
          {system.map((item) => (
            <Link
              className={`app-nav-link ${active(item.href) ? "active" : ""}`}
              href={item.href}
              key={item.href}
              onClick={() => setMenuOpen(false)}
            >
              <span className="app-nav-icon"><Icon name={item.icon} /></span>
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="sidebar-status">
          <span className={`connection-dot ${connection}`} aria-hidden="true" />
          <div><strong>{connection === "connected" ? "Evidence plane online" : "Evidence plane offline"}</strong><small>DataHub + GlassBox</small></div>
        </div>
      </aside>

      <div className="app-workspace">
        <header className="app-topbar">
          <button
            className="menu-trigger"
            type="button"
            aria-label="Toggle navigation"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((current) => !current)}
          ><span /><span /></button>
          <form className="global-search" onSubmit={submitLookup}>
            <span className="search-symbol"><Icon name="search" /></span>
            <input
              aria-label="Search receipts and DataHub URNs"
              name="lookup"
              placeholder="Search receipts and URNs"
              value={lookup}
              onChange={(event) => setLookup(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault();
                  navigateLookup(event.currentTarget.value);
                }
              }}
            />
            <button
              className="global-search-submit"
              type="submit"
              aria-label="Search receipts and DataHub URNs"
            ><kbd aria-hidden="true">↵</kbd></button>
          </form>
          <div className="topbar-actions">
            {datahubUiOrigin && <a className="datahub-link" href={datahubUiOrigin} target="_blank" rel="noreferrer"><Icon name="link" />DataHub</a>}
            <Link className="rawfree-badge" href="/trust"><Icon name="shield" />Raw-free</Link>
            <button
              className="refresh-button"
              type="button"
              onClick={() => startRefresh(() => router.refresh())}
              disabled={refreshing}
            >
              <Icon name="refresh" />{refreshing ? "Refreshing…" : "Refresh"}
            </button>
            <button
              className="theme-toggle"
              type="button"
              onClick={toggleTheme}
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
              aria-pressed={theme === "dark"}
            >
              <Icon name={theme === "dark" ? "sun" : "moon"} />
            </button>
          </div>
        </header>
        <div className="app-page">{children}</div>
      </div>
      {menuOpen && <button className="sidebar-scrim" aria-label="Close navigation" onClick={() => setMenuOpen(false)} />}
    </div>
  </DataHubUiContext.Provider>;
}

export function DataHubEntityLink({ urn, label = "Open in DataHub" }: { urn: string; label?: string }) {
  const origin = useContext(DataHubUiContext);
  if (!origin) return null;
  const linkedUrn = schemaFieldDatasetUrn(urn) ?? urn;
  const entityType = linkedUrn.split(":", 4)[2];
  if (!entityType) return null;
  return <a className="datahub-entity-link" href={`${origin}/${entityType}/${encodeURIComponent(linkedUrn)}`} target="_blank" rel="noreferrer"><Icon name="link" />{label}</a>;
}

function schemaFieldDatasetUrn(urn: string) {
  if (!urn.startsWith("urn:li:schemaField:(urn:li:dataset:")) return null;
  const closing = urn.lastIndexOf("),");
  return closing > 0 ? urn.slice("urn:li:schemaField:(".length, closing + 1) : null;
}
