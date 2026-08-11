import type { NextRequest } from "next/server";
import { NextResponse } from "next/server";

/**
 * One build, two faces.
 *
 * Next 16 renamed the middleware entry point to `proxy.ts`; vinext honours the
 * old filename but warns, and does not run it.
 *
 * GlassBox ships self-hosted and organization-owned (ADR-0027), so the console
 * is the default at `/`: a customer running this inside their own network gets
 * the operator surface with no configuration, and never serves our marketing
 * page from their cluster.
 *
 * Marketing mode is opt-in per host. Set `GLASSBOX_PUBLIC_HOSTS` to a
 * comma-separated list on the public deployment only:
 *
 *     GLASSBOX_PUBLIC_HOSTS=glassbox.dev,www.glassbox.dev
 *
 * On those hosts `/` renders the landing page and the operator routes are not
 * served, because there is no evidence plane behind them.
 */
const OPERATOR_ROUTES = [
  "/investigations",
  "/receipts",
  "/campaigns",
  "/recovery",
  "/trust",
  "/settings",
];

function publicHosts(): string[] {
  return (process.env.GLASSBOX_PUBLIC_HOSTS ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

export function proxy(request: NextRequest) {
  const hosts = publicHosts();
  if (hosts.length === 0) return NextResponse.next();

  const host = request.headers.get("host")?.split(":")[0].toLowerCase();
  if (!host || !hosts.includes(host)) return NextResponse.next();

  const { pathname } = request.nextUrl;

  // `/home` is an implementation detail of the rewrite. Keep it out of the
  // public URL space so the landing page has exactly one address.
  if (pathname === "/home") {
    return NextResponse.redirect(new URL("/", request.url));
  }

  if (pathname === "/") {
    const landing = request.nextUrl.clone();
    landing.pathname = "/home";
    return NextResponse.rewrite(landing);
  }

  if (OPERATOR_ROUTES.some((route) => pathname === route || pathname.startsWith(`${route}/`))) {
    return NextResponse.redirect(new URL("/", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.svg|fonts/|media/).*)"],
};
