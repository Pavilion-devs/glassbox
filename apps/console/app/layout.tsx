import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://glassboxhq.xyz"),
  title: "GlassBox Forensics — Decision Control Center",
  description:
    "Investigate signed AI-agent decisions, causal evidence, stale impact, and safe replay through DataHub.",
  icons: {
    icon: "/favicon.svg",
  },
  openGraph: {
    type: "website",
    url: "https://glassboxhq.xyz",
    siteName: "GlassBox",
    title: "GlassBox Forensics — Agent Decision Evidence",
    description:
      "Signed agent-decision evidence, causal impact analysis, and governed replay through DataHub.",
    images: [{ url: "/og.png", width: 1200, height: 630, alt: "GlassBox" }],
  },
  twitter: {
    card: "summary_large_image",
    title: "GlassBox Forensics",
    description: "Know when an AI-agent decision is still safe to trust.",
    images: ["/og.png"],
  },
};

// Runs before first paint so a stored dark preference does not flash light.
// Light is the default, so an absent or unreadable value needs no attribute.
const THEME_INIT = `try{if(localStorage.getItem("gbx-theme")==="dark"){document.documentElement.dataset.theme="dark"}}catch(e){}`;

/**
 * Root layout owns only the document, the theme attribute, and global CSS.
 *
 * The operator console shell lives in the `(console)` route group so that the
 * documentation routes, which bring their own topbar and sidebar, are not
 * wrapped in it.
 */
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_INIT }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
