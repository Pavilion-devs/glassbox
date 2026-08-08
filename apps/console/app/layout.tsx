import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "GlassBox Forensics — Agent Decision Evidence",
  description:
    "Investigate signed AI-agent decisions, causal evidence, stale impact, and safe replay through DataHub.",
  icons: {
    icon: "/favicon.svg",
  },
  openGraph: {
    type: "website",
    title: "GlassBox Forensics — Agent Decision Evidence",
    description:
      "Signed agent-decision evidence, causal impact analysis, and governed replay through DataHub.",
    images: [
      {
        url: "/og.png",
        width: 1200,
        height: 630,
        alt: "GlassBox agent decision forensics evidence chain",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "GlassBox Forensics",
    description: "Know when an AI-agent decision is still safe to trust.",
    images: ["/og.png"],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
