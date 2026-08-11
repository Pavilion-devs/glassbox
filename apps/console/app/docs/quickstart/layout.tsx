import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Quickstart",
  description:
    "Run GlassBox against a live, pinned DataHub estate and verify the complete causal chain.",
};

export default function QuickstartDocsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
