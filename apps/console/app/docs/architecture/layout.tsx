import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Architecture",
  description:
    "The GlassBox evidence plane, control plane, and transactional state authority.",
};

export default function ArchitectureDocsLayout({ children }: { children: React.ReactNode }) {
  return children;
}
