import type { Metadata } from "next";
import DocsTopbar from "@/components/docs/DocsTopbar";
import DocsSidebar from "@/components/docs/DocsSidebar";
import Toc from "@/components/docs/Toc";
import PrevNext from "@/components/docs/PrevNext";

export const metadata: Metadata = {
  title: { default: "GlassBox Docs", template: "%s · GlassBox Docs" },
  description:
    "Documentation for GlassBox — signed agent-decision evidence, deterministic invalidation, and governed recovery over DataHub.",
};

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-canvas text-ink">
      <DocsTopbar />
      <div className="mx-auto flex w-full max-w-[1600px]">
        <DocsSidebar />
        <main className="min-w-0 flex-1 px-6 py-10 lg:px-12">
          <article id="doc-article" className="mx-auto max-w-3xl">
            {children}
            <PrevNext />
          </article>
        </main>
        <Toc />
      </div>
    </div>
  );
}
