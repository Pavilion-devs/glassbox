import type { MDXComponents } from "mdx/types";
import Link from "next/link";
import CodeBlock from "@/components/docs/CodeBlock";
import CodeGroup from "@/components/docs/CodeGroup";
import Callout from "@/components/docs/Callout";
import { Card, CardGroup } from "@/components/docs/Card";
import { Steps, Step } from "@/components/docs/Steps";
import ArchitectureDiagram from "@/components/docs/ArchitectureDiagram";

const linkClass =
  "font-medium text-accent underline decoration-accent/30 underline-offset-2 transition-colors hover:decoration-accent";

export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    h1: (p) => (
      <h1 className="scroll-mt-24 text-3xl font-semibold tracking-tight text-ink md:text-[34px]" {...p} />
    ),
    h2: (p) => (
      <h2
        className="scroll-mt-24 mb-4 mt-12 border-t border-line pt-8 text-[22px] font-semibold tracking-tight text-ink"
        {...p}
      />
    ),
    h3: (p) => (
      <h3 className="scroll-mt-24 mb-3 mt-8 text-lg font-semibold tracking-tight text-ink" {...p} />
    ),
    p: (p) => <p className="my-4 text-[15px] leading-7 text-muted" {...p} />,
    a: ({ href = "", ...p }) => {
      const internal = href.startsWith("/") || href.startsWith("#");
      return internal ? (
        <Link href={href} className={linkClass} {...p} />
      ) : (
        <a href={href} target="_blank" rel="noreferrer" className={linkClass} {...p} />
      );
    },
    ul: (p) => (
      <ul
        className="my-4 list-disc space-y-2 pl-5 text-[15px] leading-7 text-muted marker:text-faint"
        {...p}
      />
    ),
    ol: (p) => (
      <ol
        className="my-4 list-decimal space-y-2 pl-5 text-[15px] leading-7 text-muted marker:text-faint"
        {...p}
      />
    ),
    li: (p) => <li className="pl-1.5 [&>p]:my-0 [&>ul]:my-2 [&>ol]:my-2" {...p} />,
    strong: (p) => <strong className="font-semibold text-ink" {...p} />,
    hr: (p) => <hr className="my-10 border-line" {...p} />,
    blockquote: (p) => (
      <blockquote className="my-5 border-l-2 border-accent/40 pl-4 italic text-muted" {...p} />
    ),
    table: (p) => (
      <div className="my-6 overflow-x-auto">
        <table className="w-full text-left text-sm" {...p} />
      </div>
    ),
    thead: (p) => <thead className="border-b border-line-strong" {...p} />,
    th: (p) => <th className="px-3 py-2 font-semibold text-ink" {...p} />,
    td: (p) => <td className="border-b border-line px-3 py-2 align-top text-muted" {...p} />,
    pre: (p) => <CodeBlock {...p} />,
    code: ({ className, ...p }: { className?: string }) =>
      className?.includes("language-") ? (
        <code className={className} {...p} />
      ) : (
        <code
          className="rounded-md border border-line bg-panel-soft px-1.5 py-0.5 font-mono text-[13px] text-accent"
          {...p}
        />
      ),
    // Custom components available inside MDX:
    Eyebrow: (p: React.HTMLAttributes<HTMLParagraphElement>) => (
      <p className="mb-2 text-[12px] font-semibold uppercase tracking-wider text-accent" {...p} />
    ),
    // A block element, not a <p>: MDX parses multi-line children as a paragraph,
    // and a <p> inside a <p> is invalid HTML that the browser reparents, which
    // shows up as a hydration mismatch. The child overrides keep the lede
    // typography whether the source is written inline or across lines.
    Lede: (p: React.HTMLAttributes<HTMLDivElement>) => (
      <div
        className="mb-8 mt-3 text-[17px] leading-8 text-muted [&>p]:m-0 [&>p]:text-[17px] [&>p]:leading-8"
        {...p}
      />
    ),
    Callout,
    Card,
    CardGroup,
    Steps,
    Step,
    CodeGroup,
    ArchitectureDiagram,
    ...components,
  };
}
