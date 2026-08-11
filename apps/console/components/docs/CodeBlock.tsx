"use client";

import { useRef, useState, type ReactElement, type ReactNode } from "react";
import { Icon } from "./Icon";

type FenceChild = ReactElement<{ className?: string; title?: string }>;

/**
 * Wraps fenced code blocks (mapped from MDX `pre`) with a language label and a
 * copy button. Styled for both themes; no syntax tokenizing, so it stays
 * dependency-free and crisp.
 */
export default function CodeBlock({
  children,
  inGroup = false,
  ...props
}: {
  children?: ReactNode;
  /** Set by <CodeGroup>, whose tab already shows the title. */
  inGroup?: boolean;
} & React.HTMLAttributes<HTMLPreElement>) {
  const ref = useRef<HTMLPreElement>(null);
  const [copied, setCopied] = useState(false);

  const codeChild = children as FenceChild | undefined;
  const childClass = codeChild?.props?.className || "";
  const match = /language-([\w-]+)/.exec(childClass);
  const lang = match ? match[1] : "code";
  // A fence `title="…"` wins over the bare language in the header — except
  // inside a CodeGroup, where the tab is already showing it.
  const title = inGroup ? undefined : codeChild?.props?.title;

  const copy = async () => {
    const text = ref.current?.innerText ?? "";
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="group relative my-5 overflow-hidden rounded-xl border border-line bg-panel-soft">
      <div className="flex items-center justify-between border-b border-line px-4 py-2">
        <span
          className={
            title
              ? "text-[12px] font-medium text-muted"
              : "font-mono text-[11px] uppercase tracking-wider text-faint"
          }
        >
          {title ?? lang}
        </span>
        <button
          onClick={copy}
          className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-[12px] text-muted transition-colors hover:text-ink"
          aria-label="Copy code"
        >
          <Icon
            icon={copied ? "solar:check-read-linear" : "solar:copy-linear"}
            className="h-3.5 w-3.5"
          />
          {copied ? "Copied" : "Copy"}
        </button>
      </div>
      <pre
        ref={ref}
        {...props}
        className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed text-ink-soft"
      >
        {children}
      </pre>
    </div>
  );
}
