"use client";

import {
  Children,
  cloneElement,
  isValidElement,
  useState,
  type ReactElement,
  type ReactNode,
} from "react";

type FenceProps = {
  title?: string;
  className?: string;
  children?: ReactElement<{ className?: string; title?: string }>;
  inGroup?: boolean;
};

/**
 * Tabbed set of code blocks. Each child is one fenced block; its tab label
 * comes from the `title` prop set on the fence (```bash title="stdio").
 * Falls back to the language, then to a positional label.
 */
export default function CodeGroup({ children }: { children: ReactNode }) {
  const blocks = Children.toArray(children).filter(isValidElement) as ReactElement<FenceProps>[];
  const [active, setActive] = useState(0);

  if (blocks.length === 0) return null;

  const labelFor = (block: ReactElement<FenceProps>, i: number): string => {
    const codeChild = block.props?.children;
    // `title` lands on the inner <code>, because that is the element
    // mdast-util-to-hast applies fence hProperties to.
    const title = block.props?.title ?? codeChild?.props?.title;
    if (typeof title === "string" && title) return title;
    const cls = codeChild?.props?.className ?? "";
    const m = /language-([\w-]+)/.exec(cls);
    return m ? m[1] : `Option ${i + 1}`;
  };

  return (
    <div className="my-5 overflow-hidden rounded-xl border border-line">
      <div className="flex gap-1 overflow-x-auto border-b border-line bg-panel-soft px-2 py-1.5">
        {blocks.map((b, i) => (
          <button
            key={i}
            onClick={() => setActive(i)}
            className={`shrink-0 rounded-md px-3 py-1 text-[12.5px] font-medium transition-colors ${
              i === active
                ? "bg-panel text-ink shadow-sm"
                : "text-muted hover:text-ink"
            }`}
          >
            {labelFor(b, i)}
          </button>
        ))}
      </div>
      {/* Strip the child's own border/rounding so it sits flush inside the frame. */}
      <div className="[&>div]:my-0 [&>div]:rounded-none [&>div]:border-0 [&>div>div]:border-t-0">
        {cloneElement(blocks[active], { inGroup: true })}
      </div>
    </div>
  );
}
