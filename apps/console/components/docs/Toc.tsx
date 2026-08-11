"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";

type Heading = { id: string; text: string; level: number };

/** Builds the "On this page" rail from the rendered article headings. */
export default function Toc() {
  const pathname = usePathname();
  const [items, setItems] = useState<Heading[]>([]);
  const [active, setActive] = useState("");

  useEffect(() => {
    let observer: IntersectionObserver | undefined;
    const frame = requestAnimationFrame(() => {
      const article = document.getElementById("doc-article");
      if (!article) return;
      const els = Array.from(article.querySelectorAll("h2, h3")).filter(
        (e) => (e as HTMLElement).id,
      ) as HTMLElement[];
      setItems(
        els.map((e) => ({
          id: e.id,
          text: e.innerText,
          level: e.tagName === "H3" ? 3 : 2,
        })),
      );

      observer = new IntersectionObserver(
        (entries) => {
          entries.forEach((entry) => {
            if (entry.isIntersecting) setActive((entry.target as HTMLElement).id);
          });
        },
        { rootMargin: "-80px 0px -70% 0px" },
      );
      els.forEach((element) => observer?.observe(element));
    });
    return () => {
      cancelAnimationFrame(frame);
      observer?.disconnect();
    };
    // Re-scan on navigation: the article subtree is replaced, not remounted.
  }, [pathname]);

  if (items.length === 0) return null;

  return (
    <aside className="sticky top-16 hidden h-[calc(100vh-4rem)] w-56 shrink-0 overflow-y-auto py-10 pr-6 xl:block">
      <p className="mb-3 text-[11px] font-semibold uppercase tracking-wider text-faint">
        On this page
      </p>
      <ul className="space-y-1.5">
        {items.map((h) => (
          <li key={h.id} className={h.level === 3 ? "ml-3" : ""}>
            <a
              href={`#${h.id}`}
              className={`block border-l-2 pl-3 text-[13px] leading-snug transition-colors ${
                active === h.id
                  ? "border-accent text-accent"
                  : "border-transparent text-muted hover:text-ink"
              }`}
            >
              {h.text}
            </a>
          </li>
        ))}
      </ul>
    </aside>
  );
}
