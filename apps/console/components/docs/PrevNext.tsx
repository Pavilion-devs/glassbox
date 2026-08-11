"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { Icon } from "./Icon";
import { flatDocs } from "@/lib/docs-nav";

export default function PrevNext() {
  const pathname = usePathname();
  const idx = flatDocs.findIndex((d) => d.slug === pathname);
  if (idx === -1) return null;
  const prev = idx > 0 ? flatDocs[idx - 1] : null;
  const next = idx < flatDocs.length - 1 ? flatDocs[idx + 1] : null;

  return (
    <nav className="mt-16 grid grid-cols-2 gap-4 border-t border-line pt-8">
      <div>
        {prev && (
          <Link
            href={prev.slug}
            className="flex flex-col rounded-xl border border-line p-4 transition-colors hover:border-line-strong"
          >
            <span className="flex items-center gap-1 text-[12px] text-faint">
              <Icon icon="solar:arrow-left-linear" className="h-3.5 w-3.5" /> Previous
            </span>
            <span className="mt-1 text-[14px] font-medium text-ink">{prev.title}</span>
          </Link>
        )}
      </div>
      <div>
        {next && (
          <Link
            href={next.slug}
            className="flex flex-col items-end rounded-xl border border-line p-4 text-right transition-colors hover:border-line-strong"
          >
            <span className="flex items-center gap-1 text-[12px] text-faint">
              Next <Icon icon="solar:arrow-right-linear" className="h-3.5 w-3.5" />
            </span>
            <span className="mt-1 text-[14px] font-medium text-ink">{next.title}</span>
          </Link>
        )}
      </div>
    </nav>
  );
}
