"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { docsNav } from "@/lib/docs-nav";

export default function DocsSidebar() {
  const pathname = usePathname();
  return (
    <aside className="sticky top-16 hidden h-[calc(100vh-4rem)] w-64 shrink-0 overflow-y-auto border-r border-line px-4 py-8 lg:block">
      <nav className="space-y-7">
        {docsNav.map((group) => (
          <div key={group.title}>
            <p className="mb-2 px-3 text-[11px] font-semibold uppercase tracking-wider text-faint">
              {group.title}
            </p>
            <ul className="space-y-0.5">
              {group.items.map((item) => {
                const active = pathname === item.slug;
                return (
                  <li key={item.slug}>
                    <Link
                      href={item.slug}
                      className={`block rounded-lg px-3 py-1.5 text-[14px] transition-colors ${
                        active
                          ? "bg-accent/10 font-medium text-accent"
                          : "text-muted hover:bg-panel-soft hover:text-ink"
                      }`}
                    >
                      {item.title}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </nav>
    </aside>
  );
}
