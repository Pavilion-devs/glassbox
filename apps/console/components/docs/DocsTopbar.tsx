"use client";

import Link from "next/link";
import { Icon } from "./Icon";
import GlassBoxMark from "./GlassBoxMark";
import ThemeToggle from "./ThemeToggle";
import SearchPalette from "./SearchPalette";

const openSearch = () => window.dispatchEvent(new Event("glassbox:open-search"));

export default function DocsTopbar() {
  return (
    <header className="sticky top-0 z-50 border-b border-line bg-canvas/80 backdrop-blur-xl">
      <div className="mx-auto flex h-16 max-w-[1600px] items-center gap-3 px-4 lg:px-6">
        <Link href="/docs" className="flex items-center gap-2.5">
          <GlassBoxMark className="h-8 w-8" />
          <span className="text-[15px] font-semibold tracking-tight text-ink">
            GlassBox <span className="text-faint">Docs</span>
          </span>
        </Link>

        <div className="flex-1" />

        <button
          onClick={openSearch}
          className="hidden items-center gap-2 rounded-lg border border-line bg-panel-soft px-3 py-1.5 text-[13px] text-faint transition-colors hover:border-line-strong sm:flex"
        >
          <Icon icon="solar:magnifer-linear" className="h-4 w-4" />
          Search
          <kbd className="ml-6 rounded border border-line px-1.5 text-[10px]">⌘K</kbd>
        </button>
        <button
          onClick={openSearch}
          aria-label="Search"
          className="grid h-9 w-9 place-items-center rounded-lg text-muted hover:bg-panel-soft sm:hidden"
        >
          <Icon icon="solar:magnifer-linear" className="h-[18px] w-[18px]" />
        </button>

        <Link
          href="/docs/architecture"
          className="hidden text-[14px] font-medium text-muted transition-colors hover:text-ink md:block"
        >
          Architecture
        </Link>

        <Link
          href="/"
          className="hidden text-[14px] font-medium text-muted transition-colors hover:text-ink md:block"
        >
          Console
        </Link>

        <ThemeToggle />

        <a
          href="https://github.com/Pavilion-devs/glassbox"
          target="_blank"
          rel="noreferrer"
          className="rounded-full bg-accent px-4 py-1.5 text-[13px] font-medium text-on-accent transition-opacity hover:opacity-90"
        >
          GitHub
        </a>
      </div>
      <SearchPalette />
    </header>
  );
}
