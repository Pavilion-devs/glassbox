"use client";

import { useRef, useState } from "react";
import { Icon } from "@/components/docs/Icon";

/**
 * The hero's primary call to action.
 *
 * The strongest claim this project can make is that a reader can falsify it in
 * one command, so the command itself is the button.
 */
export default function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => setCopied(false), 1800);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <button
      onClick={copy}
      aria-label={copied ? "Command copied" : "Copy the quickstart command"}
      className="group flex w-full items-center gap-3 rounded-xl border border-line bg-panel px-4 py-3.5 text-left shadow-sm transition-colors hover:border-line-strong sm:px-5"
    >
      <span aria-hidden="true" className="select-none font-mono text-[13px] text-faint">
        $
      </span>
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[12.5px] leading-6 text-ink sm:text-[13.5px]">
        {command}
      </code>
      <span
        className={`inline-flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[12px] font-semibold transition-colors ${
          copied ? "bg-positive/10 text-positive" : "bg-panel-soft text-muted group-hover:text-ink"
        }`}
      >
        <Icon
          icon={copied ? "solar:check-read-linear" : "solar:copy-linear"}
          className="h-3.5 w-3.5"
        />
        {copied ? "Copied" : "Copy"}
      </span>
    </button>
  );
}
