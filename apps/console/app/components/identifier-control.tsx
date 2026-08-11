"use client";

import { useState } from "react";

export function IdentifierControl({
  value,
  compact,
  label,
}: {
  value: string;
  compact: string;
  label: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setCopied(false);
    }
  }

  return (
    <span className={`identifier-control ${expanded ? "expanded" : ""}`}>
      <code title={expanded ? undefined : value}>{expanded ? value : compact}</code>
      <span className="identifier-actions">
        <button
          type="button"
          aria-expanded={expanded}
          aria-label={`${expanded ? "Hide" : "Reveal"} full ${label}`}
          onClick={() => setExpanded((current) => !current)}
        >{expanded ? "Hide" : "Reveal"}</button>
        <button type="button" aria-label={`Copy ${label}`} onClick={copy}>
          {copied ? "Copied" : "Copy"}
        </button>
      </span>
    </span>
  );
}
