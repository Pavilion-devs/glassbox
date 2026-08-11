/**
 * Docs wordmark glyph. Mirrors the two offset panes of the console's
 * `.app-mark`, drawn as SVG so it scales cleanly in the topbar.
 */
export default function GlassBoxMark({ className = "" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <rect width="32" height="32" rx="9" fill="var(--ink)" />
      <rect
        x="7.5"
        y="6.5"
        width="11"
        height="15"
        rx="3"
        transform="rotate(-10 7.5 6.5)"
        fill="none"
        stroke="var(--on-ink)"
        strokeWidth="1.5"
      />
      <rect
        x="14"
        y="12"
        width="11"
        height="15"
        rx="3"
        transform="rotate(7 14 12)"
        fill="none"
        stroke="#aaa2ff"
        strokeWidth="1.5"
      />
    </svg>
  );
}
