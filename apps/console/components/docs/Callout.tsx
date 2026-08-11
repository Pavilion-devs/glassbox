"use client";

import { Icon } from "./Icon";
import type { ReactNode } from "react";

type CalloutType = "note" | "tip" | "warning" | "danger";

const VARIANTS: Record<CalloutType, { icon: string; ring: string; tint: string; mark: string }> = {
  note: {
    icon: "solar:info-circle-linear",
    ring: "border-accent/30",
    tint: "bg-accent/[0.06]",
    mark: "text-accent",
  },
  tip: {
    icon: "solar:lightbulb-bolt-linear",
    ring: "border-positive/30",
    tint: "bg-positive/[0.06]",
    mark: "text-positive",
  },
  warning: {
    icon: "solar:danger-triangle-linear",
    ring: "border-caution/30",
    tint: "bg-caution/[0.06]",
    mark: "text-caution",
  },
  danger: {
    icon: "solar:shield-warning-linear",
    ring: "border-critical/30",
    tint: "bg-critical/[0.06]",
    mark: "text-critical",
  },
};

export default function Callout({
  type = "note",
  title,
  children,
}: {
  type?: CalloutType;
  title?: string;
  children: ReactNode;
}) {
  const v = VARIANTS[type];
  return (
    <div className={`my-5 flex gap-3 rounded-xl border ${v.ring} ${v.tint} px-4 py-3.5`}>
      <Icon icon={v.icon} className={`mt-0.5 h-5 w-5 shrink-0 ${v.mark}`} />
      <div className="min-w-0 text-[14px] leading-relaxed text-ink-soft [&>p]:m-0 [&>p+p]:mt-2">
        {title && <p className="mb-1 font-semibold text-ink">{title}</p>}
        {children}
      </div>
    </div>
  );
}
