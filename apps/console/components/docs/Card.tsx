import Link from "next/link";
import type { ReactNode } from "react";
import { Icon } from "./Icon";

/**
 * Icon card. Becomes a link when `href` is given, a plain panel otherwise, so
 * the same component works for both "go here next" grids and static feature
 * grids.
 */
export function Card({
  title,
  icon,
  href,
  children,
}: {
  title: string;
  icon?: string;
  href?: string;
  children?: ReactNode;
}) {
  const inner = (
    <>
      {icon && (
        <span className="mb-3 grid h-9 w-9 place-items-center rounded-lg bg-accent/10 text-accent">
          <Icon icon={icon} className="h-[19px] w-[19px]" />
        </span>
      )}
      <p className="text-[15px] font-semibold tracking-tight text-ink">{title}</p>
      {children && (
        <div className="mt-1.5 text-[13.5px] leading-6 text-muted [&>p]:m-0">{children}</div>
      )}
    </>
  );

  const base = "flex flex-col rounded-xl border border-line bg-panel p-5";

  if (!href) return <div className={base}>{inner}</div>;

  const internal = href.startsWith("/") || href.startsWith("#");
  const cls = `${base} transition-colors hover:border-accent/60 hover:bg-accent/[0.03]`;

  return internal ? (
    <Link href={href} className={cls}>
      {inner}
    </Link>
  ) : (
    <a href={href} target="_blank" rel="noreferrer" className={cls}>
      {inner}
    </a>
  );
}

/** Responsive grid wrapper. `cols` is the desktop column count. */
export function CardGroup({ cols = 2, children }: { cols?: 1 | 2 | 3; children: ReactNode }) {
  const grid =
    cols === 1 ? "sm:grid-cols-1" : cols === 3 ? "sm:grid-cols-2 lg:grid-cols-3" : "sm:grid-cols-2";
  return <div className={`my-6 grid grid-cols-1 gap-4 ${grid}`}>{children}</div>;
}

export default Card;
