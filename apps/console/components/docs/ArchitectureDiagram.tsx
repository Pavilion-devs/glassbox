type Props = {
  className?: string;
  /** Wrap in a panel card (useful when placed against the page canvas). */
  framed?: boolean;
};

/**
 * Responsive GlassBox architecture diagram.
 *
 * Renders the hand-authored SVG via <object> so it stays vector-crisp at any
 * size and can carry its own internal styles. The aspect ratio is locked to
 * the source artboard (1644 x 1010) so it scales to any width with no layout
 * shift.
 *
 * Source of truth is `docs/architecture/` in the repo root; the copy under
 * `public/media/` is produced as part of the site build.
 */
export default function ArchitectureDiagram({ className = "", framed = false }: Props) {
  return (
    <div
      className={[
        "w-full overflow-hidden",
        framed ? "rounded-2xl border border-line bg-panel shadow-2xl" : "",
        className,
      ]
        .filter(Boolean)
        .join(" ")}
      style={{ aspectRatio: "1644 / 1010" }}
    >
      <object
        type="image/svg+xml"
        data="/media/glassbox-architecture-diagram.svg"
        aria-label="GlassBox architecture — signed decision evidence and deterministic invalidation over DataHub"
        className="pointer-events-none block h-full w-full select-none"
      >
        <Image
          src="/media/glassbox-architecture-diagram.svg"
          alt="GlassBox architecture — signed decision evidence and deterministic invalidation over DataHub"
          width={1644}
          height={1010}
          unoptimized
          className="block h-full w-full"
        />
      </object>
    </div>
  );
}
import Image from "next/image";
