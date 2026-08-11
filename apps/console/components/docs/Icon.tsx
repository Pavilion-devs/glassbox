import { SOLAR_ICONS, type SolarIcon } from "./solar-icons";

/**
 * Drop-in replacement for `@iconify/react`'s `<Icon icon="solar:…" />`.
 *
 * Same call signature, but the body comes from the inlined `solar-icons`
 * module instead of the Iconify HTTP API, so a docs page renders its icons
 * offline and makes no third-party request.
 */
export function Icon({ icon, className }: { icon: string; className?: string }) {
  const name = icon.replace(/^solar:/, "") as SolarIcon;
  const entry = SOLAR_ICONS[name];
  if (!entry) return null;
  return (
    <svg
      className={className}
      viewBox={`0 0 ${entry.w} ${entry.h}`}
      width="1em"
      height="1em"
      aria-hidden="true"
      dangerouslySetInnerHTML={{ __html: entry.body }}
    />
  );
}

export default Icon;
