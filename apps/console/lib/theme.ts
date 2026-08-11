/**
 * Shared theme store.
 *
 * The theme lives on `<html>` as `data-theme`, written by the pre-paint script
 * in the root layout before React exists, and persisted under `gbx-theme`.
 * Reading it through an external store keeps the server snapshot at the light
 * default while the client reads the real attribute, so a stored dark
 * preference resolves without a hydration mismatch.
 *
 * The documentation routes deliberately share this with the operator console:
 * one toggle, one key, one attribute across the whole app.
 */
export const THEME_KEY = "gbx-theme";

const listeners = new Set<() => void>();

export function subscribeTheme(onChange: () => void) {
  listeners.add(onChange);
  return () => void listeners.delete(onChange);
}

export function readTheme(): "light" | "dark" {
  return document.documentElement.dataset.theme === "dark" ? "dark" : "light";
}

export function serverTheme(): "light" {
  return "light";
}

export function applyTheme(next: "light" | "dark") {
  if (next === "dark") document.documentElement.dataset.theme = "dark";
  else delete document.documentElement.dataset.theme;
  try {
    localStorage.setItem(THEME_KEY, next);
  } catch {
    // A blocked storage backend still gets the toggle for this session.
  }
  listeners.forEach((notify) => notify());
}
