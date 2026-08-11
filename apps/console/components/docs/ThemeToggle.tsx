"use client";

import { useSyncExternalStore } from "react";
import { Icon } from "./Icon";
import { applyTheme, readTheme, serverTheme, subscribeTheme } from "@/lib/theme";

/** Dark/light toggle. Shares one attribute and one storage key with the console. */
export default function ThemeToggle() {
  const theme = useSyncExternalStore(subscribeTheme, readTheme, serverTheme);

  return (
    <button
      onClick={() => applyTheme(theme === "dark" ? "light" : "dark")}
      aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
      aria-pressed={theme === "dark"}
      className="grid h-9 w-9 place-items-center rounded-lg text-muted transition-colors hover:bg-panel-soft hover:text-ink"
    >
      <Icon
        icon={theme === "dark" ? "solar:sun-2-linear" : "solar:moon-linear"}
        className="h-[18px] w-[18px]"
      />
    </button>
  );
}
