import mdx from "@mdx-js/rollup";
import rehypeSlug from "rehype-slug";
import remarkGfm from "remark-gfm";
import vinext from "vinext";
import { defineConfig } from "vite";
import hostingConfig from "./.openai/hosting.json" with { type: "json" };
import remarkCodeMeta from "./lib/remark-code-meta.ts";
import { sites } from "./lib/sites-vite-plugin.ts";

// Points the compiled MDX at the root `mdx-components.tsx`. That module exports
// a plain `useMDXComponents` function rather than a React context provider, so
// documentation pages keep rendering as server components.
//
// Resolved through the `@/` alias rather than an absolute filesystem path: an
// absolute specifier produces a second module instance outside the normal graph,
// which breaks the "use client" boundaries on CodeBlock and friends and leaves
// them calling hooks against a null dispatcher.
const mdxProvider = "@/mdx-components";

const SITE_CREATOR_PLACEHOLDER_DATABASE_ID =
  "00000000-0000-4000-8000-000000000000";

const { d1, r2 } = hostingConfig;

// macOS Seatbelt blocks FSEvents, so Codex previews need polling for HMR.
const isCodexSeatbeltSandbox = process.env.CODEX_SANDBOX === "seatbelt";

const localBindingConfig = {
  main: "./worker/index.ts",
  compatibility_flags: ["nodejs_compat"],
  // The Workers runtime does not inherit the shell environment, so anything the
  // app reads from `process.env` on this path has to be handed over as a var.
  // Production sets the same key in wrangler config; this bridges local dev.
  vars: {
    GLASSBOX_PUBLIC_HOSTS: process.env.GLASSBOX_PUBLIC_HOSTS ?? "",
  },
  d1_databases: d1
    ? [
        {
          binding: d1,
          database_name: "site-creator-d1",
          database_id: SITE_CREATOR_PLACEHOLDER_DATABASE_ID,
        },
      ]
    : [],
  r2_buckets: r2
    ? [
        {
          binding: r2,
          bucket_name: "site-creator-r2",
        },
      ]
    : [],
};

export default defineConfig(async () => {
  // Keep Wrangler and Miniflare state project-local. These are non-secret tool
  // settings; application environment belongs in ignored `.env*` files.
  process.env.WRANGLER_WRITE_LOGS ??= "false";
  process.env.WRANGLER_LOG_PATH ??= ".wrangler/logs";
  process.env.MINIFLARE_REGISTRY_PATH ??= ".wrangler/registry";

  // Wrangler snapshots its log path while the Cloudflare plugin is imported.
  const { cloudflare } = await import("@cloudflare/vite-plugin");

  // The dev server rejects unknown Host headers. Marketing mode is selected by
  // host in middleware, so developing or testing it locally needs those exact
  // hostnames allowed here too. Production runs on Workers, where this check
  // does not apply.
  const marketingHosts = (process.env.GLASSBOX_PUBLIC_HOSTS ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);

  return {
    server: {
      ...(isCodexSeatbeltSandbox ? { watch: { useFsEvents: false, usePolling: true } } : {}),
      ...(marketingHosts.length > 0 ? { allowedHosts: marketingHosts } : {}),
    },
    plugins: [
      // Must precede vinext: it defers to a user-registered MDX plugin and
      // otherwise injects its own without a provider.
      {
        enforce: "pre" as const,
        ...mdx({
          remarkPlugins: [remarkGfm, remarkCodeMeta],
          // Gives every heading an id, which is what the "On this page" rail reads.
          rehypePlugins: [rehypeSlug],
          providerImportSource: mdxProvider,
        }),
      },
      vinext(),
      sites(),
      cloudflare({
        viteEnvironment: { name: "rsc", childEnvironments: ["ssr"] },
        config: localBindingConfig,
      }),
    ],
  };
});
