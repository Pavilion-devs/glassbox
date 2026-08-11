import createMDX from "@next/mdx";
import type { NextConfig } from "next";
import rehypeSlug from "rehype-slug";
import remarkGfm from "remark-gfm";
import remarkCodeMeta from "./lib/remark-code-meta";

// Connection URLs and service credentials are server-runtime configuration.
// Do not copy them through `env`, which would make Next treat them as build-time
// values and risks exposing future additions to client bundles.
//
// MDX itself is registered in vite.config.ts rather than through `@next/mdx`:
// vinext runs on Vite/rolldown, and its own MDX delegate forwards remark and
// rehype plugins but never sets `providerImportSource`, which is what binds
// `mdx-components.tsx` to the compiled pages.
const nextConfig: NextConfig = {
  // Documentation pages under app/docs/** are authored as MDX.
  pageExtensions: ["ts", "tsx", "js", "jsx", "md", "mdx"],
  ...(process.env.GLASSBOX_NEXT_STANDALONE_BUILD === "1"
    ? { output: "standalone" as const }
    : {}),
};

const withMDX = createMDX({
  options: {
    remarkPlugins: [remarkGfm, remarkCodeMeta],
    rehypePlugins: [rehypeSlug],
  },
});

// Vinext owns MDX compilation in local/Sites builds. The deployment image uses
// Next's standalone server so build-only Vite and Wrangler packages never enter
// the production runtime.
export default process.env.GLASSBOX_NEXT_STANDALONE_BUILD === "1"
  ? withMDX(nextConfig)
  : nextConfig;
