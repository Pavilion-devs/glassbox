import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

async function render() {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request("http://localhost/", {
      headers: { accept: "text/html" },
    }),
    {
      ASSETS: {
        fetch: async () => new Response("Not found", { status: 404 }),
      },
    },
    {
      waitUntil() {},
      passThroughOnException() {},
    },
  );
}

test("server-renders the GlassBox forensic investigation", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);

  const html = await response.text();
  assert.match(html, /<title>GlassBox Forensics — Agent Decision Evidence<\/title>/i);
  assert.match(html, /og:image[^>]+og\.png|og\.png[^>]+og:image/i);
  assert.match(html, /Pricing recommendation/);
  assert.match(html, /OBSERVED_MATERIAL_DEPENDENCY_CHANGED/);
  assert.match(html, /PROJECTION_ONLY/);
  assert.match(html, /Integrity is not truth/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|SECRET/i);
});

test("removes starter-only assets and dependency", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.match(page, /datahub-agent-forensics/);
  assert.match(page, /safe_for_deterministic_policy|All gates pass/);
  assert.match(layout, /GlassBox Forensics/);
  assert.match(layout, /\/og\.png/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
});
