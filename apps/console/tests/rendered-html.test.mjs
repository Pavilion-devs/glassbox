import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

async function render(path = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${path}`);
  const { default: worker } = await import(workerUrl.href);
  return worker.fetch(
    new Request(`http://localhost${path}`, { headers: { accept: "text/html" } }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("server-renders a real disconnected application state", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  const html = await response.text();

  assert.match(html, /<title>GlassBox Forensics — Decision Control Center<\/title>/i);
  assert.match(html, />Overview</);
  assert.match(html, /Connect your evidence plane/);
  assert.match(html, /href="\/investigations"/);
  assert.match(html, /href="\/receipts"/);
  assert.match(html, /href="\/campaigns"/);
  assert.match(html, /href="\/recovery"/);
  assert.match(html, /href="\/trust"/);
  assert.doesNotMatch(html, /Pricing recommendation|OBSERVED_MATERIAL_DEPENDENCY_CHANGED/);
  assert.doesNotMatch(html, /codex-preview|react-loading-skeleton|SECRET/i);
});

test("renders the public product, documentation, and architecture surfaces", async () => {
  const landing = await render("/home");
  assert.equal(landing.status, 200);
  const landingHtml = await landing.text();
  assert.match(landingHtml, /GlassBox tells you what your agents did because of it/);
  assert.match(landingHtml, /href="\/docs"/);
  assert.match(landingHtml, /href="\/docs\/architecture"/);
  assert.match(landingHtml, /href="https:\/\/youtu\.be\/g-j9zD5cxLk"/);
  assert.match(landingHtml, />Watch demo</);
  assert.doesNotMatch(landingHtml, /Service-account token|Create ingestion key/);

  const docs = await render("/docs");
  assert.equal(docs.status, 200);
  assert.match(await docs.text(), /Documentation/);

  const architecture = await render("/docs/architecture");
  assert.equal(architecture.status, 200);
  assert.match(await architecture.text(), /Architecture/);
});

test("every primary navigation destination is independently rendered", async () => {
  for (const [path, heading] of [
    ["/investigations", "Investigations"],
    ["/receipts", "Receipts"],
    ["/campaigns", "Campaigns"],
    ["/recovery", "Recovery"],
    ["/trust", "Trust &amp; privacy"],
    ["/settings", "Connections"],
  ]) {
    const response = await render(path);
    assert.equal(response.status, 200, path);
    assert.match(await response.text(), new RegExp(`>${heading}<`), path);
  }
});

test("removes starter and bundled-success implementation paths", async () => {
  const [layout, operatorLayout, packageJson, api] = await Promise.all([
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/(console)/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
    readFile(new URL("../app/lib/forensics-api.ts", import.meta.url), "utf8"),
  ]);

  assert.match(layout, /Root layout owns only the document/);
  assert.match(operatorLayout, /ConsoleShell/);
  assert.match(operatorLayout, /dynamic\s*=\s*["']force-dynamic["']/);
  assert.match(api, /GLASSBOX_FORENSICS_API_URL/);
  assert.doesNotMatch(api, /one-command-flagship|Pricing recommendation/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await assert.rejects(access(new URL("../app/_sites-preview", import.meta.url)));
  await assert.rejects(access(new URL("../app/flagship-evidence.ts", import.meta.url)));
});

test("keeps the operator-facing repairs wired into the product", async () => {
  const [shell, investigation, campaign, receipts, recovery, overview] = await Promise.all([
    readFile(new URL("../app/components/console-shell.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/(console)/investigations/[receiptId]/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/(console)/campaigns/[campaignId]/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/(console)/receipts/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/(console)/recovery/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/(console)/page.tsx", import.meta.url), "utf8"),
  ]);

  assert.match(shell, /EXACT_RECEIPT_ID/);
  assert.match(shell, /global-search-submit/);
  assert.match(investigation, /IdentifierControl/);
  assert.match(investigation, /DateValue/);
  assert.match(campaign, /IdentifierControl/);
  assert.match(campaign, /DateValue/);
  assert.match(receipts, /DateValue/);
  assert.match(recovery, /AWAITING_AUTHORIZATION/);
  assert.match(overview, /compactChangeLabel/);
  assert.match(overview, /compactUrn/);
});

test("renders the real connection center without exposing deployment secrets", async () => {
  const response = await render("/settings");
  const html = await response.text();
  const [controlApi, proxy] = await Promise.all([
    readFile(new URL("../app/lib/control-api.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/control/[...path]/route.ts", import.meta.url), "utf8"),
  ]);

  assert.match(html, /Connect DataHub/);
  assert.match(html, /Service-account token/);
  assert.match(html, /Prove write permission/);
  assert.match(html, /Agent keys/);
  assert.match(controlApi, /GLASSBOX_CONTROL_API_TOKEN/);
  assert.match(proxy, /proxyControlRequest/);
  assert.doesNotMatch(html, /GLASSBOX_CONTROL_MASTER_KEY|DATAHUB_GMS_TOKEN/);
});
