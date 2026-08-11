import type { Metadata } from "next";
import Link from "next/link";
import ArchitectureDiagram from "@/components/docs/ArchitectureDiagram";
import GlassBoxMark from "@/components/docs/GlassBoxMark";
import { Icon } from "@/components/docs/Icon";
import CopyCommand from "@/components/site/CopyCommand";

export const metadata: Metadata = {
  title: "GlassBox — Know when an agent decision is no longer safe to trust",
  description:
    "GlassBox records a signed Decision Bill of Materials for consequential agent outputs, binds it to DataHub's governed metadata graph, and turns a metadata change into deterministic invalidation and governed recovery.",
};

const QUICKSTART = "uv run --all-extras python -m examples.flagship_demo --allow-live";

const STEPS = [
  {
    title: "Capture",
    body: "Instrumented runs emit OTLP. Nested agent runs correlate through explicit parent run and span IDs.",
  },
  {
    title: "Sign",
    body: "Canonicalised with RFC 8785, digested with SHA-256, signed with Ed25519. Ambiguity is an error, not a guess.",
  },
  {
    title: "Project",
    body: "Every dependency resolves to a real DataHub URN, then publishes as a governed projection verified by direct readback.",
  },
  {
    title: "Assess",
    body: "A metadata change becomes a content-addressed campaign. A versioned rule pack decides materiality — not a model.",
  },
  {
    title: "Recover",
    body: "Quarantine, fingerprint-authorized replay in a digest-pinned sandbox, and append-only supersession.",
  },
];

const EVIDENCE = [
  {
    icon: "solar:box-linear",
    title: "A pinned, disposable estate",
    body: "The flagship demo fetches DataHub Core v1.6.0's official quickstart from an exact upstream commit, records the downloaded bytes' SHA-256, and removes only its own estate.",
  },
  {
    icon: "solar:target-linear",
    title: "Negative controls that must not fire",
    body: "Every invalidation proof also runs an unrelated-field change that has to stay UNAFFECTED. A detector that only fires positively is not evidence.",
  },
  {
    icon: "solar:global-linear",
    title: "Acknowledgement failure, on purpose",
    body: "The Kafka proof fails every commit inside one retry window, confirms through an independent consumer that the offset did not advance, then forces exact same-offset redelivery.",
  },
  {
    icon: "solar:database-linear",
    title: "Readback, not write acknowledgement",
    body: "A DataHub capability counts as proven only after a live probe writes metadata and reads it back directly from the configured server.",
  },
];

export default function LandingPage() {
  return (
    <main className="min-h-screen bg-canvas text-ink">
      {/* ---------------------------------------------------------------- hero */}
      <div className="relative overflow-hidden">
        <div
          aria-hidden="true"
          className="absolute inset-0 bg-[linear-gradient(to_right,rgba(41,40,46,0.05)_1px,transparent_1px),linear-gradient(to_bottom,rgba(41,40,46,0.05)_1px,transparent_1px)] bg-[size:52px_52px] [mask-image:radial-gradient(ellipse_78%_70%_at_50%_38%,#000_35%,transparent_100%)]"
        />
        <div
          aria-hidden="true"
          className="absolute left-1/2 top-[-6rem] h-[32rem] w-[32rem] -translate-x-1/2 rounded-full bg-accent/15 blur-3xl"
        />

        <div className="relative z-10 mx-auto w-full max-w-6xl px-6 lg:px-10">
          <header className="flex items-center justify-between py-6">
            <Link href="/" className="flex items-center gap-2.5" aria-label="GlassBox home">
              <GlassBoxMark className="h-9 w-9" />
              <span className="text-[17px] font-semibold tracking-tight">GlassBox</span>
            </Link>
            <nav className="flex items-center gap-5 text-[14px] font-medium text-muted">
              <Link className="transition-colors hover:text-ink" href="/docs">
                Docs
              </Link>
              <Link
                className="hidden transition-colors hover:text-ink sm:block"
                href="/docs/architecture"
              >
                Architecture
              </Link>
              <a
                className="hidden transition-colors hover:text-ink sm:block"
                href="https://app.glassboxhq.xyz"
              >
                Live console
              </a>
              <a
                className="rounded-full bg-accent px-4 py-1.5 text-[13px] font-medium text-on-accent transition-opacity hover:opacity-90"
                href="https://github.com/Pavilion-devs/glassbox"
                target="_blank"
                rel="noreferrer"
              >
                GitHub
              </a>
            </nav>
          </header>

          <section className="mx-auto max-w-4xl py-20 text-center sm:py-28">
            <p className="mb-6 font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-accent">
              Open source · DataHub-native
            </p>

            <h1 className="text-balance text-[clamp(2.1rem,4.6vw,3.9rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
              <span className="text-muted">Data lineage tells you where data went.</span>{" "}
              GlassBox tells you what your agents did because of it.
            </h1>

            <p className="mx-auto mt-7 max-w-2xl text-pretty text-[16px] leading-8 text-muted sm:text-[17px]">
              Signed decision receipts, deterministic invalidation, and governed recovery — bound to
              the metadata graph you already run.
            </p>

            <div className="mx-auto mt-10 max-w-2xl">
              <CopyCommand command={QUICKSTART} />
              <p className="mt-3 text-[13px] text-faint">
                Brings up a pinned estate, runs the real causal chain, and tears it down.{" "}
                <Link className="font-medium text-accent hover:underline" href="/docs/quickstart">
                  What this does
                </Link>
              </p>
            </div>

            <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
              <Link
                href="/docs"
                className="inline-flex min-h-11 items-center justify-center rounded-full bg-ink px-6 text-[14px] font-semibold text-[var(--on-ink)] transition-transform hover:-translate-y-0.5"
              >
                Read the docs
              </Link>
              <Link
                href="/docs/architecture"
                className="inline-flex min-h-11 items-center justify-center rounded-full border border-line bg-panel px-6 text-[14px] font-semibold transition-colors hover:border-line-strong"
              >
                See the architecture
              </Link>
              <a
                href="https://app.glassboxhq.xyz"
                className="inline-flex min-h-11 items-center justify-center rounded-full border border-line bg-panel px-6 text-[14px] font-semibold transition-colors hover:border-line-strong"
              >
                Open read-only console
              </a>
            </div>
            <p className="mt-3 text-[12px] text-faint">
              Any GitHub account can sign in as a viewer. Mutations remain maintainer-only.
            </p>
          </section>
        </div>
      </div>

      {/* ------------------------------------------------------------- problem */}
      <section className="mx-auto w-full max-w-6xl px-6 py-20 lg:px-10">
        <div className="mx-auto max-w-3xl">
          <p className="mb-4 font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-faint">
            The problem
          </p>
          <h2 className="text-[clamp(1.5rem,2.6vw,2.1rem)] font-semibold leading-tight tracking-[-0.03em]">
            A schema field changed six weeks ago. Which decisions are no longer safe?
          </h2>
          <div className="mt-6 space-y-4 text-[16px] leading-8 text-muted">
            <p>
              When an agent writes a recommendation, an approval, or a price, that output is a claim
              about the state of the world at a moment in time. It depended on specific fields, in
              specific datasets, at specific versions.
            </p>
            <p>
              Nothing normally records that dependency. So when the schema moves, there is no
              mechanical way to answer the only question that matters — and the usual substitute is
              a human reading dashboards and guessing.
            </p>
            <p className="font-medium text-ink">
              That does not scale, and it is not evidence.
            </p>
          </div>
        </div>
      </section>

      {/* --------------------------------------------------------- how it works */}
      <section className="border-y border-line bg-panel-soft">
        <div className="mx-auto w-full max-w-6xl px-6 py-20 lg:px-10">
          <div className="mx-auto max-w-3xl text-center">
            <p className="mb-4 font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-faint">
              How it works
            </p>
            <h2 className="text-[clamp(1.5rem,2.6vw,2.1rem)] font-semibold leading-tight tracking-[-0.03em]">
              One connected chain, from the run to the recovery
            </h2>
          </div>

          <ol className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
            {STEPS.map((step, i) => (
              <li
                key={step.title}
                className="flex flex-col rounded-xl border border-line bg-panel p-5"
              >
                <span className="mb-3 grid h-7 w-7 place-items-center rounded-full bg-ink text-[12px] font-semibold text-[var(--on-ink)]">
                  {i + 1}
                </span>
                <p className="text-[15px] font-semibold tracking-tight">{step.title}</p>
                <p className="mt-1.5 text-[13.5px] leading-6 text-muted">{step.body}</p>
              </li>
            ))}
          </ol>

          <div className="mt-12">
            <ArchitectureDiagram framed />
            <p className="mt-4 text-center text-[13px] text-faint">
              Evidence plane on the wire, control plane off it, and one transactional state
              authority connecting them.{" "}
              <Link className="font-medium text-accent hover:underline" href="/docs/architecture">
                Read the architecture
              </Link>
            </p>
          </div>
        </div>
      </section>

      {/* ------------------------------------------------------------- evidence */}
      <section className="mx-auto w-full max-w-6xl px-6 py-20 lg:px-10">
        <div className="mx-auto max-w-3xl text-center">
          <p className="mb-4 font-mono text-[11px] font-semibold uppercase tracking-[0.18em] text-faint">
            Evidence
          </p>
          <h2 className="text-[clamp(1.5rem,2.6vw,2.1rem)] font-semibold leading-tight tracking-[-0.03em]">
            No screenshot is proof of anything
          </h2>
          <p className="mx-auto mt-5 max-w-2xl text-[16px] leading-8 text-muted">
            Every capability claim in this project traces to a committed, sanitized live evidence
            report — or it is not claimed.
          </p>
        </div>

        <div className="mt-12 grid gap-4 sm:grid-cols-2">
          {EVIDENCE.map((item) => (
            <div key={item.title} className="rounded-xl border border-line bg-panel p-6">
              <span className="mb-3 grid h-9 w-9 place-items-center rounded-lg bg-accent/10 text-accent">
                <Icon icon={item.icon} className="h-[19px] w-[19px]" />
              </span>
              <p className="text-[15px] font-semibold tracking-tight">{item.title}</p>
              <p className="mt-1.5 text-[14px] leading-7 text-muted">{item.body}</p>
            </div>
          ))}
        </div>

        <div className="mx-auto mt-8 max-w-3xl rounded-xl border border-line bg-panel-soft p-6">
          <p className="flex items-center gap-2 text-[14px] font-semibold">
            <Icon icon="solar:info-circle-linear" className="h-[18px] w-[18px] text-accent" />
            And the boundaries, stated
          </p>
          <p className="mt-2 text-[14px] leading-7 text-muted">
            The SQLite profile coordinates processes on one host — it is not a multi-node
            deployment. The PostgreSQL proof establishes real multi-connection coordination, not
            managed failover or network-partition recovery. Kafka and PostgreSQL Queue claims are
            independent: neither substitutes for the other. Replay runs in a strong, verifiable
            sandbox, not a formal isolation guarantee.
          </p>
        </div>
      </section>

      {/* --------------------------------------------------------------- footer */}
      <footer className="border-t border-line">
        <div className="mx-auto w-full max-w-6xl px-6 py-10 lg:px-10">
          <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
            <Link href="/" className="flex items-center gap-2.5" aria-label="GlassBox home">
              <GlassBoxMark className="h-7 w-7" />
              <span className="text-[15px] font-semibold tracking-tight">GlassBox</span>
            </Link>
            <nav className="flex flex-wrap items-center gap-5 text-[13.5px] text-muted">
              <Link className="transition-colors hover:text-ink" href="/docs">
                Docs
              </Link>
              <Link className="transition-colors hover:text-ink" href="/docs/quickstart">
                Quickstart
              </Link>
              <Link className="transition-colors hover:text-ink" href="/docs/architecture">
                Architecture
              </Link>
              <a className="transition-colors hover:text-ink" href="https://app.glassboxhq.xyz">
                Live console
              </a>
              <a
                className="transition-colors hover:text-ink"
                href="https://github.com/Pavilion-devs/glassbox"
                target="_blank"
                rel="noreferrer"
              >
                GitHub
              </a>
            </nav>
          </div>
          <div className="mt-8 flex flex-col gap-2 border-t border-line pt-6 font-mono text-[10.5px] uppercase tracking-[0.16em] text-faint sm:flex-row sm:items-center sm:justify-between">
            <span>GlassBox × DataHub</span>
            <span>Capture · Sign · Project · Assess · Recover</span>
          </div>
        </div>
      </footer>
    </main>
  );
}
