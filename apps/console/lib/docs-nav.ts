export type DocPage = {
  title: string;
  slug: string;
  summary: string;
};

export type DocGroup = {
  title: string;
  items: DocPage[];
};

/** Sidebar structure. Drives the sidebar, ⌘K search, and prev/next footer. */
export const docsNav: DocGroup[] = [
  {
    title: "Getting started",
    items: [
      {
        title: "Overview",
        slug: "/docs",
        summary:
          "What GlassBox is: a signed evidence boundary between an agent's decision and the data it depended on.",
      },
      {
        title: "Quickstart",
        slug: "/docs/quickstart",
        summary:
          "Bring up the flagship estate, record a decision receipt, change a schema, and watch the decision go stale.",
      },
      {
        title: "Installation & setup",
        slug: "/docs/setup",
        summary: "Toolchain, package extras, state profiles, signing keys, and the DataHub estate.",
      },
    ],
  },
  {
    title: "Core concepts",
    items: [
      {
        title: "How GlassBox works",
        slug: "/docs/how-it-works",
        summary: "Capture, sign, project, assess, recover — the five steps end to end.",
      },
      {
        title: "Decision receipts",
        slug: "/docs/receipts",
        summary: "Canonical integrity, Ed25519 signing, signer trust, and supersession.",
      },
      {
        title: "The invalidation loop",
        slug: "/docs/invalidation-loop",
        summary: "One metadata change becomes a campaign, an assessment, and a writeback.",
      },
    ],
  },
  {
    title: "Assessment",
    items: [
      {
        title: "Deterministic invalidation",
        slug: "/docs/assessment/deterministic",
        summary: "Reason codes, policy versions, and why a rule decides staleness instead of a model.",
      },
      {
        title: "Evidence completeness",
        slug: "/docs/assessment/completeness",
        summary: "Dependency resolution, field-lineage coverage, and wildcard queries.",
      },
    ],
  },
  {
    title: "Policy",
    items: [
      {
        title: "Domain-semantic policies",
        slug: "/docs/policy",
        summary: "Content-addressed rule packs, the operator trust registry, and equivalence primitives.",
      },
      {
        title: "Recovery & quarantine",
        slug: "/docs/recovery",
        summary: "Signed handoff, authorization, isolated replay, and verified closure.",
      },
    ],
  },
  {
    title: "Integrations",
    items: [
      {
        title: "DataHub",
        slug: "/docs/integrations/datahub",
        summary: "The Actions plugin, governed writeback, ownership routing, and incident closure.",
      },
      {
        title: "OTLP & Kafka",
        slug: "/docs/integrations/transport",
        summary: "Durable publication, acknowledgement, and independent transport recovery.",
      },
      {
        title: "Forensics MCP",
        slug: "/docs/integrations/mcp",
        summary: "Six proof-carrying read-only tools over the same state authority.",
      },
    ],
  },
  {
    title: "Reference",
    items: [
      {
        title: "CLI reference",
        slug: "/docs/cli",
        summary: "Every command across the DBOM, state, receiver, replay, and plugin binaries.",
      },
      {
        title: "Schemas & contracts",
        slug: "/docs/schemas",
        summary: "The seven published JSON contracts and where each one is enforced.",
      },
    ],
  },
  {
    title: "Resources",
    items: [
      {
        title: "Architecture",
        slug: "/docs/architecture",
        summary: "The full GlassBox runtime topology, in one diagram.",
      },
    ],
  },
];

/** Flattened, ordered list for prev/next navigation and search. */
export const flatDocs = docsNav.flatMap((group) =>
  group.items.map((item) => ({ ...item, group: group.title })),
);
