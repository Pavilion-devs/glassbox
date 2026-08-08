"use client";

import { useState } from "react";

const receiptId =
  "gbx:receipt:sha256:d87482b9feb3eb0e4a32777771febcaea008c6c4f5836aed86d52c501e8e0ace";

const scenarios = {
  material: {
    label: "Material change",
    field: "revenue",
    state: "STALE",
    reason: "OBSERVED_MATERIAL_DEPENDENCY_CHANGED",
    headline: "This decision is stale.",
    explanation:
      "The run observed commerce.orders.revenue before its type changed. The dependency is exact, signed, and material to the output.",
    relation: "Exact evidence match",
    match: "evidence-orders-001",
    quarantined: "Required",
    tone: "danger",
  },
  control: {
    label: "Negative control",
    field: "internal_note",
    state: "UNAFFECTED",
    reason: "COMPLETE_FIELD_LINEAGE_PROVES_FIELD_UNUSED",
    headline: "This decision remains valid.",
    explanation:
      "The changed field was not used. Complete field lineage and a proven non-wildcard query provide positive evidence of absence.",
    relation: "Positive exclusion proof",
    match: "No matched evidence",
    quarantined: "Not required",
    tone: "safe",
  },
} as const;

const tabs = ["Evidence", "Actions", "Replay"] as const;
type ScenarioKey = keyof typeof scenarios;
type Tab = (typeof tabs)[number];

export default function Home() {
  const [scenarioKey, setScenarioKey] = useState<ScenarioKey>("material");
  const [activeTab, setActiveTab] = useState<Tab>("Evidence");
  const [copied, setCopied] = useState(false);
  const scenario = scenarios[scenarioKey];

  async function copyReceipt() {
    await navigator.clipboard?.writeText(receiptId);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1600);
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <span className="brand-mark" aria-hidden="true">
            <span />
            <span />
            <span />
          </span>
          <span className="brand-name">GlassBox</span>
          <span className="brand-divider" aria-hidden="true" />
          <span className="workspace-name">Forensics</span>
        </div>
        <div className="topbar-actions">
          <span className="live-connection">
            <span className="status-light" aria-hidden="true" />
            DataHub Core 1.6.0
          </span>
          <button className="icon-button" type="button" aria-label="Open help">
            ?
          </button>
          <button className="avatar" type="button" aria-label="Open user menu">
            OP
          </button>
        </div>
      </header>

      <div className="console-grid">
        <aside className="sidebar" aria-label="Forensic navigation">
          <nav>
            <p className="nav-label">Workspace</p>
            <a className="nav-link active" href="#investigation">
              <span className="nav-icon lens-icon" aria-hidden="true" />
              Investigations
              <span className="nav-count">3</span>
            </a>
            <a className="nav-link" href="#receipts">
              <span className="nav-icon receipt-icon" aria-hidden="true" />
              Receipts
            </a>
            <a className="nav-link" href="#campaigns">
              <span className="nav-icon pulse-icon" aria-hidden="true" />
              Campaigns
              <span className="nav-count muted">1</span>
            </a>
            <a className="nav-link" href="#replays">
              <span className="nav-icon replay-icon" aria-hidden="true" />
              Replays
            </a>
          </nav>

          <div className="case-list">
            <p className="nav-label">Recent decisions</p>
            <button className="case-row selected" type="button">
              <span className="case-state stale" aria-hidden="true" />
              <span>
                <strong>Pricing recommendation</strong>
                <small>pricing-agent · 2m ago</small>
              </span>
            </button>
            <button className="case-row" type="button">
              <span className="case-state verified" aria-hidden="true" />
              <span>
                <strong>Customer cohort brief</strong>
                <small>growth-agent · 18m ago</small>
              </span>
            </button>
            <button className="case-row" type="button">
              <span className="case-state superseded" aria-hidden="true" />
              <span>
                <strong>Renewal outreach plan</strong>
                <small>retention-agent · 1h ago</small>
              </span>
            </button>
          </div>

          <div className="privacy-note">
            <span className="privacy-mark" aria-hidden="true" />
            <div>
              <strong>Raw content withheld</strong>
              <span>Digests and governed metadata only</span>
            </div>
          </div>
        </aside>

        <main className="main-content" id="investigation">
          <div className="breadcrumbs" aria-label="Breadcrumb">
            <span>Agent decisions</span>
            <span aria-hidden="true">/</span>
            <strong>Pricing recommendation</strong>
          </div>

          <section className="case-header">
            <div>
              <div className="eyebrow-row">
                <span>Decision receipt</span>
                <span aria-hidden="true">·</span>
                <code>d87482b9feb3</code>
              </div>
              <h1>Pricing recommendation</h1>
              <p>
                <strong>pricing-agent</strong> v0.1.0
                <span aria-hidden="true">·</span> forensics-live-run-001
                <span aria-hidden="true">·</span> Aug 6, 2026 at 1:24 PM
              </p>
            </div>
            <div className="header-actions">
              <button className="secondary-button" type="button" onClick={copyReceipt}>
                <span className="copy-glyph" aria-hidden="true" />
                {copied ? "Copied" : "Copy receipt ID"}
              </button>
              <a className="primary-button" href="#evidence-table">
                Inspect evidence
                <span aria-hidden="true">→</span>
              </a>
            </div>
          </section>

          <section className="status-ribbon" aria-label="Decision status">
            <div className="ribbon-step complete">
              <span className="step-dot">1</span>
              <span>
                <strong>Receipt verified</strong>
                <small>Ed25519 · all gates pass</small>
              </span>
            </div>
            <span className="ribbon-line complete" aria-hidden="true" />
            <div className="ribbon-step alert">
              <span className="step-dot">2</span>
              <span>
                <strong>Dependency changed</strong>
                <small>schemaMetadata · revenue</small>
              </span>
            </div>
            <span className="ribbon-line alert" aria-hidden="true" />
            <div className={`ribbon-step ${scenario.tone}`}>
              <span className="step-dot">3</span>
              <span>
                <strong>Policy classified</strong>
                <small>glassbox.materiality.v1</small>
              </span>
            </div>
          </section>

          <div className="scenario-switch" role="group" aria-label="Forensic scenario">
            {(Object.keys(scenarios) as ScenarioKey[]).map((key) => (
              <button
                key={key}
                type="button"
                className={scenarioKey === key ? "active" : ""}
                aria-pressed={scenarioKey === key}
                onClick={() => setScenarioKey(key)}
              >
                <span className={`scenario-dot ${scenarios[key].tone}`} aria-hidden="true" />
                {scenarios[key].label}
              </button>
            ))}
            <span className="switch-note">Live proof controls</span>
          </div>

          <div className="workspace-grid">
            <div className="primary-column">
              <section className="causal-card" aria-labelledby="causal-title">
                <div className="section-heading">
                  <div>
                    <p>Run-specific influence</p>
                    <h2 id="causal-title">Why this output changed state</h2>
                  </div>
                  <span className="evidence-standard">Observed evidence only</span>
                </div>

                <div className="causal-flow">
                  <article className="flow-node source-node">
                    <span className="node-kicker">DataHub change</span>
                    <div className="node-title-row">
                      <span className="database-glyph" aria-hidden="true" />
                      <div>
                        <strong>commerce.orders</strong>
                        <code>.{scenario.field}</code>
                      </div>
                    </div>
                    <span className="change-chip">Type changed</span>
                  </article>

                  <div className={`flow-connector ${scenario.tone}`} aria-hidden="true">
                    <span />
                    <em>{scenarioKey === "material" ? "MATCH" : "EXCLUDE"}</em>
                  </div>

                  <article className="flow-node receipt-node">
                    <span className="node-kicker">Signed receipt</span>
                    <div className="node-title-row">
                      <span className="agent-glyph" aria-hidden="true">G</span>
                      <div>
                        <strong>pricing-agent</strong>
                        <code>run-001</code>
                      </div>
                    </div>
                    <span className={`match-chip ${scenario.tone}`}>{scenario.relation}</span>
                  </article>

                  <div className={`flow-connector ${scenario.tone}`} aria-hidden="true">
                    <span />
                    <em>POLICY</em>
                  </div>

                  <article className={`flow-node output-node ${scenario.tone}`}>
                    <span className="node-kicker">Decision output</span>
                    <div className="node-title-row">
                      <span className="document-glyph" aria-hidden="true" />
                      <div>
                        <strong>recommendation</strong>
                        <code>application/json</code>
                      </div>
                    </div>
                    <span className={`verdict-chip ${scenario.tone}`}>{scenario.state}</span>
                  </article>
                </div>
              </section>

              <section className="details-card">
                <div className="tabs" role="tablist" aria-label="Receipt detail views">
                  {tabs.map((tab) => (
                    <button
                      key={tab}
                      type="button"
                      role="tab"
                      aria-selected={activeTab === tab}
                      className={activeTab === tab ? "active" : ""}
                      onClick={() => setActiveTab(tab)}
                    >
                      {tab}
                      {tab === "Evidence" && <span>1</span>}
                      {tab === "Actions" && <span>1</span>}
                    </button>
                  ))}
                </div>

                {activeTab === "Evidence" && (
                  <div className="tab-panel" role="tabpanel" id="evidence-table">
                    <div className="table-heading">
                      <div>
                        <h3>Observed evidence</h3>
                        <p>Captured from the run, not inferred from catalog lineage.</p>
                      </div>
                      <span className="count-pill">1 record</span>
                    </div>
                    <div className="evidence-table" role="table" aria-label="Observed evidence">
                      <div className="table-row table-labels" role="row">
                        <span role="columnheader">Evidence</span>
                        <span role="columnheader">Role</span>
                        <span role="columnheader">State</span>
                        <span role="columnheader">Commitment</span>
                      </div>
                      <div className="table-row" role="row">
                        <span className="evidence-name" role="cell">
                          <span className="field-glyph" aria-hidden="true" />
                          <span>
                            <strong>commerce.orders.revenue</strong>
                            <small>PostgreSQL · PROD</small>
                          </span>
                        </span>
                        <span role="cell">INPUT</span>
                        <span role="cell"><b className="observed-chip">OBSERVED</b></span>
                        <span role="cell"><code>aad125f0…8a991</code></span>
                      </div>
                    </div>
                    <div className="truth-boundary">
                      <span className="truth-icon" aria-hidden="true">i</span>
                      <p>
                        <strong>Integrity is not truth.</strong> The signature proves this evidence
                        record was not altered. It does not prove the source value was factually
                        correct.
                      </p>
                    </div>
                  </div>
                )}

                {activeTab === "Actions" && (
                  <div className="tab-panel" role="tabpanel">
                    <div className="table-heading">
                      <div>
                        <h3>Recorded tool action</h3>
                        <p>Input and output bodies are withheld; commitments remain verifiable.</p>
                      </div>
                      <span className="read-only-chip">READ ONLY</span>
                    </div>
                    <div className="action-summary">
                      <span className="tool-glyph" aria-hidden="true" />
                      <div>
                        <strong>glassbox.orders.lookup</strong>
                        <p>Succeeded · no approval required · exact tool v0.1.0</p>
                      </div>
                      <code>action-read-orders-001</code>
                    </div>
                    <div className="digest-grid">
                      <span><small>INPUT DIGEST</small><code>c062fa43…d5ffa</code></span>
                      <span><small>OUTPUT DIGEST</small><code>aad125f0…8a991</code></span>
                    </div>
                  </div>
                )}

                {activeTab === "Replay" && (
                  <div className="tab-panel" role="tabpanel">
                    <div className="table-heading">
                      <div>
                        <h3>Safe replay chain</h3>
                        <p>History is append-only. The original receipt is never overwritten.</p>
                      </div>
                      <span className="ready-chip">READY</span>
                    </div>
                    <div className="replay-chain">
                      <div><span>1</span><strong>Exact resources pinned</strong><small>Agent, model, skill, tool, schema</small></div>
                      <i aria-hidden="true" />
                      <div><span>2</span><strong>Read-only execution</strong><small>Fresh policy check · zero source mutations</small></div>
                      <i aria-hidden="true" />
                      <div><span>3</span><strong>New signed receipt</strong><small>Raw-free diff · separate supersession</small></div>
                    </div>
                  </div>
                )}
              </section>
            </div>

            <aside className="insight-rail" aria-label="Forensic verdict">
              <section className={`verdict-card ${scenario.tone}`} aria-live="polite">
                <div className="verdict-heading">
                  <span className={`shield-mark ${scenario.tone}`} aria-hidden="true">
                    {scenarioKey === "material" ? "!" : "✓"}
                  </span>
                  <span className={`state-badge ${scenario.tone}`}>{scenario.state}</span>
                </div>
                <h2>{scenario.headline}</h2>
                <p>{scenario.explanation}</p>
                <dl>
                  <div><dt>Policy</dt><dd>glassbox.materiality.v1</dd></div>
                  <div><dt>Reason code</dt><dd><code>{scenario.reason}</code></dd></div>
                  <div><dt>Matched evidence</dt><dd>{scenario.match}</dd></div>
                  <div><dt>Quarantine</dt><dd>{scenario.quarantined}</dd></div>
                </dl>
              </section>

              <section className="integrity-card">
                <div className="rail-title">
                  <div>
                    <p>Cryptographic integrity</p>
                    <h2>All gates pass</h2>
                  </div>
                  <span className="verified-seal" aria-hidden="true">✓</span>
                </div>
                <ul className="gate-list">
                  <li><span>Payload digest</span><b>VERIFIED</b></li>
                  <li><span>Receipt identity</span><b>VERIFIED</b></li>
                  <li><span>Merkle root</span><b>VERIFIED</b></li>
                  <li><span>Ed25519 signature</span><b>VERIFIED</b></li>
                </ul>
              </section>

              <section className="datahub-card">
                <div className="datahub-logo" aria-hidden="true"><span>dh</span></div>
                <div>
                  <p>Direct DataHub read</p>
                  <h2>5 aspects returned</h2>
                  <span>Document projection · Core 1.6.0</span>
                  <code className="skill-context">skill=datahub-agent-forensics</code>
                </div>
                <span className="projection-badge">PROJECTION_ONLY</span>
              </section>
            </aside>
          </div>
        </main>
      </div>
    </div>
  );
}
