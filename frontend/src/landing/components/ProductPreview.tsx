import { useState } from 'react';
import { SAMPLE_FINDINGS, PIPELINE_STAGES, type FindingMock } from '../data/landingData';

interface ProductPreviewProps {
  onNavigateLogin: () => void;
}

export function ProductPreview({ onNavigateLogin }: ProductPreviewProps) {
  const [activeTab, setActiveTab] = useState<'findings' | 'pipeline' | 'ledger' | 'narrative'>('findings');
  const [selectedSeverity, setSelectedSeverity] = useState<'all' | 'critical' | 'high' | 'medium'>('all');

  const filteredFindings = SAMPLE_FINDINGS.filter((f) => {
    if (selectedSeverity === 'all') return true;
    return f.severity === selectedSeverity;
  });

  return (
    <section id="preview" className="fc-preview-section" aria-labelledby="preview-heading">
      <div className="fc-container">
        {/* Section Header */}
        <div style={{ textAlign: 'center', marginBottom: '28px' }}>
          <span className="fc-demo-badge">
            Sample data · illustration only — not a live audit
          </span>
          <h2 id="preview-heading" className="fc-section-title" style={{ marginTop: '12px' }}>
            Interactive Audit Walkthrough
          </h2>
          <p className="fc-section-desc" style={{ maxWidth: '640px', margin: '8px auto 0' }}>
            Inspect client-side audit visualization: normalized findings, containerized pipeline execution,
            deterministic risk scoring, and the optional read-only AI executive briefing.
          </p>
        </div>

        {/* Console Preview Window */}
        <div className="fc-preview-window">
          {/* Window Topbar */}
          <div className="fc-window-topbar">
            <div className="fc-window-controls" aria-hidden="true">
              <div className="fc-dot fc-dot-red" />
              <div className="fc-dot fc-dot-yellow" />
              <div className="fc-dot fc-dot-green" />
            </div>

            {/* Semantic Accessible Tablist */}
            <div className="fc-preview-tabs" role="tablist" aria-label="Audit Console Views">
              <button
                role="tab"
                id="tab-findings"
                aria-selected={activeTab === 'findings'}
                aria-controls="panel-findings"
                className={`fc-preview-tab-btn ${activeTab === 'findings' ? 'active' : ''}`}
                onClick={() => setActiveTab('findings')}
                type="button"
              >
                01. Findings ({SAMPLE_FINDINGS.length})
              </button>
              <button
                role="tab"
                id="tab-pipeline"
                aria-selected={activeTab === 'pipeline'}
                aria-controls="panel-pipeline"
                className={`fc-preview-tab-btn ${activeTab === 'pipeline' ? 'active' : ''}`}
                onClick={() => setActiveTab('pipeline')}
                type="button"
              >
                02. Pipeline Stages
              </button>
              <button
                role="tab"
                id="tab-ledger"
                aria-selected={activeTab === 'ledger'}
                aria-controls="panel-ledger"
                className={`fc-preview-tab-btn ${activeTab === 'ledger' ? 'active' : ''}`}
                onClick={() => setActiveTab('ledger')}
                type="button"
              >
                03. Scoring Ledger
              </button>
              <button
                role="tab"
                id="tab-narrative"
                aria-selected={activeTab === 'narrative'}
                aria-controls="panel-narrative"
                className={`fc-preview-tab-btn ${activeTab === 'narrative' ? 'active' : ''}`}
                onClick={() => setActiveTab('narrative')}
                type="button"
              >
                04. AI Briefing (Read-Only)
              </button>
            </div>

            {/* Sample-data tag */}
            <div className="fc-window-badge" title="Illustrative sample, not live data">
              <span className="fc-pulse-dot" style={{ background: '#eab308', boxShadow: '0 0 6px #eab308' }} aria-hidden="true" />
              <span>SAMPLE · NOT LIVE</span>
            </div>
          </div>

          {/* Window Body */}
          <div className="fc-window-body">
            {/* Tab 1: Canonical Findings */}
            {activeTab === 'findings' && (
              <div
                id="panel-findings"
                role="tabpanel"
                aria-labelledby="tab-findings"
                className="fc-findings-layout"
              >
                {/* Findings Filter Bar */}
                <div className="fc-findings-toolbar">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                    <span style={{ fontSize: '0.78rem', color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)' }}>
                      SEVERITY:
                    </span>
                    <div className="fc-filter-pill-group">
                      {(['all', 'critical', 'high', 'medium'] as const).map((sev) => (
                        <button
                          key={sev}
                          type="button"
                          className={`fc-filter-pill ${selectedSeverity === sev ? 'active' : ''}`}
                          onClick={() => setSelectedSeverity(sev)}
                        >
                          {sev.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>

                  <span style={{ fontSize: '0.76rem', color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)' }}>
                    TARGET: sample-repo/main @ 8f3c1b
                  </span>
                </div>

                {/* Finding Cards */}
                {filteredFindings.map((finding: FindingMock) => (
                  <div key={finding.id} className="fc-finding-card">
                    <div className="fc-finding-head">
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '4px' }}>
                          <span className={`fc-badge fc-badge-${finding.severity}`}>
                            {finding.severity}
                          </span>
                          <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.74rem', color: 'var(--fc-warm-subtle)' }}>
                            {finding.id}
                          </span>
                        </div>
                        <h3 className="fc-finding-title">{finding.title}</h3>
                      </div>

                      <div style={{ textAlign: 'right', fontFamily: 'var(--fc-font-mono)', fontSize: '0.78rem' }}>
                        <span style={{ color: 'var(--fc-text-muted)' }}>CVSS: </span>
                        <strong style={{ color: 'var(--fc-text-primary)' }}>{finding.cvss.toFixed(1)}</strong>
                      </div>
                    </div>

                    <p style={{ fontSize: '0.86rem', color: 'var(--fc-text-secondary)', fontWeight: 500, marginBottom: '12px', lineHeight: 1.55 }}>
                      {finding.description}
                    </p>

                    <div className="fc-finding-meta">
                      <span><strong>File:</strong> {finding.filePath}:{finding.lineNumber}</span>
                      <span><strong>Engine:</strong> {finding.scanner}</span>
                      <span><strong>Mapping:</strong> {finding.cwe}</span>
                    </div>

                    {/* Code Evidence Block */}
                    <div className="fc-code-snippet">
                      <span style={{ color: 'var(--fc-text-muted)', marginRight: '8px', userSelect: 'none' }}>
                        {finding.lineNumber} |
                      </span>
                      <span style={{ color: '#F1F5F9' }}>{finding.evidence}</span>
                    </div>

                    {/* Actionable remediation */}
                    <div className="fc-remediation-box">
                      <span style={{ color: 'var(--fc-clean)', fontWeight: 700 }}>REMEDIATION:</span>
                      <span>{finding.remediation}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* Tab 2: Scanner Pipeline Breakdown */}
            {activeTab === 'pipeline' && (
              <div
                id="panel-pipeline"
                role="tabpanel"
                aria-labelledby="tab-pipeline"
                className="fc-pipeline-list"
              >
                <div style={{ paddingBottom: '12px', borderBottom: '1px solid var(--fc-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '8px' }}>
                  <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.78rem', color: 'var(--fc-warm-muted)' }}>
                    EXECUTION PROTOCOL: DOCKER EPHEMERAL MICRO-SANDBOXES
                  </span>
                  <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.78rem', color: 'var(--fc-clean)' }}>
                    WALL TIME: 3.20s
                  </span>
                </div>

                {PIPELINE_STAGES.map((stage) => (
                  <div key={stage.step} className="fc-pipeline-stage-item">
                    <div className="fc-stage-left">
                      <span className="fc-stage-number">{stage.step}</span>
                      <div>
                        <div className="fc-stage-name">{stage.name}</div>
                        <div className="fc-stage-desc">{stage.summary}</div>
                      </div>
                    </div>

                    <div className="fc-stage-meta">
                      <span style={{ color: 'var(--fc-warm-subtle)' }}>Engine: {stage.scanner}</span>
                      <span style={{ color: 'var(--fc-ember-bright)', background: 'var(--fc-ember-dim)', padding: '2px 8px', borderRadius: '4px' }}>
                        {stage.duration}
                      </span>
                      <span style={{ color: 'var(--fc-clean)' }}>✓ {stage.status}</span>
                    </div>
                  </div>
                ))}

                <div style={{ marginTop: '14px', padding: '14px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', fontSize: '0.8rem', color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)', border: '1px solid var(--fc-glass-border)' }}>
                  ℹ All scanner containers drop Linux privileges (--cap-drop=ALL), enforce read-only repo volume mounts, and block external network egress.
                </div>
              </div>
            )}

            {/* Tab 3: Security Score & Compliance Ledger */}
            {activeTab === 'ledger' && (
              <div
                id="panel-ledger"
                role="tabpanel"
                aria-labelledby="tab-ledger"
                className="fc-report-ledger-grid"
              >
                <div className="fc-score-card">
                  <span className="fc-score-label">Deterministic Score</span>
                  <div className="fc-score-value">78</div>
                  <span className="fc-score-label">Out of 100 max</span>
                  <span className="fc-score-grade">GRADE: B+ (GOOD)</span>
                  <p style={{ fontSize: '0.76rem', color: 'var(--fc-warm-subtle)', marginTop: '14px' }}>
                    Calculated mathematically from verified findings: 1 critical (-15), 1 high (-7), 1 medium (-0).
                  </p>
                </div>

                <div className="fc-report-breakdown">
                  <div className="fc-breakdown-row">
                    <span><strong>Critical Severities</strong> (CWE-798 Hardcoded Secrets)</span>
                    <span className="fc-badge fc-badge-critical">1 Confirmed</span>
                  </div>
                  <div className="fc-breakdown-row">
                    <span><strong>High Severities</strong> (CVE-2020-7598 Prototype Pollution)</span>
                    <span className="fc-badge fc-badge-high">1 Confirmed</span>
                  </div>
                  <div className="fc-breakdown-row">
                    <span><strong>Medium Severities</strong> (CWE-22 Path Traversal in Extraction)</span>
                    <span className="fc-badge fc-badge-medium">1 Confirmed</span>
                  </div>
                  <div className="fc-breakdown-row">
                    <span><strong>Low / Informational</strong></span>
                    <span className="fc-badge fc-badge-low">0 Findings</span>
                  </div>

                  <div style={{ marginTop: '16px', display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
                    <button onClick={onNavigateLogin} className="fc-btn-primary" style={{ fontSize: '0.82rem' }} type="button">
                      Sign in to audit your repo →
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Tab 4: Optional AI-Generated Briefing (Strict Read-Only) */}
            {activeTab === 'narrative' && (
              <div
                id="panel-narrative"
                role="tabpanel"
                aria-labelledby="tab-narrative"
                className="fc-narrative-preview-panel"
              >
                <div className="fc-narrative-banner">
                  <span className="fc-pulse-dot" style={{ background: '#0284c7', boxShadow: '0 0 6px #0284c7' }} aria-hidden="true" />
                  <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.76rem', color: 'var(--fc-low)', fontWeight: 700 }}>
                    READ-ONLY AI NARRATIVE · ILLUSTRATIVE EXAMPLE
                  </span>
                </div>

                <div className="fc-narrative-content">
                  <h4 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--fc-text-primary)', marginBottom: '8px' }}>
                    Executive Security Briefing — sample-repo @ 8f3c1b
                  </h4>
                  <p style={{ fontSize: '0.86rem', color: 'var(--fc-text-secondary)', lineHeight: 1.6, marginBottom: '14px' }}>
                    Automated analysis completed across static analysis (Semgrep), dependency CVE tracking (OSV-Scanner),
                    and credential entropy (Gitleaks). The audit identified 3 confirmed issues. Two items require immediate remediation:
                  </p>

                  <ul style={{ paddingLeft: '20px', fontSize: '0.84rem', color: 'var(--fc-text-secondary)', lineHeight: 1.6, marginBottom: '16px' }}>
                    <li style={{ marginBottom: '6px' }}>
                      <strong style={{ color: 'var(--fc-critical)' }}>Critical:</strong> Rotate symmetric secret key hardcoded in <code>backend/src/config.rs:44</code> and migrate to KMS or environment variables.
                    </li>
                    <li style={{ marginBottom: '6px' }}>
                      <strong style={{ color: 'var(--fc-high)' }}>High:</strong> Upgrade <code>minimist</code> from <code>0.0.8</code> to <code>&gt;=0.2.4</code> to close prototype pollution vector GHSA-vh95-rm6w-qq85.
                    </li>
                    <li>
                      <strong style={{ color: 'var(--fc-medium)' }}>Medium:</strong> Enforce canonical path validation on extracted zip entries in <code>fetch.rs</code>.
                    </li>
                  </ul>

                  <div className="fc-narrative-disclaimer">
                    <svg width="16" height="16" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true" style={{ flexShrink: 0 }}>
                      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                    </svg>
                    <span>
                      <strong>Integrity Guarantee:</strong> AI models generate summaries solely from frozen audit ledgers.
                      They have zero permission to delete, modify, or fabricate security findings or modify the 78/100 score.
                    </span>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </section>
  );
}
