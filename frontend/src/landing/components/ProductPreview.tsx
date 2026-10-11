import { useState } from 'react';
import { SAMPLE_FINDINGS, PIPELINE_STAGES, type FindingMock } from '../data/landingData';

interface ProductPreviewProps {
  onNavigateLogin: () => void;
}

export function ProductPreview({ onNavigateLogin }: ProductPreviewProps) {
  const [activeTab, setActiveTab] = useState<'findings' | 'pipeline' | 'ledger'>('findings');
  const [selectedSeverity, setSelectedSeverity] = useState<'all' | 'critical' | 'high' | 'medium'>('all');

  const filteredFindings = SAMPLE_FINDINGS.filter((f) => {
    if (selectedSeverity === 'all') return true;
    return f.severity === selectedSeverity;
  });

  return (
    <section id="preview" className="fc-preview-section" aria-labelledby="preview-heading">
      <div className="fc-container">
        {/* Subtle section header */}
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <span className="fc-cap-eyebrow" style={{ textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            Interactive Demonstration
          </span>
          <h2 id="preview-heading" style={{ fontSize: '1.45rem', fontWeight: 700, color: '#ffffff', marginTop: '4px' }}>
            Live Audit Console Interface
          </h2>
          <p style={{ fontSize: '0.86rem', color: 'var(--fc-text-secondary)', marginTop: '4px' }}>
            Explore canonical audit findings, containerized scan stages, and deterministic risk reporting.
          </p>
        </div>

        {/* macOS-style Terminal / Console Preview Window */}
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
              >
                01. Canonical Findings ({SAMPLE_FINDINGS.length})
              </button>
              <button
                role="tab"
                id="tab-pipeline"
                aria-selected={activeTab === 'pipeline'}
                aria-controls="panel-pipeline"
                className={`fc-preview-tab-btn ${activeTab === 'pipeline' ? 'active' : ''}`}
                onClick={() => setActiveTab('pipeline')}
              >
                02. Scanner Pipeline
              </button>
              <button
                role="tab"
                id="tab-ledger"
                aria-selected={activeTab === 'ledger'}
                aria-controls="panel-ledger"
                className={`fc-preview-tab-btn ${activeTab === 'ledger' ? 'active' : ''}`}
                onClick={() => setActiveTab('ledger')}
              >
                03. Score &amp; Compliance Ledger
              </button>
            </div>

            {/* Verified Status Tag */}
            <div className="fc-window-badge">
              <span className="fc-pulse-dot" style={{ background: '#10b981', boxShadow: '0 0 6px #10b981' }} aria-hidden="true" />
              <span>STATUS: CANONICAL AUDIT VERIFIED</span>
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
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '0.8rem', color: 'var(--fc-text-secondary)', fontFamily: 'var(--fc-font-mono)' }}>
                      FILTER SEVERITY:
                    </span>
                    <div className="fc-filter-pill-group">
                      {(['all', 'critical', 'high', 'medium'] as const).map((sev) => (
                        <button
                          key={sev}
                          className={`fc-filter-pill ${selectedSeverity === sev ? 'active' : ''}`}
                          onClick={() => setSelectedSeverity(sev)}
                        >
                          {sev.toUpperCase()}
                        </button>
                      ))}
                    </div>
                  </div>

                  <span style={{ fontSize: '0.76rem', color: 'var(--fc-text-muted)', fontFamily: 'var(--fc-font-mono)' }}>
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
                          <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.74rem', color: 'var(--fc-text-muted)' }}>
                            {finding.id}
                          </span>
                        </div>
                        <h3 className="fc-finding-title">{finding.title}</h3>
                      </div>

                      <div style={{ textAlign: 'right', fontFamily: 'var(--fc-font-mono)', fontSize: '0.78rem' }}>
                        <span style={{ color: 'var(--fc-text-muted)' }}>CVSS: </span>
                        <strong style={{ color: '#ffffff' }}>{finding.cvss.toFixed(1)}</strong>
                      </div>
                    </div>

                    <p style={{ fontSize: '0.84rem', color: 'var(--fc-text-secondary)', marginBottom: '10px' }}>
                      {finding.description}
                    </p>

                    <div className="fc-finding-meta">
                      <span><strong>File:</strong> {finding.filePath}:{finding.lineNumber}</span>
                      <span><strong>Scanner:</strong> {finding.scanner}</span>
                      <span><strong>Classification:</strong> {finding.cwe}</span>
                    </div>

                    {/* Code Evidence Block */}
                    <div className="fc-code-snippet">
                      <span style={{ color: 'var(--fc-text-muted)', marginRight: '8px', userSelect: 'none' }}>
                        {finding.lineNumber} |
                      </span>
                      {finding.evidence}
                    </div>

                    {/* Remediation box */}
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
                <div style={{ paddingBottom: '12px', borderBottom: '1px solid var(--fc-border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.78rem', color: 'var(--fc-text-secondary)' }}>
                    EXECUTION PROTOCOL: DOCKER EPHEMERAL MICRO-SANDBOXES
                  </span>
                  <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.78rem', color: 'var(--fc-clean)' }}>
                    TOTAL DURATION: 3.20s
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
                      <span style={{ color: 'var(--fc-text-muted)' }}>Engine: {stage.scanner}</span>
                      <span style={{ color: 'var(--fc-ember-bright)', background: 'var(--fc-ember-dim)', padding: '2px 8px', borderRadius: '4px' }}>
                        {stage.duration}
                      </span>
                      <span style={{ color: 'var(--fc-clean)' }}>✓ {stage.status}</span>
                    </div>
                  </div>
                ))}

                <div style={{ marginTop: '12px', padding: '14px', background: 'rgba(255, 255, 255, 0.02)', borderRadius: '8px', fontSize: '0.8rem', color: 'var(--fc-text-muted)', fontFamily: 'var(--fc-font-mono)' }}>
                  ℹ All scanner containers drop Linux privileges (--cap-drop=ALL), enforce read-only repo volume mounts, and block external network sockets.
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
                  <p style={{ fontSize: '0.76rem', color: 'var(--fc-text-muted)', marginTop: '14px' }}>
                    Calculated strictly by formula from 1 Critical, 1 High, 1 Medium verified finding.
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
                    <button onClick={onNavigateLogin} className="fc-btn-primary" style={{ fontSize: '0.82rem' }}>
                      Audit Your Repository →
                    </button>
                    <button onClick={onNavigateLogin} className="fc-btn-ghost" style={{ fontSize: '0.82rem' }}>
                      Export Sample PDF Report
                    </button>
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
