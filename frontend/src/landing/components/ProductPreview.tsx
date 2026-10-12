import { useState, useMemo } from 'react';
import { SAMPLE_FINDINGS, PIPELINE_STAGES, type FindingMock } from '../data/landingData';
import { ShinyText } from './ShinyText';
import { DecryptedText } from './DecryptedText';
import { CountUp } from './CountUp';

interface ProductPreviewProps {
  onNavigateLogin: () => void;
}

const STAGE_TELEMETRY: Record<string, {
  cmd: string;
  flags: string;
  containerId: string;
  logs: string[];
}> = {
  '01': {
    containerId: 'fc-ingest-8f3c',
    cmd: 'stream_unpack --max-mb=50 /archive.tar.gz',
    flags: '--network=none --memory=256m --cap-drop=ALL',
    logs: [
      '[0.00s] Validating streaming archive signature...',
      '[0.04s] Verified clean tar headers (no symlink traversal)',
      '[0.14s] Repository contents extracted to ephemeral volume (/tmp/audit-repo)',
    ],
  },
  '02': {
    containerId: 'fc-gitleaks-4a11',
    cmd: 'gitleaks detect --source=/tmp/audit-repo --report-format=json',
    flags: '--read-only --network=none --memory=512m --cap-drop=ALL',
    logs: [
      '[0.00s] Initializing high-entropy Shannon regex engine...',
      '[0.18s] Scanned 128 commits and 42 source files',
      '[0.36s] Confirmed 1 hardcoded symmetric secret in backend/src/config.rs:44',
    ],
  },
  '03': {
    containerId: 'fc-semgrep-9f20',
    cmd: 'semgrep scan --config=p/security-audit --json /tmp/audit-repo',
    flags: '--read-only --network=none --memory=1024m --cap-drop=ALL',
    logs: [
      '[0.00s] Loading OWASP Top 10 rule manifests...',
      '[0.82s] AST traversal across Rust and TypeScript callgraphs',
      '[1.80s] Flagged CWE-22 path traversal vulnerability in fetch.rs:88',
    ],
  },
  '04': {
    containerId: 'fc-osv-3d88',
    cmd: 'osv-scanner --lockfile=package-lock.json --json',
    flags: '--read-only --network=none --memory=512m --cap-drop=ALL',
    logs: [
      '[0.00s] Reading manifest dependencies (48 packages)...',
      '[0.32s] Cross-referencing against Google OSV CVE database',
      '[0.72s] Matched GHSA-vh95-rm6w-qq85 (CVE-2020-7598) in minimist@0.0.8',
    ],
  },
  '05': {
    containerId: 'fc-ledger-synth',
    cmd: 'fc-synthesize --canonical --hash=sha256',
    flags: '--network=none --memory=256m',
    logs: [
      '[0.00s] Aggregating findings across 3 scanner outputs...',
      '[0.06s] Deduplication complete: 3 unique confirmed findings',
      '[0.18s] Mathematical score ledger finalized: 78/100 (Grade B+)',
    ],
  },
};

export function ProductPreview({ onNavigateLogin }: ProductPreviewProps) {
  const [activeTab, setActiveTab] = useState<'findings' | 'pipeline' | 'ledger' | 'narrative'>('findings');
  const [selectedSeverity, setSelectedSeverity] = useState<'all' | 'critical' | 'high' | 'medium'>('all');
  const [selectedEngine, setSelectedEngine] = useState<string>('all');
  const [copiedFindingId, setCopiedFindingId] = useState<string | null>(null);
  const [expandedStage, setExpandedStage] = useState<string | null>('02');
  const [simulatedFixCritical, setSimulatedFixCritical] = useState<boolean>(false);
  const [aiStreaming, setAiStreaming] = useState<boolean>(false);

  const filteredFindings = useMemo(() => {
    return SAMPLE_FINDINGS.filter((f) => {
      const matchSev = selectedSeverity === 'all' || f.severity === selectedSeverity;
      const matchEngine = selectedEngine === 'all' || f.scanner.toLowerCase().includes(selectedEngine.toLowerCase());
      return matchSev && matchEngine;
    });
  }, [selectedSeverity, selectedEngine]);

  const handleCopyEvidence = (finding: FindingMock) => {
    const text = `${finding.filePath}:${finding.lineNumber}\n${finding.evidence}\n// ${finding.remediation}`;
    navigator.clipboard?.writeText(text);
    setCopiedFindingId(finding.id);
    setTimeout(() => setCopiedFindingId(null), 2000);
  };

  const handleTriggerAiStream = () => {
    setAiStreaming(true);
    setTimeout(() => setAiStreaming(false), 1200);
  };

  // Deterministic score calculation
  const calculatedScore = simulatedFixCritical ? 93 : 78;
  const calculatedGrade = simulatedFixCritical ? 'A (EXCELLENT)' : 'B+ (GOOD)';

  return (
    <section id="preview" className="fc-preview-section" aria-labelledby="preview-heading">
      <div className="fc-container">
        {/* Section Header */}
        <div className="fc-section-header-left" style={{ marginBottom: '28px' }}>
          <span className="fc-demo-badge">
            <span className="fc-pulse-dot" style={{ background: '#34D399', boxShadow: 'none', width: '6px', height: '6px' }} aria-hidden="true" />
            <ShinyText text="Sample audit data · Interactive console simulation" shineColor="#38BDF8" />
          </span>
          <h2 id="preview-heading" className="fc-section-title" style={{ marginTop: '12px', textAlign: 'left' }}>
            Interactive Audit Walkthrough
          </h2>
          <p className="fc-section-desc" style={{ maxWidth: '600px', margin: '8px 0 0', textAlign: 'left' }}>
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
              <span className="fc-pulse-dot" style={{ background: '#34D399', boxShadow: '0 0 6px #34D399' }} aria-hidden="true" />
              <span>LIVE INTERACTION READY</span>
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
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontSize: '0.74rem', color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)' }}>
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

                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                      <span style={{ fontSize: '0.74rem', color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)' }}>
                        ENGINE:
                      </span>
                      <div className="fc-filter-pill-group">
                        {['all', 'gitleaks', 'semgrep', 'osv'].map((engine) => (
                          <button
                            key={engine}
                            type="button"
                            className={`fc-filter-pill ${selectedEngine === engine ? 'active' : ''}`}
                            onClick={() => setSelectedEngine(engine)}
                          >
                            {engine.toUpperCase()}
                          </button>
                        ))}
                      </div>
                    </div>
                  </div>

                  <span style={{ fontSize: '0.76rem', color: 'var(--fc-clean)', fontFamily: 'var(--fc-font-mono)' }}>
                    TARGET: sample-repo/main @ <DecryptedText text="8f3c1b" speed={30} animateOn="view" /> (3 findings)
                  </span>
                </div>

                {/* Finding Cards */}
                {filteredFindings.length === 0 ? (
                  <div style={{ padding: '32px', textAlign: 'center', color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)' }}>
                    No findings match the selected filters.
                  </div>
                ) : (
                  filteredFindings.map((finding: FindingMock) => {
                    const isCopied = copiedFindingId === finding.id;

                    return (
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

                        <div className="fc-finding-meta-chips">
                          <span className="fc-meta-chip">
                            <span className="fc-meta-chip-label">File:</span>
                            <code className="fc-meta-chip-code">{finding.filePath}:{finding.lineNumber}</code>
                          </span>
                          <span className="fc-meta-chip">
                            <span className="fc-meta-chip-label">Engine:</span>
                            <span className="fc-meta-chip-val">{finding.scanner}</span>
                          </span>
                          <span className="fc-meta-chip">
                            <span className="fc-meta-chip-label">Mapping:</span>
                            <span className="fc-meta-chip-val">{finding.cwe}</span>
                          </span>
                        </div>

                        {/* Code Evidence Block with interactive copy */}
                        <div className="fc-code-snippet" style={{ position: 'relative' }}>
                          <span style={{ color: 'var(--fc-text-muted)', marginRight: '8px', userSelect: 'none' }}>
                            {finding.lineNumber} |
                          </span>
                          <span style={{ color: '#F1F5F9' }}>{finding.evidence}</span>
                          <button
                            type="button"
                            onClick={() => handleCopyEvidence(finding)}
                            className="fc-snippet-copy-btn"
                            title="Copy code snippet & remediation"
                            aria-label={`Copy evidence for ${finding.id}`}
                          >
                            {isCopied ? (
                              <span style={{ color: '#34D399', display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                  <path d="M20 6L9 17l-5-5" />
                                </svg>
                                Copied
                              </span>
                            ) : (
                              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '4px' }}>
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                                  <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                                </svg>
                                Copy
                              </span>
                            )}
                          </button>
                        </div>

                        {/* Actionable remediation */}
                        <div className="fc-remediation-box">
                          <span style={{ color: 'var(--fc-clean)', fontWeight: 700 }}>REMEDIATION:</span>
                          <span>{finding.remediation}</span>
                        </div>
                      </div>
                    );
                  })
                )}
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
                    TOTAL DURATION: 3.20s (PARALLEL EXECUTION)
                  </span>
                </div>

                {PIPELINE_STAGES.map((stage) => {
                  const isExpanded = expandedStage === stage.step;
                  const telemetry = STAGE_TELEMETRY[stage.step];

                  return (
                    <div key={stage.step} className="fc-pipeline-stage-container">
                      <div
                        className={`fc-pipeline-stage-item ${isExpanded ? 'is-active-stage' : ''}`}
                        onClick={() => setExpandedStage(isExpanded ? null : stage.step)}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            setExpandedStage(isExpanded ? null : stage.step);
                          }
                        }}
                        aria-expanded={isExpanded}
                      >
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
                          <span style={{ fontSize: '0.74rem', color: 'var(--fc-warm-subtle)' }}>
                            {isExpanded ? '▲ Logs' : '▼ Inspect'}
                          </span>
                        </div>
                      </div>

                      {/* Expandable Container Telemetry Logs */}
                      {isExpanded && telemetry && (
                        <div className="fc-stage-telemetry-drawer">
                          <div className="fc-stage-telemetry-meta">
                            <span><strong>CONTAINER:</strong> <code>{telemetry.containerId}</code></span>
                            <span><strong>FLAGS:</strong> <code>{telemetry.flags}</code></span>
                          </div>
                          <div className="fc-stage-telemetry-cmd">
                            <span>$ {telemetry.cmd}</span>
                          </div>
                          <div className="fc-stage-telemetry-logs">
                            {telemetry.logs.map((log, i) => (
                              <div key={i} className="fc-telemetry-log-line">{log}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}

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
                  <div className="fc-score-value">
                    <CountUp to={calculatedScore} duration={1.1} />
                  </div>
                  <span className="fc-score-label">Out of 100 max</span>
                  <span className="fc-score-grade">GRADE: {calculatedGrade}</span>

                  <p style={{ fontSize: '0.76rem', color: 'var(--fc-warm-subtle)', marginTop: '14px', lineHeight: 1.5 }}>
                    Formula: <code>100 - (15 × Critical) - (7 × High) - (0 × Medium)</code>
                  </p>

                  {/* Interactive Remediation Simulator */}
                  <div style={{ marginTop: '16px', padding: '12px', background: 'rgba(255, 255, 255, 0.03)', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.08)' }}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer', fontSize: '0.78rem', color: '#F2F4F7' }}>
                      <input
                        type="checkbox"
                        checked={simulatedFixCritical}
                        onChange={(e) => setSimulatedFixCritical(e.target.checked)}
                        style={{ accentColor: 'var(--fc-ember)' }}
                      />
                      <span>Simulate Remediating CWE-798 Secret (+15 pts)</span>
                    </label>
                  </div>
                </div>

                <div className="fc-report-breakdown">
                  <div className="fc-breakdown-row">
                    <span><strong>Critical Severities</strong> (CWE-798 Hardcoded Secrets)</span>
                    <span className={`fc-badge ${simulatedFixCritical ? 'fc-badge-clean' : 'fc-badge-critical'}`}>
                      {simulatedFixCritical ? '0 Confirmed (Fixed)' : '1 Confirmed (-15)'}
                    </span>
                  </div>
                  <div className="fc-breakdown-row">
                    <span><strong>High Severities</strong> (CVE-2020-7598 Prototype Pollution)</span>
                    <span className="fc-badge fc-badge-high">1 Confirmed (-7)</span>
                  </div>
                  <div className="fc-breakdown-row">
                    <span><strong>Medium Severities</strong> (CWE-22 Path Traversal in Extraction)</span>
                    <span className="fc-badge fc-badge-medium">1 Confirmed (-0)</span>
                  </div>
                  <div className="fc-breakdown-row">
                    <span><strong>Low / Informational</strong></span>
                    <span className="fc-badge fc-badge-low">0 Findings (0)</span>
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
                <div className="fc-narrative-banner" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span className="fc-pulse-dot" style={{ background: '#0284c7', boxShadow: '0 0 6px #0284c7' }} aria-hidden="true" />
                    <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.76rem', color: 'var(--fc-low)', fontWeight: 700 }}>
                      <ShinyText text="READ-ONLY AI NARRATIVE · DETERMINISTIC SUMMARY BOUNDARY" shineColor="#38BDF8" />
                    </span>
                  </div>
                  <button
                    type="button"
                    onClick={handleTriggerAiStream}
                    className="fc-simulate-stream-btn"
                  >
                    {aiStreaming ? 'Streaming...' : 'Replay Briefing Stream ↺'}
                  </button>
                </div>

                <div className="fc-narrative-content" style={{ opacity: aiStreaming ? 0.6 : 1, transition: 'opacity 0.2s ease' }}>
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

