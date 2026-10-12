import { useState } from 'react';
import { NextLabSymbol } from './BrandLogos';
import TechText from './TechText';
import StrokeText from './StrokeText';
import { ShinyText } from './ShinyText';
import { DecryptedText } from './DecryptedText';
import { SpotlightCard } from './SpotlightCard';
import { CountUp } from './CountUp';

interface HeroSectionProps {
  onNavigateLogin: () => void;
}

export function HeroSection({ onNavigateLogin }: HeroSectionProps) {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'curl' | 'cli' | 'action'>('curl');

  const curlCommand = `curl -X POST /api/v1/audits \\
  -H "Content-Type: application/json" \\
  -d '{
    "repo_url": "https://github.com/acme/core-api",
    "branch": "main",
    "commit_sha": null
  }'`;

  const cliCommand = `firecrow audit https://github.com/acme/core-api \\
  --branch main \\
  --scanners gitleaks,semgrep,osv \\
  --fail-on high,critical`;

  const actionSnippet = `name: FireCrow Security Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: nextlab/firecrow-action@v1
        with:
          fail_closed: true`;

  const getCodeSnippet = () => {
    switch (activeTab) {
      case 'cli':
        return cliCommand;
      case 'action':
        return actionSnippet;
      default:
        return curlCommand;
    }
  };

  const handleCopy = () => {
    navigator.clipboard?.writeText(getCodeSnippet());
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section className="fc-hero" aria-labelledby="hero-heading">
      <div className="fc-container">
        <div className="fc-hero-layout">
          {/* Left Column: Value Proposition & CTAs */}
          <div className="fc-hero-copy">
            {/* NEXT LAB.inc endorsement badge */}
            <div className="fc-eyebrow-pill" aria-label="Endorsement by NEXT LAB.inc">
              <span className="fc-brand-micro-tag">
                <NextLabSymbol size={14} />
                <span>NEXT LAB.inc</span>
              </span>
              <span className="fc-eyebrow-sep" aria-hidden="true">/</span>
              <span className="fc-eyebrow-text">
                <ShinyText text="Flagship Repository Security Auditing" shineColor="#E5484D" />
              </span>
            </div>

            {/* High-impact Fire Crow headline */}
            <h1 id="hero-heading" className="fc-hero-headline fc-hero-punch">
              <span className="fc-punch-static">Know what&rsquo;s in your repo</span>
              <StrokeText
                text="before attackers do."
                strokeColor="#E5484D"
                fillColor="#F2F4F7"
                strokeWidth={1.6}
                drawDuration={1.1}
                fillDelay={0.15}
                stagger={0.04}
                trigger="scroll"
                fillMode="wipe"
                fontSize={56}
                fontWeight={800}
                letterSpacing={-2}
              />
            </h1>

            {/* Credible, truthful lead summary & subtext */}
            <p className="fc-hero-summary">
              Automated security auditing that leaves zero trace on your infrastructure.
            </p>
            <p className="fc-hero-subtext">
              <strong>Fire Crow</strong> runs <code>Semgrep</code>, <code>Gitleaks</code>, and{' '}
              <code>OSV-Scanner</code> inside <strong>ephemeral, zero-privilege Docker containers</strong>.
              Every confirmed finding is frozen into an <strong>immutable canonical audit ledger</strong> with CWE classifications,
              CVSS scores, line-level evidence, and deterministic remediation.
            </p>

            {/* Dual CTA group — leads to sign-in / sample walkthrough */}
            <div className="fc-hero-cta-group">
              <button onClick={onNavigateLogin} className="fc-btn-hero-primary" type="button">
                Audit Your Repository →
              </button>
              <a href="#preview" className="fc-btn-hero-secondary">
                Explore Sample Audit ↓
              </a>
            </div>

            {/* Real product flow */}
            <div className="fc-hero-steps" aria-label="How Fire Crow works">
              <span className="fc-step-item">
                <strong className="fc-step-num">01</strong> Sign in with GitHub
              </span>
              <span className="fc-step-sep" aria-hidden="true">
                <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 8h10M9 4l4 4-4 4" />
                </svg>
              </span>
              <span className="fc-step-item">
                <strong className="fc-step-num">02</strong> Submit repo + branch
              </span>
              <span className="fc-step-sep" aria-hidden="true">
                <svg width="13" height="13" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M3 8h10M9 4l4 4-4 4" />
                </svg>
              </span>
              <span className="fc-step-item">
                <strong className="fc-step-num">03</strong> Read canonical ledger
              </span>
            </div>

            {/* Miniature Glassic Telemetry HUD Strip */}
            <div className="fc-mini-glass-hud" aria-label="Live System Telemetry">
              <div className="fc-hud-chip">
                <span className="fc-hud-label">ENGINES</span>
                <span className="fc-hud-val">
                  <CountUp to={3} duration={1.2} /> ACTIVE
                </span>
              </div>
              <div className="fc-hud-chip">
                <span className="fc-hud-label">WALL TIME</span>
                <span className="fc-hud-val">
                  <CountUp to={3.2} decimals={2} duration={1.5} suffix="s" />
                </span>
              </div>
              <div className="fc-hud-chip">
                <span className="fc-hud-label">RETENTION</span>
                <span className="fc-hud-val">0 BITS</span>
              </div>
              <div className="fc-hud-chip">
                <span className="fc-hud-label">DETERMINISTIC</span>
                <span className="fc-hud-val">
                  <CountUp to={100} duration={1.4} suffix="%" />
                </span>
              </div>
            </div>
          </div>

          {/* Right Column: Live Interactive Security Terminal */}
          <div className="fc-hero-terminal-col">
            <SpotlightCard
              className="fc-terminal"
              spotlightColor="rgba(229, 72, 77, 0.22)"
              intensity={0.25}
              borderGlow={0.6}
              role="img"
              aria-label="Sample audit submission request showing the repository URL and branch fields"
            >
              <div className="fc-terminal-bar">
                <div className="fc-window-controls" aria-hidden="true">
                  <div className="fc-dot fc-dot-red" />
                  <div className="fc-dot fc-dot-yellow" />
                  <div className="fc-dot fc-dot-green" />
                </div>

                {/* Terminal Tab Switcher */}
                <div className="fc-terminal-tabs" role="tablist" aria-label="Terminal commands">
                  <button
                    type="button"
                    className={`fc-terminal-tab ${activeTab === 'curl' ? 'active' : ''}`}
                    onClick={() => setActiveTab('curl')}
                  >
                    cURL API
                  </button>
                  <button
                    type="button"
                    className={`fc-terminal-tab ${activeTab === 'cli' ? 'active' : ''}`}
                    onClick={() => setActiveTab('cli')}
                  >
                    CLI
                  </button>
                  <button
                    type="button"
                    className={`fc-terminal-tab ${activeTab === 'action' ? 'active' : ''}`}
                    onClick={() => setActiveTab('action')}
                  >
                    CI/CD
                  </button>
                </div>

                <button
                  type="button"
                  onClick={handleCopy}
                  className="fc-terminal-copy-btn"
                  title="Copy command to clipboard"
                  aria-label="Copy command snippet"
                >
                  {copied ? (
                    <span style={{ color: '#34D399', display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M20 6L9 17l-5-5" />
                      </svg>
                      Copied
                    </span>
                  ) : (
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px' }}>
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                        <path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
                      </svg>
                      Copy
                    </span>
                  )}
                </button>
              </div>

              <div className="fc-terminal-body">
                <div className="fc-terminal-lines">
                  <span className="fc-tok-comment"># Ephemeral containerized audit intake</span>{'\n'}
                  <span className="fc-tok-comment"># Zero code retention · read-only volume mounts</span>{'\n'}
                  {activeTab === 'curl' && (
                    <>
                      <span className="fc-tok-cmd">curl</span> <span className="fc-tok-flag">-X POST</span> <span className="fc-tok-url">/api/v1/audits</span> {'\\\n'}
                      {'  '}<span className="fc-tok-flag">-H</span> <span className="fc-tok-str">&quot;Content-Type: application/json&quot;</span> {'\\\n'}
                      {'  '}<span className="fc-tok-flag">-d</span> <span className="fc-tok-str">&apos;{'{'}</span>{'\n'}
                      {'    '}<span className="fc-tok-key">&quot;repo_url&quot;</span><span className="fc-tok-punct">: </span><span className="fc-tok-str">&quot;https://github.com/acme/core-api&quot;</span><span className="fc-tok-punct">,</span>{'\n'}
                      {'    '}<span className="fc-tok-key">&quot;branch&quot;</span><span className="fc-tok-punct">: </span><span className="fc-tok-str">&quot;main&quot;</span><span className="fc-tok-punct">,</span>{'\n'}
                      {'    '}<span className="fc-tok-key">&quot;commit_sha&quot;</span><span className="fc-tok-punct">: </span><span className="fc-tok-kw">null</span> <span className="fc-tok-comment"># or pin a 40-char SHA</span>{'\n'}
                      {'  '}<span className="fc-tok-str">&apos;</span>{'\n\n'}
                    </>
                  )}
                  {activeTab === 'cli' && (
                    <>
                      <span className="fc-tok-cmd">firecrow</span> <span className="fc-tok-flag">audit</span> <span className="fc-tok-str">https://github.com/acme/core-api</span> {'\\\n'}
                      {'  '}<span className="fc-tok-flag">--branch</span> <span className="fc-tok-str">main</span> {'\\\n'}
                      {'  '}<span className="fc-tok-flag">--scanners</span> <span className="fc-tok-key">gitleaks,semgrep,osv</span> {'\\\n'}
                      {'  '}<span className="fc-tok-flag">--fail-on</span> <span className="fc-tok-out">high,critical</span>{'\n\n'}
                    </>
                  )}
                  {activeTab === 'action' && (
                    <>
                      <span className="fc-tok-comment"># GitHub Actions Security Gate</span>{'\n'}
                      <span className="fc-tok-key">name</span><span className="fc-tok-punct">: </span><span className="fc-tok-str">FireCrow Security Audit</span>{'\n'}
                      <span className="fc-tok-key">steps</span><span className="fc-tok-punct">:</span>{'\n'}
                      {'  '}- <span className="fc-tok-key">uses</span><span className="fc-tok-punct">: </span><span className="fc-tok-url">nextlab/firecrow-action@v1</span>{'\n'}
                      {'    '}<span className="fc-tok-key">with</span><span className="fc-tok-punct">:</span>{'\n'}
                      {'      '}<span className="fc-tok-flag">fail_closed</span><span className="fc-tok-punct">: </span><span className="fc-tok-kw">true</span>{'\n\n'}
                    </>
                  )}
                  <span className="fc-tok-out">→ ephemeral micro-sandbox → canonical ledger → JSON / HTML / PDF</span>
                </div>
              </div>

              <div className="fc-terminal-note">
                <strong>Guaranteed boundaries:</strong>{' '}
                <DecryptedText
                  text="50MB unpack ceiling, --cap-drop=ALL, commit-SHA attestation."
                  speed={30}
                  animateOn="view"
                />
              </div>
            </SpotlightCard>
          </div>
        </div>

        {/* Interactive wordmark — the brand dissolves into dashed vector
            outlines under the pointer, like evidence under inspection. */}
        <div className="fc-wordmark-band">
          <TechText
            text="FIRE CROW"
            fontFamily='"Space Grotesk", "Inter", sans-serif'
            fontWeight={700}
            fontSize={150}
            letterSpacing={-0.03}
            color="#F2F4F7"
            accentColor="#E5484D"
            reveal="letter"
            reach={180}
            dashLength={4}
            dashGap={2}
            specks={12}
          />
        </div>

        {/* Verified Trust Strip */}
        <div className="fc-trust-strip" aria-label="Verified Security Architecture Highlights">
          <div className="fc-trust-item">
            <svg className="fc-trust-icon" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span>Tri-Engine Static &amp; Dependency Analysis</span>
          </div>

          <div className="fc-trust-item">
            <svg className="fc-trust-icon" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span>Ephemeral Docker Sandboxes (--cap-drop=ALL)</span>
          </div>

          <div className="fc-trust-item">
            <svg className="fc-trust-icon" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span>Deterministic Scoring Formula (0–100)</span>
          </div>

          <div className="fc-trust-item">
            <svg className="fc-trust-icon" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
            </svg>
            <span>Exportable PDF, HTML &amp; JSON Artifacts</span>
          </div>
        </div>
      </div>
    </section>
  );
}

export default HeroSection;
