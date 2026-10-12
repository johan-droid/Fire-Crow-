import { NextLabSymbol } from './BrandLogos';

interface HeroSectionProps {
  onNavigateLogin: () => void;
}

export function HeroSection({ onNavigateLogin }: HeroSectionProps) {
  return (
    <section className="fc-hero" aria-labelledby="hero-heading">
      <div className="fc-container">
        <div className="fc-hero-layout">
          {/* Copy column */}
          <div className="fc-hero-copy">
            {/* NEXT LAB.inc endorsement badge */}
            <div className="fc-eyebrow-pill" aria-label="Endorsement by NEXT LAB.inc">
              <span className="fc-brand-micro-tag">
                <NextLabSymbol size={14} />
                <span>NEXT LAB.inc</span>
              </span>
              <span className="fc-eyebrow-sep" aria-hidden="true">/</span>
              <span className="fc-eyebrow-text">Flagship Repository Security Auditing</span>
            </div>

            {/* High-impact Fire Crow headline */}
            <h1 id="hero-heading" className="fc-hero-headline">
              Engineering-first security auditing.<br />
              <span className="fc-hero-subhead">
                Know what&apos;s in your repo before <span className="fc-accent">attackers do.</span>
              </span>
            </h1>

            {/* Credible, truthful subtext */}
            <p className="fc-hero-subtext">
              <strong>Fire Crow</strong> runs <code>Semgrep</code>, <code>Gitleaks</code>, and{' '}
              <code>OSV-Scanner</code> inside ephemeral, zero-privilege Docker containers.
              Every confirmed finding is frozen into a canonical audit ledger with CWE classifications,
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
              <span><strong>01</strong> Sign in with GitHub</span>
              <span className="fc-step-sep" aria-hidden="true">→</span>
              <span><strong>02</strong> Submit repo + branch</span>
              <span className="fc-step-sep" aria-hidden="true">→</span>
              <span><strong>03</strong> Read canonical ledger</span>
            </div>
          </div>

          {/* Glass terminal — the exact shape the console submits */}
          <div className="fc-terminal" role="img" aria-label="Sample audit submission request showing the repository URL and branch fields">
            <div className="fc-terminal-bar">
              <div className="fc-window-controls" aria-hidden="true">
                <div className="fc-dot fc-dot-red" />
                <div className="fc-dot fc-dot-yellow" />
                <div className="fc-dot fc-dot-green" />
              </div>
              <span className="fc-terminal-title">audit-submit.sh // NEXT LAB ENGINE</span>
              <span className="fc-terminal-live">
                <span className="fc-pulse-dot" style={{ background: '#10b981', boxShadow: '0 0 6px #10b981' }} aria-hidden="true" />
                API CONTRACT
              </span>
            </div>
            <div className="fc-terminal-body">
              <span className="fc-tok-comment"># Ephemeral containerized audit intake</span>{'\n'}
              <span className="fc-tok-comment"># Zero code retention · read-only volume mounts</span>{'\n'}
              <span className="fc-tok-cmd">curl</span> <span className="fc-tok-flag">-X POST</span> /api/v1/audit/submit {'\\\n'}
              {'  '}<span className="fc-tok-flag">-H</span> <span className="fc-tok-str">&quot;Content-Type: application/json&quot;</span> {'\\\n'}
              {'  '}<span className="fc-tok-flag">-d</span> <span className="fc-tok-str">&apos;{'{'}</span>{'\n'}
              {'    '}<span className="fc-tok-key">&quot;repo_url&quot;</span><span className="fc-tok-str">: &quot;https://github.com/acme/api&quot;,</span>{'\n'}
              {'    '}<span className="fc-tok-key">&quot;repo_branch&quot;</span><span className="fc-tok-str">: &quot;main&quot;,</span>{'\n'}
              {'    '}<span className="fc-tok-key">&quot;commit_sha&quot;</span><span className="fc-tok-str">: null  </span><span className="fc-tok-comment"># or pin a 40-char commit SHA</span>{'\n'}
              {'  '}<span className="fc-tok-str">&apos;</span>{'\n\n'}
              <span className="fc-tok-out">→ ephemeral micro-sandbox → canonical ledger → JSON / HTML / PDF</span>
            </div>
            <div className="fc-terminal-note">
              <strong>Guaranteed boundaries:</strong> 50MB unpack ceiling, --cap-drop=ALL, commit-SHA attestation.
            </div>
          </div>
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
