import { NextLabSymbol } from './BrandLogos';
import TechText from './TechText';
import StrokeText from './StrokeText';

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
                fontSize={120}
                fontWeight={800}
                letterSpacing={-3}
              />
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
