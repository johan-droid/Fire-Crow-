interface HeroSectionProps {
  onNavigateLogin: () => void;
}

export function HeroSection({ onNavigateLogin }: HeroSectionProps) {
  return (
    <section className="fc-hero" aria-labelledby="hero-heading">
      <div className="fc-container">
        {/* Eyebrow badge */}
        <div className="fc-eyebrow-pill">
          <span className="fc-pulse-dot" aria-hidden="true" />
          <span>Containerized Repository Security Auditing</span>
        </div>

        {/* High-impact headline */}
        <h1 id="hero-heading" className="fc-hero-headline">
          Automated Repository Auditing.<br />
          <span className="fc-accent">Deterministic Findings. Zero Noise.</span>
        </h1>

        {/* Credible, truthful subtext */}
        <p className="fc-hero-subtext">
          Fire Crow orchestrates Semgrep, Gitleaks, and OSV-Scanner inside ephemeral,
          zero-privilege containers. Obtain structured canonical audit ledgers, precise CWE anchors,
          and actionable remediation guidance—backed by mathematical risk scoring.
        </p>

        {/* Dual CTA group */}
        <div className="fc-hero-cta-group">
          <button onClick={onNavigateLogin} className="fc-btn-hero-primary">
            Audit Your Repository →
          </button>
          <a href="#preview" className="fc-btn-hero-secondary">
            Explore Sample Audit ↓
          </a>
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
