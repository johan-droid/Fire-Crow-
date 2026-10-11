interface FinalCTAProps {
  onNavigateLogin: () => void;
}

export function FinalCTA({ onNavigateLogin }: FinalCTAProps) {
  return (
    <section className="fc-section" style={{ borderBottom: 'none', paddingBottom: '40px' }} aria-labelledby="cta-heading">
      <div className="fc-container">
        <div className="fc-final-cta-card">
          <h2 id="cta-heading" className="fc-cta-title">
            Ready to audit your repository?
          </h2>
          <p className="fc-cta-sub">
            Run multi-engine static analysis, dependency vulnerability scanning, and secret detection
            in isolated containers. Receive deterministic audit reports in seconds.
          </p>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <button onClick={onNavigateLogin} className="fc-btn-hero-primary">
              Launch Security Console →
            </button>
            <a
              href="https://github.com/johan-droid/Fire-Crow-"
              target="_blank"
              rel="noreferrer"
              className="fc-btn-hero-secondary"
            >
              Explore on GitHub ↗
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
