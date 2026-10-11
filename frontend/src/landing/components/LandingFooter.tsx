export function LandingFooter() {
  const scrollToTop = () => {
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  return (
    <footer className="fc-footer" aria-label="Footer">
      <div className="fc-container">
        <div className="fc-footer-grid">
          {/* Brand Info */}
          <div className="fc-footer-brand">
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <img src="/fire-crow-logo.png" alt="Fire Crow Logo" style={{ width: '28px', height: '28px', borderRadius: '6px' }} />
              <span style={{ fontSize: '1.05rem', fontWeight: 700, color: '#ffffff' }}>Fire Crow</span>
            </div>
            <p>
              Containerized repository security auditing platform providing deterministic findings,
              ephemeral sandbox isolation, and verified remediation guidance.
            </p>
          </div>

          {/* Navigation Links */}
          <div>
            <div className="fc-footer-col-title">Platform</div>
            <ul className="fc-footer-links">
              <li><a href="#capabilities">Capabilities</a></li>
              <li><a href="#workflow">Architecture</a></li>
              <li><a href="#preview">Audit Preview</a></li>
              <li><a href="#pricing">Pricing Plans</a></li>
            </ul>
          </div>

          {/* Developer Resources */}
          <div>
            <div className="fc-footer-col-title">Developers</div>
            <ul className="fc-footer-links">
              <li>
                <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer">
                  GitHub Repository ↗
                </a>
              </li>
              <li>
                <a href="https://github.com/johan-droid/Fire-Crow-#readme" target="_blank" rel="noreferrer">
                  Documentation ↗
                </a>
              </li>
              <li><a href="#faq">Technical FAQ</a></li>
            </ul>
          </div>

          {/* Security & Architecture Guarantees */}
          <div>
            <div className="fc-footer-col-title">Architecture</div>
            <ul className="fc-footer-links">
              <li><span>Docker Sandbox Isolation</span></li>
              <li><span>--cap-drop=ALL Privileges</span></li>
              <li><span>Zero Code Retention</span></li>
              <li><span>Deterministic Scoring Formula</span></li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="fc-footer-bottom">
          <div>
            © {new Date().getFullYear()} Fire Crow Security Intelligence. All rights reserved.
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '0.76rem', color: 'var(--fc-clean)' }}>
              <span className="fc-pulse-dot" style={{ background: '#10b981', boxShadow: '0 0 6px #10b981' }} aria-hidden="true" />
              Engine Operational
            </span>
            <button onClick={scrollToTop} className="fc-footer-back-top" aria-label="Scroll back to top">
              ↑ Back to top
            </button>
          </div>
        </div>
      </div>
    </footer>
  );
}
