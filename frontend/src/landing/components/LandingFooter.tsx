import { FireCrowSymbol, NextLabSymbol } from './BrandLogos';

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
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
              <FireCrowSymbol size={28} />
              <div>
                <span style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f5f4ef', display: 'block', lineHeight: 1.1 }}>
                  Fire Crow
                </span>
                <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.66rem', color: 'var(--fc-warm-subtle)', letterSpacing: '0.04em' }}>
                  BY NEXT LAB.inc
                </span>
              </div>
            </div>

            <p style={{ marginTop: '14px', fontSize: '0.86rem', color: 'var(--fc-warm-muted)', lineHeight: 1.6 }}>
              Independent, engineering-first security auditing. Fire Crow freezes verified findings
              into deterministic audit ledgers using ephemeral container isolation and multi-engine orchestration.
            </p>

            <div className="fc-footer-studio-badge" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', marginTop: '16px' }}>
              <NextLabSymbol size={16} />
              <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.72rem', color: 'var(--fc-warm-muted)' }}>
                NEXT LAB.inc // ENGINEERING STUDIO
              </span>
            </div>
          </div>

          {/* Platform Links */}
          <div>
            <div className="fc-footer-col-title">Platform</div>
            <ul className="fc-footer-links">
              <li><a href="#capabilities">Capabilities</a></li>
              <li><a href="#workflow">Architecture</a></li>
              <li><a href="#preview">Audit Walkthrough</a></li>
              <li><a href="#pricing">Pricing Plans</a></li>
              <li><a href="#faq">Technical FAQ</a></li>
            </ul>
          </div>

          {/* Parent Company Ecosystem */}
          <div>
            <div className="fc-footer-col-title">NEXT LAB.inc</div>
            <ul className="fc-footer-links">
              <li><a href="#studio">Engineering Studio</a></li>
              <li><a href="#studio">Zero Black Boxes</a></li>
              <li><a href="#studio">Zero Code Retention</a></li>
              <li><a href="#trust">Integrity Guarantees</a></li>
              <li><a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer">Open Ecosystem ↗</a></li>
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
              <li>
                <a href="https://github.com/johan-droid/Fire-Crow-/issues" target="_blank" rel="noreferrer">
                  Issue Tracker ↗
                </a>
              </li>
              <li>
                <a href="#faq">Scanner Support</a>
              </li>
            </ul>
          </div>

          {/* Architectural Guarantees */}
          <div>
            <div className="fc-footer-col-title">Architecture</div>
            <ul className="fc-footer-links">
              <li><span>Docker Micro-Sandboxes</span></li>
              <li><span>--cap-drop=ALL Isolation</span></li>
              <li><span>Zero Code Retention</span></li>
              <li><span>Deterministic Scoring (0–100)</span></li>
              <li><span>Read-Only AI Boundaries</span></li>
            </ul>
          </div>
        </div>

        {/* Bottom Bar */}
        <div className="fc-footer-bottom">
          <div style={{ fontSize: '0.78rem', color: 'var(--fc-warm-subtle)' }}>
            © {new Date().getFullYear()} <strong>NEXT LAB.inc</strong>. Fire Crow is a flagship security product by NEXT LAB.inc. All rights reserved.
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
            <a
              href="https://github.com/johan-droid/Fire-Crow-"
              target="_blank"
              rel="noreferrer"
              style={{ fontSize: '0.78rem', color: 'var(--fc-warm-muted)', textDecoration: 'none' }}
            >
              Source-available on GitHub ↗
            </a>
            <button onClick={scrollToTop} className="fc-footer-back-top" aria-label="Scroll back to top" type="button">
              ↑ Back to top
            </button>
          </div>
        </div>
      </div>
    </footer>
  );
}
