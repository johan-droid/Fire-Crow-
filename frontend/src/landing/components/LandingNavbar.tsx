import { useState, useEffect } from 'react';
import { BrandLockup } from './BrandLogos';

interface LandingNavbarProps {
  user?: { username: string; email?: string | null; credit_balance?: number } | null;
  onNavigateLogin: () => void;
}

export function LandingNavbar({ user, onNavigateLogin }: LandingNavbarProps) {
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isMobileMenuOpen) {
        setIsMobileMenuOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isMobileMenuOpen]);

  const closeMenu = () => setIsMobileMenuOpen(false);

  return (
    <nav className="fc-nav" aria-label="Main Navigation">
      <div className="fc-container fc-nav-container">
        {/* Brand Lockup: Fire Crow as product, NEXT LAB.inc as parent */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <a href="#top" className="fc-logo-group" onClick={closeMenu} aria-label="Fire Crow by NEXT LAB.inc Homepage">
            <BrandLockup compact={false} />
          </a>
          <a href="#workflow" className="fc-nav-status-pill" title="All 3 scanning engines healthy & operational">
            <span className="fc-pulse-dot" style={{ background: '#10B981', boxShadow: 'none', width: '5px', height: '5px' }} aria-hidden="true" />
            <span>FLEET ONLINE</span>
          </a>
        </div>

        {/* Desktop Links */}
        <div className="fc-nav-links">
          <a href="#capabilities" className="fc-nav-link">Capabilities</a>
          <a href="#workflow" className="fc-nav-link">Architecture</a>
          <a href="#preview" className="fc-nav-link">Walkthrough</a>
          <a href="#pricing" className="fc-nav-link">Enterprise</a>
          <a href="#studio" className="fc-nav-link">Studio</a>
          <a href="#faq" className="fc-nav-link">FAQ</a>
          <a
            href="https://github.com/johan-droid/Fire-Crow-"
            target="_blank"
            rel="noreferrer"
            className="fc-nav-link fc-nav-github"
            style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
              <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
            </svg>
            GitHub
          </a>
        </div>

        {/* Desktop Actions */}
        <div className="fc-nav-actions">
          {user ? (
            <span className="fc-nav-link" style={{ cursor: 'default', color: '#FFFFFF', fontWeight: 500 }}>
              {user.username}
            </span>
          ) : (
            <button onClick={onNavigateLogin} className="fc-nav-link fc-nav-signin-link" type="button">
              Sign In
            </button>
          )}
          <button onClick={onNavigateLogin} className="fc-btn-primary" type="button">
            Launch Console →
          </button>

          {/* Mobile Hamburger Toggle */}
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="fc-mobile-toggle"
            aria-label="Toggle navigation menu"
            aria-expanded={isMobileMenuOpen}
            type="button"
          >
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              {isMobileMenuOpen ? (
                <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
              ) : (
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
              )}
            </svg>
          </button>
        </div>
      </div>

      {/* Accessible Mobile Menu Drawer */}
      {isMobileMenuOpen && (
        <div className="fc-mobile-drawer open" id="mobile-navigation" role="region" aria-label="Mobile Navigation">
          <a href="#capabilities" onClick={closeMenu}>Capabilities</a>
          <a href="#workflow" onClick={closeMenu}>Architecture</a>
          <a href="#preview" onClick={closeMenu}>Walkthrough</a>
          <a href="#pricing" onClick={closeMenu}>Enterprise</a>
          <a href="#studio" onClick={closeMenu}>Studio</a>
          <a href="#faq" onClick={closeMenu}>FAQ</a>
          <a href="https://github.com/johan-droid/Fire-Crow-" target="_blank" rel="noreferrer" onClick={closeMenu}>
            GitHub Repository ↗
          </a>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
            {user ? (
              <div style={{ textAlign: 'center', fontSize: '0.85rem', color: '#A1A1AA', padding: '6px 0' }}>
                Signed in as <strong style={{ color: '#FFFFFF' }}>{user.username}</strong>
              </div>
            ) : (
              <button
                onClick={() => {
                  closeMenu();
                  onNavigateLogin();
                }}
                className="fc-btn-ghost"
                style={{ width: '100%', justifyContent: 'center' }}
                type="button"
              >
                Sign In
              </button>
            )}
            <button
              onClick={() => {
                closeMenu();
                onNavigateLogin();
              }}
              className="fc-btn-primary"
              style={{ width: '100%', justifyContent: 'center' }}
              type="button"
            >
              Launch Console →
            </button>
          </div>
        </div>
      )}
    </nav>
  );
}
