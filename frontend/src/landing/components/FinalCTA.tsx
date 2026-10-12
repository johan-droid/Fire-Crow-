import { useState } from 'react';
import { NextLabSymbol } from './BrandLogos';
import { SpotlightCard } from './SpotlightCard';
import { ShinyText } from './ShinyText';

interface FinalCTAProps {
  onNavigateLogin: () => void;
}

export function FinalCTA({ onNavigateLogin }: FinalCTAProps) {
  const [copiedCli, setCopiedCli] = useState(false);
  const cliInstallCmd = 'curl -sSL https://raw.githubusercontent.com/johan-droid/Fire-Crow-/main/install.sh | bash';

  const handleCopyCli = () => {
    navigator.clipboard?.writeText(cliInstallCmd);
    setCopiedCli(true);
    setTimeout(() => setCopiedCli(false), 2000);
  };

  return (
    <section className="fc-section" style={{ borderBottom: 'none', paddingBottom: '40px' }} aria-labelledby="cta-heading">
      <div className="fc-container">
        <SpotlightCard
          className="fc-final-cta-card"
          spotlightColor="rgba(229, 72, 77, 0.28)"
          intensity={0.35}
          borderGlow={0.9}
          style={{ padding: '48px 32px', textAlign: 'center' }}
        >
          <div className="fc-cta-brand-tag" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginBottom: '16px' }}>
            <NextLabSymbol size={16} />
            <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.74rem', color: 'var(--fc-warm-muted)', letterSpacing: '0.06em' }}>
              <ShinyText text="NEXT LAB // FIRE CROW SECURITY" shineColor="#E5484D" />
            </span>
          </div>

          <h2 id="cta-heading" className="fc-cta-title" style={{ fontSize: '2.4rem', marginBottom: '12px' }}>
            Ready to audit your repository?
          </h2>
          <p className="fc-cta-sub" style={{ maxWidth: '600px', margin: '0 auto 24px', fontSize: '1rem', color: '#A6AEB9' }}>
            Run multi-engine static analysis, dependency vulnerability scanning, and secret detection
            in isolated containers. Receive deterministic audit reports in seconds.
          </p>

          {/* Quick CLI command teaser */}
          <div className="fc-final-cli-teaser" style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '12px',
            background: 'rgba(0, 0, 0, 0.45)',
            border: '1px solid rgba(255, 255, 255, 0.1)',
            padding: '8px 16px',
            borderRadius: '8px',
            marginBottom: '28px',
            maxWidth: '100%',
            overflowX: 'auto',
          }}>
            <span style={{ color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)', fontSize: '0.78rem' }}>$</span>
            <code style={{ color: '#F2F4F7', fontFamily: 'var(--fc-font-mono)', fontSize: '0.8rem' }}>
              {cliInstallCmd}
            </code>
            <button
              type="button"
              onClick={handleCopyCli}
              className="fc-terminal-copy-btn"
              style={{ fontSize: '0.72rem', padding: '3px 8px' }}
              title="Copy quick-install CLI command"
            >
              {copiedCli ? '✓ Copied' : 'Copy'}
            </button>
          </div>

          <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', flexWrap: 'wrap' }}>
            <button onClick={onNavigateLogin} className="fc-btn-hero-primary" type="button">
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

          {/* Guaranteed Security Badge Strip */}
          <div style={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            gap: '16px',
            flexWrap: 'wrap',
            marginTop: '32px',
            fontSize: '0.76rem',
            fontFamily: 'var(--fc-font-mono)',
            color: 'var(--fc-warm-subtle)',
          }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
              <span className="fc-pulse-dot" style={{ background: '#34D399', boxShadow: '0 0 6px #34D399' }} aria-hidden="true" />
              TRI-ENGINE ONLINE
            </span>
            <span>·</span>
            <span>0 REPO CODE RETENTION</span>
            <span>·</span>
            <span>DETERMINISTIC 0–100 SCORING</span>
          </div>
        </SpotlightCard>
      </div>
    </section>
  );
}

