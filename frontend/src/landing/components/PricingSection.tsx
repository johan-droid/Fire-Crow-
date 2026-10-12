import { useState } from 'react';
import { SpotlightCard } from './SpotlightCard';
import { ShinyText } from './ShinyText';

interface PricingSectionProps {
  user?: { user_id: string; username: string } | null;
  onNavigateLogin: () => void;
  onInitiateCheckout?: (amount: number, packageName: string) => void;
}

export function PricingSection({ onNavigateLogin }: PricingSectionProps) {
  const [email, setEmail] = useState('');
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email.trim()) {
      setSubmitted(true);
    }
  };

  return (
    <section id="pricing" className="fc-section fc-enterprise-section" aria-labelledby="enterprise-heading">
      <div className="fc-container">
        <SpotlightCard
          className="fc-enterprise-card"
          spotlightColor="rgba(229, 72, 77, 0.20)"
          intensity={0.24}
          borderGlow={0.65}
        >
          <div className="fc-enterprise-content">
            <div className="fc-section-eyebrow" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginBottom: '14px' }}>
              <span className="fc-pulse-dot" style={{ background: '#34D399', boxShadow: 'none', width: '6px', height: '6px' }} aria-hidden="true" />
              <ShinyText text="ENTERPRISE AUDITING // DEDICATED CAPACITY" shineColor="#E5484D" />
            </div>

            <h2 id="enterprise-heading" className="fc-enterprise-title">
              Custom Capacity &amp; On-Premise Deployments
            </h2>

            <p className="fc-enterprise-desc">
              Self-serve subscription billing is paused while we onboard dedicated enterprise clusters.
              Run containerized audits within your own VPC or request custom multi-repository capacity
              with zero code retention, custom Semgrep rule manifests, and guaranteed execution SLAs.
            </p>

            {/* Enterprise Guarantees Grid */}
            <div className="fc-enterprise-specs-grid">
              <div className="fc-enterprise-spec-item">
                <span className="fc-spec-icon" aria-hidden="true">
                  <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </span>
                <div>
                  <strong>Air-Gapped Runners</strong>
                  <span>Private VPC &amp; on-premise Docker micro-sandboxes</span>
                </div>
              </div>

              <div className="fc-enterprise-spec-item">
                <span className="fc-spec-icon" aria-hidden="true">
                  <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </span>
                <div>
                  <strong>Custom Rule Governance</strong>
                  <span>Bespoke Semgrep manifests and secret regex policies</span>
                </div>
              </div>

              <div className="fc-enterprise-spec-item">
                <span className="fc-spec-icon" aria-hidden="true">
                  <svg width="18" height="18" viewBox="0 0 20 20" fill="currentColor">
                    <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                  </svg>
                </span>
                <div>
                  <strong>Dedicated Security Lead</strong>
                  <span>Deterministic remediation advisory and audit SLA</span>
                </div>
              </div>
            </div>

            {/* Waitlist / Enterprise Request Form */}
            <div className="fc-enterprise-actions">
              {submitted ? (
                <div className="fc-enterprise-success">
                  <span style={{ color: '#34D399', fontWeight: 600 }}>✓ Request received.</span>
                  <span style={{ color: '#CBD5E1' }}>Our engineering team will reach out with VPC onboarding details.</span>
                </div>
              ) : (
                <form onSubmit={handleSubmit} className="fc-enterprise-form">
                  <input
                    type="email"
                    required
                    placeholder="name@organization.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="fc-enterprise-input"
                    aria-label="Work email for enterprise access"
                  />
                  <button type="submit" className="fc-btn-primary">
                    Request Enterprise Access →
                  </button>
                  <button
                    type="button"
                    onClick={onNavigateLogin}
                    className="fc-btn-ghost"
                  >
                    Open Console
                  </button>
                </form>
              )}
            </div>
          </div>
        </SpotlightCard>
      </div>
    </section>
  );
}

export default PricingSection;
