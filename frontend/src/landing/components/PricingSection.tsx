import { useState } from 'react';
import { PRICING_TIERS, type PricingTier } from '../data/landingData';

interface PricingSectionProps {
  user: { user_id: string; username: string } | null;
  onNavigateLogin: () => void;
  onInitiateCheckout: (amount: number, packageName: string) => void;
}

export function PricingSection({ user, onNavigateLogin, onInitiateCheckout }: PricingSectionProps) {
  const [billingCycle, setBillingCycle] = useState<'monthly' | 'annual'>('monthly');

  const handlePlanAction = (tier: PricingTier) => {
    const amount = billingCycle === 'annual' ? tier.priceAnnual : tier.priceMonthly;
    if (user) {
      onInitiateCheckout(amount, tier.id);
    } else {
      onNavigateLogin();
    }
  };

  return (
    <section id="pricing" className="fc-section" aria-labelledby="pricing-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow">Transparent Pricing</div>
          <h2 id="pricing-heading" className="fc-section-title">
            Predictable Auditing Capacity for Every Stage
          </h2>
          <p className="fc-section-desc">
            Deploy automated repository security audits with containerized execution,
            canonical findings ledgers, and exportable compliance reports.
          </p>
        </div>

        {/* Billing Cycle Toggle */}
        <div className="fc-billing-toggle-wrap">
          <span style={{ fontSize: '0.84rem', color: billingCycle === 'monthly' ? '#ffffff' : 'var(--fc-text-muted)', fontWeight: 600 }}>
            Monthly
          </span>
          <div className="fc-billing-toggle" role="group" aria-label="Billing cycle selection">
            <button
              type="button"
              className={`fc-billing-toggle-btn ${billingCycle === 'monthly' ? 'active' : ''}`}
              onClick={() => setBillingCycle('monthly')}
            >
              Monthly
            </button>
            <button
              type="button"
              className={`fc-billing-toggle-btn ${billingCycle === 'annual' ? 'active' : ''}`}
              onClick={() => setBillingCycle('annual')}
            >
              Annual <span className="fc-discount-tag">Save 20%</span>
            </button>
          </div>
          <span style={{ fontSize: '0.84rem', color: billingCycle === 'annual' ? '#ffffff' : 'var(--fc-text-muted)', fontWeight: 600 }}>
            Annual
          </span>
        </div>

        {/* Pricing Cards Grid */}
        <div className="fc-pricing-grid">
          {PRICING_TIERS.map((tier) => {
            const price = billingCycle === 'annual' ? tier.priceAnnual : tier.priceMonthly;
            return (
              <div
                key={tier.id}
                className={`fc-pricing-card ${tier.popular ? 'popular' : ''}`}
              >
                {tier.popular && <span className="fc-popular-badge">Most Popular</span>}

                <div>
                  <h3 className="fc-plan-name">{tier.name}</h3>
                  <p className="fc-plan-tagline">{tier.tagline}</p>

                  <div className="fc-price-row">
                    <span className="fc-price-val">${price}</span>
                    <span className="fc-price-period">/ month {billingCycle === 'annual' ? '(billed annually)' : ''}</span>
                  </div>

                  <ul className="fc-features-list" aria-label={`Features included in ${tier.name} plan`}>
                    {tier.features.map((feat) => (
                      <li key={feat.text} className={`fc-feature-item ${feat.highlight ? 'highlight' : ''}`}>
                        <svg className="fc-feature-check" viewBox="0 0 20 20" fill="currentColor" aria-hidden="true">
                          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                        </svg>
                        <span>{feat.text}</span>
                      </li>
                    ))}
                  </ul>
                </div>

                <button
                  type="button"
                  onClick={() => handlePlanAction(tier)}
                  className={tier.popular ? 'fc-btn-primary' : 'fc-btn-ghost'}
                  style={{ width: '100%', justifyContent: 'center', padding: '12px 18px', fontSize: '0.88rem' }}
                >
                  {user ? `Upgrade to ${tier.name}` : tier.ctaLabel}
                </button>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
