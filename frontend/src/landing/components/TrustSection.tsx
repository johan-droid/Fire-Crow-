import { useState } from 'react';
import { Reveal } from './Reveal';
import { SpotlightCard } from './SpotlightCard';
import { ShinyText } from './ShinyText';
import { DecryptedText } from './DecryptedText';

export function TrustSection() {
  const [activeAssertion, setActiveAssertion] = useState<number | null>(null);

  const toggleAssertion = (index: number) => {
    setActiveAssertion(activeAssertion === index ? null : index);
  };

  return (
    <section id="trust" className="fc-section" aria-labelledby="trust-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow">
            <ShinyText text="OPERATIONAL HYGIENE // ARCHITECTURAL INTEGRITY" shineColor="#34D399" />
          </div>
          <h2 id="trust-heading" className="fc-section-title">
            Security Guarantees Grounded in Implementation
          </h2>
          <p className="fc-section-desc">
            We prioritize technical transparency over marketing hype. Here is our exact
            operational posture regarding code privacy, AI boundaries, and scanner telemetry.
          </p>
        </div>

        <div className="fc-trust-grid">
          {/* Card 1: Zero Retention (Emerald Accent) */}
          <Reveal className="fc-trust-card-wrap" delay={0}>
            <SpotlightCard
              className="fc-trust-card"
              spotlightColor="rgba(52, 211, 153, 0.22)"
              intensity={0.25}
              borderGlow={0.7}
              style={{ height: '100%', padding: '28px' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                <span className="fc-badge fc-badge-clean" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  <span className="fc-pulse-dot" style={{ background: '#34D399', boxShadow: '0 0 6px #34D399' }} aria-hidden="true" />
                  <DecryptedText text="ZERO RETENTION" speed={30} animateOn="view" />
                </span>
                <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.72rem', color: 'var(--fc-clean)' }}>
                  ISO / SOC-2 ALIGNED
                </span>
              </div>

              <h3 style={{ fontSize: '1.25rem', marginBottom: '10px', color: '#F2F4F7' }}>
                Ephemeral Container Isolation
              </h3>
              <p style={{ fontSize: '0.88rem', color: '#A6AEB9', lineHeight: 1.6, marginBottom: '16px' }}>
                Scanners run in disposable Docker containers with dropped Linux capabilities
                (<code>--cap-drop=ALL</code>) and read-only repository mounts. Source archives
                are destroyed immediately post-audit. Code is never retained, indexed, or shared.
              </p>

              <button
                type="button"
                className="fc-trust-verify-btn"
                onClick={() => toggleAssertion(0)}
                aria-expanded={activeAssertion === 0}
              >
                <span>{activeAssertion === 0 ? 'Hide assertion contract' : 'Inspect runtime assertion →'}</span>
              </button>

              {activeAssertion === 0 && (
                <div className="fc-trust-assertion-box">
                  <code>ASSERT: fs.destroy(tmp_workspace) ON EXIT</code>
                  <code>POLICY: read_only_mount=true · egress=blocked</code>
                </div>
              )}
            </SpotlightCard>
          </Reveal>

          {/* Card 2: Read-Only AI (Sky / Cyan Accent) */}
          <Reveal className="fc-trust-card-wrap" delay={100}>
            <SpotlightCard
              className="fc-trust-card"
              spotlightColor="rgba(56, 189, 248, 0.22)"
              intensity={0.25}
              borderGlow={0.7}
              style={{ height: '100%', padding: '28px' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                <span className="fc-badge fc-badge-low" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  <span className="fc-pulse-dot" style={{ background: '#38BDF8', boxShadow: '0 0 6px #38BDF8' }} aria-hidden="true" />
                  <DecryptedText text="READ-ONLY AI" speed={30} animateOn="view" />
                </span>
                <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.72rem', color: 'var(--fc-low)' }}>
                  DETERMINISTIC GUARD
                </span>
              </div>

              <h3 style={{ fontSize: '1.25rem', marginBottom: '10px', color: '#F2F4F7' }}>
                Strict Narrative Boundary
              </h3>
              <p style={{ fontSize: '0.88rem', color: '#A6AEB9', lineHeight: 1.6, marginBottom: '16px' }}>
                Audit findings and risk scores are mathematically frozen before passing to the AI
                narrative writer. LLM models produce executive summaries only—they have zero authority
                to invent, delete, or alter any finding or risk score.
              </p>

              <button
                type="button"
                className="fc-trust-verify-btn"
                onClick={() => toggleAssertion(1)}
                aria-expanded={activeAssertion === 1}
              >
                <span>{activeAssertion === 1 ? 'Hide assertion contract' : 'Inspect runtime assertion →'}</span>
              </button>

              {activeAssertion === 1 && (
                <div className="fc-trust-assertion-box">
                  <code>ASSERT: ledger.status === FROZEN</code>
                  <code>POLICY: allow_score_mutation=false · write_access=none</code>
                </div>
              )}
            </SpotlightCard>
          </Reveal>

          {/* Card 3: Honest Signals (Crimson Accent) */}
          <Reveal className="fc-trust-card-wrap" delay={200}>
            <SpotlightCard
              className="fc-trust-card"
              spotlightColor="rgba(229, 72, 77, 0.22)"
              intensity={0.25}
              borderGlow={0.7}
              style={{ height: '100%', padding: '28px' }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
                <span className="fc-badge fc-badge-critical" style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                  <span className="fc-pulse-dot" style={{ background: '#F04444', boxShadow: '0 0 6px #F04444' }} aria-hidden="true" />
                  <DecryptedText text="HONEST SIGNALS" speed={30} animateOn="view" />
                </span>
                <span style={{ fontFamily: 'var(--fc-font-mono)', fontSize: '0.72rem', color: 'var(--fc-critical)' }}>
                  ZERO FALSE PASSES
                </span>
              </div>

              <h3 style={{ fontSize: '1.25rem', marginBottom: '10px', color: '#F2F4F7' }}>
                Truthful Scanner Diagnostics
              </h3>
              <p style={{ fontSize: '0.88rem', color: '#A6AEB9', lineHeight: 1.6, marginBottom: '16px' }}>
                If a scanner tool experiences an error, timeout, or outage, Fire Crow reports{' '}
                <code>engine_unavailable</code> or <code>partial</code>. We never present a silent,
                artificial clean bill of health when a scan could not run.
              </p>

              <button
                type="button"
                className="fc-trust-verify-btn"
                onClick={() => toggleAssertion(2)}
                aria-expanded={activeAssertion === 2}
              >
                <span>{activeAssertion === 2 ? 'Hide assertion contract' : 'Inspect runtime assertion →'}</span>
              </button>

              {activeAssertion === 2 && (
                <div className="fc-trust-assertion-box">
                  <code>ASSERT: on_error -&gt; RFC9457(engine_unavailable)</code>
                  <code>POLICY: fail_closed=true · never_mask_outages=true</code>
                </div>
              )}
            </SpotlightCard>
          </Reveal>
        </div>
      </div>
    </section>
  );
}

