import { NextLabSymbol, FireCrowSymbol } from './BrandLogos';
import { Reveal } from './Reveal';
import { SpotlightCard } from './SpotlightCard';
import { ShinyText } from './ShinyText';

export function NextLabBrandSection() {
  return (
    <section className="fc-section fc-brand-studio-section" aria-labelledby="studio-heading">
      <div className="fc-container">
        {/* Editorial Brand Header */}
        <div className="fc-section-header fc-section-header-left">
          <div className="fc-brand-endorsement-pill">
            <NextLabSymbol size={16} />
            <span>
              <ShinyText text="PARENT COMPANY & ENGINEERING STUDIO" shineColor="#E5484D" />
            </span>
          </div>

          <h2 id="studio-heading" className="fc-section-title" style={{ textAlign: 'left' }}>
            Engineering tools for what comes next.
          </h2>

          <p className="fc-section-desc" style={{ maxWidth: '600px', margin: '0', textAlign: 'left' }}>
            <strong>Next Lab</strong> is an independent, engineering-first software studio.
            We build precise, developer-centric tools designed to make complex systems more secure,
            transparent, and mathematically verifiable. Fire Crow is our flagship security auditing product.
          </p>
        </div>

        {/* 3 Engineering Pillars wrapped in SpotlightCard */}
        <div className="fc-studio-pillars-grid">
          <Reveal className="fc-studio-card-wrap" delay={0}>
            <SpotlightCard
              className="fc-studio-card"
              spotlightColor="rgba(242, 244, 247, 0.14)"
              intensity={0.22}
              borderGlow={0.6}
              style={{ height: '100%', padding: '26px', display: 'flex', flexDirection: 'column' }}
            >
              <div className="fc-studio-card-head">
                <span className="fc-studio-idx">01</span>
                <span className="fc-studio-tag">DETERMINISTIC SYSTEMS</span>
              </div>
              <h3 className="fc-studio-title">Zero black boxes</h3>
              <p className="fc-studio-p">
                We reject opaque, hand-waving claims. In Fire Crow, every risk score is calculated via an
                open formula, every finding is linked to line-level evidence and authoritative CWE identifiers,
                and audits are strictly reproducible.
              </p>
              <div className="fc-studio-meta">
                <code>formula: 100 - Σ(severity_weights)</code>
              </div>
            </SpotlightCard>
          </Reveal>

          <Reveal className="fc-studio-card-wrap" delay={100}>
            <SpotlightCard
              className="fc-studio-card"
              spotlightColor="rgba(229, 72, 77, 0.16)"
              intensity={0.22}
              borderGlow={0.6}
              style={{ height: '100%', padding: '26px', display: 'flex', flexDirection: 'column' }}
            >
              <div className="fc-studio-card-head">
                <span className="fc-studio-idx">02</span>
                <span className="fc-studio-tag">ZERO TRUST RUNTIME</span>
              </div>
              <h3 className="fc-studio-title">Ephemeral sandbox isolation</h3>
              <p className="fc-studio-p">
                Developer tools must never compromise the systems they audit. Fire Crow runs scanners in
                disposable containers stripped of Linux capabilities (<code>--cap-drop=ALL</code>), mounting code
                strictly read-only and discarding containers instantly.
              </p>
              <div className="fc-studio-meta">
                <code>privileges: dropped · network: airgapped</code>
              </div>
            </SpotlightCard>
          </Reveal>

          <Reveal className="fc-studio-card-wrap" delay={200}>
            <SpotlightCard
              className="fc-studio-card"
              spotlightColor="rgba(56, 189, 248, 0.14)"
              intensity={0.22}
              borderGlow={0.6}
              style={{ height: '100%', padding: '26px', display: 'flex', flexDirection: 'column' }}
            >
              <div className="fc-studio-card-head">
                <span className="fc-studio-idx">03</span>
                <span className="fc-studio-tag">STUDIO ECOSYSTEM</span>
              </div>
              <h3 className="fc-studio-title">Architected for multiple tools</h3>
              <p className="fc-studio-p">
                Fire Crow adopts Next Lab’s unified visual grammar—precise grids, fine borders,
                layered surfaces, and purposeful motion. As the studio releases additional developer tools,
                they share this foundation.
              </p>
              <div className="fc-studio-meta">
                <code>ecosystem: NEXT LAB // Fire Crow</code>
              </div>
            </SpotlightCard>
          </Reveal>
        </div>

        {/* Studio Architecture Blueprint Bar */}
        <Reveal className="fc-studio-blueprint" delay={150}>
          <div className="fc-blueprint-left">
            <div className="fc-blueprint-brand">
              <NextLabSymbol size={20} />
              <div>
                <span className="fc-blueprint-parent">NEXT LAB</span>
                <span className="fc-blueprint-sub">Independent Developer Tools</span>
              </div>
            </div>

            <div className="fc-blueprint-arrow" aria-hidden="true">
              <span>→</span>
            </div>

            <div className="fc-blueprint-product">
              <FireCrowSymbol size={28} />
              <div>
                <span className="fc-blueprint-prod-title">Fire Crow</span>
                <span className="fc-blueprint-prod-tag">Flagship Security Auditing Tool</span>
              </div>
            </div>
          </div>

          <div className="fc-blueprint-right">
            <div className="fc-blueprint-stat">
              <span className="fc-bp-label">PARADIGM</span>
              <span className="fc-bp-value">Containerized SAST &amp; CVE</span>
            </div>
            <div className="fc-blueprint-stat">
              <span className="fc-bp-label">DATA POLICY</span>
              <span className="fc-bp-value">Zero Code Retention</span>
            </div>
            <div className="fc-blueprint-stat">
              <span className="fc-bp-label">INTELLIGENCE</span>
              <span className="fc-bp-value">Read-Only AI Summaries</span>
            </div>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
