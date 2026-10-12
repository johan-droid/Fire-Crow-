import { Reveal } from './Reveal';

export function TrustSection() {
  return (
    <section id="trust" className="fc-section" aria-labelledby="trust-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow">OPERATIONAL HYGIENE // ARCHITECTURAL INTEGRITY</div>
          <h2 id="trust-heading" className="fc-section-title">
            Security Guarantees Grounded in Implementation
          </h2>
          <p className="fc-section-desc">
            We prioritize technical transparency over marketing hype. Here is our exact
            operational posture regarding code privacy, AI boundaries, and scanner telemetry.
          </p>
        </div>

        <div className="fc-trust-grid">
          <Reveal className="fc-trust-card" delay={0}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <span className="fc-badge fc-badge-low">ZERO RETENTION</span>
            </div>
            <h3>Ephemeral Container Isolation</h3>
            <p>
              Scanners run in disposable Docker containers with dropped Linux capabilities
              (<code>--cap-drop=ALL</code>) and read-only repository mounts. Source archives
              are destroyed immediately post-audit. Code is never retained, indexed, or shared.
            </p>
          </Reveal>

          <Reveal className="fc-trust-card" delay={100}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <span className="fc-badge fc-badge-high">READ-ONLY AI</span>
            </div>
            <h3>Strict Narrative Boundary</h3>
            <p>
              Audit findings and risk scores are mathematically frozen before passing to the AI
              narrative writer. LLM models produce executive summaries only—they have zero authority
              to invent, delete, or alter any finding or risk score.
            </p>
          </Reveal>

          <Reveal className="fc-trust-card" delay={200}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
              <span className="fc-badge fc-badge-critical">HONEST SIGNALS</span>
            </div>
            <h3>Truthful Scanner Diagnostics</h3>
            <p>
              If a scanner tool experiences an error, timeout, or outage, Fire Crow reports
              <code>engine_unavailable</code> or <code>partial</code>. We never present a silent,
              artificial clean bill of health when a scan could not run.
            </p>
          </Reveal>
        </div>
      </div>
    </section>
  );
}
