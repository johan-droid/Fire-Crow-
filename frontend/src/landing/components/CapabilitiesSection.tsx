import { CAPABILITIES } from '../data/landingData';

export function CapabilitiesSection() {
  return (
    <section id="capabilities" className="fc-section" aria-labelledby="capabilities-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow">Platform Capabilities</div>
          <h2 id="capabilities-heading" className="fc-section-title">
            Engineered for Precision &amp; Isolation
          </h2>
          <p className="fc-section-desc">
            Fire Crow combines containerized static analysis, upstream vulnerability telemetry,
            and deterministic audit ledgers to deliver actionable security intelligence without the noise.
          </p>
        </div>

        <div className="fc-capabilities-grid">
          {CAPABILITIES.map((cap) => (
            <div key={cap.id} className="fc-cap-card">
              <div>
                <div className="fc-cap-header">
                  <span className="fc-cap-eyebrow">{cap.eyebrow}</span>
                  <span className="fc-cap-badge">{cap.badge}</span>
                </div>
                <h3 className="fc-cap-title">{cap.title}</h3>
                <p className="fc-cap-desc">{cap.description}</p>
              </div>

              <div className="fc-cap-detail">
                {cap.technicalDetail}
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
