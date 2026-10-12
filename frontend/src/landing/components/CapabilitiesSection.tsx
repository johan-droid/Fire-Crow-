import { CAPABILITIES } from '../data/landingData';
import { Reveal } from './Reveal';

export function CapabilitiesSection() {
  return (
    <section id="capabilities" className="fc-section" aria-labelledby="capabilities-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow">NEXT LAB STANDARDS // PLATFORM CAPABILITIES</div>
          <h2 id="capabilities-heading" className="fc-section-title">
            Engineered for Precision, Isolation &amp; Truth
          </h2>
          <p className="fc-section-desc">
            Fire Crow combines containerized static analysis, upstream CVE telemetry,
            and deterministic audit ledgers to deliver actionable security intelligence without the noise.
          </p>
        </div>

        <div className="fc-capabilities-grid">
          {CAPABILITIES.map((cap, idx) => (
            <Reveal
              key={cap.id}
              className="fc-cap-card"
              delay={(idx % 3) * 90}
            >
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
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}
