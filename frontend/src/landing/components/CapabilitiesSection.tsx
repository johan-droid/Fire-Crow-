import { CAPABILITIES } from '../data/landingData';
import { Reveal } from './Reveal';
import { SpotlightCard } from './SpotlightCard';
import { ShinyText } from './ShinyText';
import { DecryptedText } from './DecryptedText';

export function CapabilitiesSection() {
  return (
    <section id="capabilities" className="fc-section" aria-labelledby="capabilities-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <span className="fc-pulse-dot" style={{ background: '#E5484D', boxShadow: '0 0 8px #E5484D' }} aria-hidden="true" />
            <ShinyText text="NEXT LAB STANDARDS // PLATFORM CAPABILITIES" shineColor="#E5484D" />
          </div>
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
              className="fc-cap-reveal-wrap"
              delay={(idx % 3) * 90}
            >
              <SpotlightCard
                className="fc-cap-card"
                spotlightColor="rgba(229, 72, 77, 0.22)"
                intensity={0.25}
                borderGlow={0.65}
              >
                <div style={{ flex: 1 }}>
                  <div className="fc-cap-header">
                    <span className="fc-cap-eyebrow">{cap.eyebrow}</span>
                    <span className="fc-cap-badge">
                      <DecryptedText text={cap.badge} speed={35} animateOn="hover" />
                    </span>
                  </div>
                  <h3 className="fc-cap-title">{cap.title}</h3>
                  <p className="fc-cap-desc">{cap.description}</p>
                </div>

                <div className="fc-cap-detail">
                  {cap.technicalDetail}
                </div>
              </SpotlightCard>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

export default CapabilitiesSection;
