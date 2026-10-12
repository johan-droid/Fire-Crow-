import { useState } from 'react';
import { WORKFLOW_STEPS } from '../data/landingData';
import { Reveal } from './Reveal';
import { SpotlightCard } from './SpotlightCard';
import { DecryptedText } from './DecryptedText';
import { ShinyText } from './ShinyText';

const STAGE_TAGS: Record<string, { badge: string; command: string; duration: string }> = {
  '01': {
    badge: 'STREAM-INGEST BOUNDS',
    command: 'git archive --remote | tar -tz --max-size=50MB',
    duration: '0.14s',
  },
  '02': {
    badge: 'ZERO-PRIVILEGE SANDBOX',
    command: 'docker run --rm --cap-drop=ALL --read-only --network=none',
    duration: '0.08s',
  },
  '03': {
    badge: 'TRI-ENGINE PARALLEL SAST',
    command: 'semgrep scan & gitleaks detect & osv-scanner --lockfile',
    duration: '2.80s',
  },
  '04': {
    badge: 'IMMUTABLE AUDIT SYNTHESIS',
    command: 'sha256sum canonical_ledger.json > audit.sig',
    duration: '0.18s',
  },
};

export function WorkflowSection() {
  const [activeStage, setActiveStage] = useState<string | null>(null);

  return (
    <section id="workflow" className="fc-section" aria-labelledby="workflow-heading">
      <div className="fc-container">
        {/* Left-Aligned Pipeline Header */}
        <div className="fc-section-header fc-section-header-left" style={{ marginBottom: '32px' }}>
          <div className="fc-section-eyebrow" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px', marginBottom: '12px' }}>
            <span className="fc-pulse-dot" style={{ background: '#E5484D', boxShadow: 'none', width: '6px', height: '6px' }} aria-hidden="true" />
            <ShinyText text="EXECUTION PIPELINE // DETERMINISTIC RUNTIME" shineColor="#E5484D" />
          </div>
          <h2 id="workflow-heading" className="fc-section-title" style={{ textAlign: 'left', marginTop: '6px' }}>
            The Verified 4-Stage Audit Lifecycle
          </h2>
          <p className="fc-section-desc" style={{ maxWidth: '680px', margin: 0, textAlign: 'left' }}>
            From stream-bounded archive intake to containerized scanner isolation,
            every repository audit follows an immutable, zero-trust execution model.
          </p>
        </div>

        {/* Pipeline Telemetry Tracker Bar */}
        <div className="fc-pipeline-telemetry-bar" role="tablist" aria-label="Pipeline stage sequence">
          {WORKFLOW_STEPS.map((step) => {
            const isSelected = activeStage === step.number;
            const meta = STAGE_TAGS[step.number];
            return (
              <button
                key={step.number}
                type="button"
                role="tab"
                aria-selected={isSelected}
                className={`fc-telemetry-stage-btn ${isSelected ? 'active' : ''}`}
                onClick={() => setActiveStage(isSelected ? null : step.number)}
              >
                <span className="fc-telemetry-num">{step.number}</span>
                <span className="fc-telemetry-name">{step.title}</span>
                <span className="fc-telemetry-time">{meta?.duration}</span>
              </button>
            );
          })}
        </div>

        {/* 4-Stage Workflow Cards wrapped in SpotlightCard with equal heights */}
        <div className="fc-workflow-grid">
          {WORKFLOW_STEPS.map((step, idx) => {
            const isHighlighted = activeStage === null || activeStage === step.number;
            const meta = STAGE_TAGS[step.number];

            return (
              <Reveal key={step.number} className="fc-workflow-card-wrap" delay={idx * 90}>
                <SpotlightCard
                  className={`fc-workflow-card ${isHighlighted ? 'is-focused' : 'is-dimmed'}`}
                  spotlightColor="rgba(229, 72, 77, 0.20)"
                  intensity={0.26}
                  borderGlow={0.7}
                  style={{
                    height: '100%',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                    padding: '24px',
                    opacity: isHighlighted ? 1 : 0.45,
                    transition: 'all 0.3s ease',
                  }}
                >
                  <div className="fc-workflow-card-body">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
                      <div className="fc-step-num">
                        <DecryptedText text={step.number} speed={40} animateOn="view" />
                      </div>
                      <span className="fc-workflow-stage-tag">
                        {meta?.badge}
                      </span>
                    </div>

                    <h3 className="fc-step-title" style={{ fontSize: '1.18rem', marginBottom: '8px', color: '#F2F4F7' }}>
                      {step.title}
                    </h3>
                    <p className="fc-step-desc" style={{ fontSize: '0.86rem', color: '#A6AEB9', lineHeight: 1.6, marginBottom: '16px' }}>
                      {step.description}
                    </p>

                    {/* Micro Command Preview with High-Contrast Terminal Styling */}
                    <div className="fc-workflow-cmd-box" style={{
                      background: 'rgba(0, 0, 0, 0.55)',
                      padding: '10px 12px',
                      borderRadius: '6px',
                      border: '1px solid rgba(255, 255, 255, 0.10)',
                      fontFamily: 'var(--fc-font-mono)',
                      fontSize: '0.74rem',
                      color: '#38BDF8',
                      marginBottom: '18px',
                      overflowX: 'auto',
                    }}>
                      <span style={{ color: '#94A3B8', userSelect: 'none', marginRight: '6px' }}>$</span>
                      <code>{meta?.command}</code>
                    </div>
                  </div>

                  {/* Equal-Height Sticky Bottom Specifications */}
                  <ul className="fc-step-specs" aria-label={`Technical specifications for stage ${step.number}`}>
                    {step.specs.map((spec) => (
                      <li key={spec} className="fc-spec-item">
                        <span className="fc-spec-bullet" aria-hidden="true">→</span>
                        <span>{spec}</span>
                      </li>
                    ))}
                  </ul>
                </SpotlightCard>
              </Reveal>
            );
          })}
        </div>
      </div>
    </section>
  );
}

