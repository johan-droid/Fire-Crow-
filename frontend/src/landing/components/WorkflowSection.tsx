import { WORKFLOW_STEPS } from '../data/landingData';

export function WorkflowSection() {
  return (
    <section id="workflow" className="fc-section" aria-labelledby="workflow-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow">Execution Pipeline</div>
          <h2 id="workflow-heading" className="fc-section-title">
            The Verified 4-Stage Audit Lifecycle
          </h2>
          <p className="fc-section-desc">
            From stream-bounded archive intake to containerized scanner isolation,
            every repository audit follows an immutable, zero-trust execution model.
          </p>
        </div>

        <div className="fc-workflow-grid">
          {WORKFLOW_STEPS.map((step) => (
            <div key={step.number} className="fc-workflow-card">
              <div>
                <div className="fc-step-num">{step.number}</div>
                <h3 className="fc-step-title">{step.title}</h3>
                <p className="fc-step-desc">{step.description}</p>
              </div>

              <ul className="fc-step-specs" aria-label={`Technical specifications for stage ${step.number}`}>
                {step.specs.map((spec) => (
                  <li key={spec}>{spec}</li>
                ))}
              </ul>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
