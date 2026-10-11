import { useState } from 'react';
import { FAQ_ITEMS } from '../data/landingData';

export function FAQSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);

  const toggleFAQ = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section id="faq" className="fc-section" aria-labelledby="faq-heading">
      <div className="fc-container">
        <div className="fc-section-header">
          <div className="fc-section-eyebrow">Frequently Asked Questions</div>
          <h2 id="faq-heading" className="fc-section-title">
            Answers on Architecture &amp; Execution
          </h2>
          <p className="fc-section-desc">
            Direct, technical explanations of how Fire Crow handles source archives,
            container boundaries, and deterministic security reporting.
          </p>
        </div>

        <div className="fc-faq-list">
          {FAQ_ITEMS.map((item, idx) => {
            const isOpen = openIndex === idx;
            const answerId = `faq-answer-${item.id}`;
            const buttonId = `faq-btn-${item.id}`;

            return (
              <div key={item.id} className={`fc-faq-item ${isOpen ? 'open' : ''}`}>
                <button
                  type="button"
                  id={buttonId}
                  aria-expanded={isOpen}
                  aria-controls={answerId}
                  className="fc-faq-trigger"
                  onClick={() => toggleFAQ(idx)}
                >
                  <span>{item.question}</span>
                  <span className="fc-faq-toggle-icon" aria-hidden="true">+</span>
                </button>

                {isOpen && (
                  <div
                    id={answerId}
                    role="region"
                    aria-labelledby={buttonId}
                    className="fc-faq-answer"
                  >
                    {item.answer}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
}
