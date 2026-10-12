import { useState, useMemo } from 'react';
import { FAQ_ITEMS } from '../data/landingData';
import { ShinyText } from './ShinyText';

export function FAQSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(0);
  const [searchQuery, setSearchQuery] = useState('');

  const filteredItems = useMemo(() => {
    if (!searchQuery.trim()) return FAQ_ITEMS;
    const q = searchQuery.toLowerCase();
    return FAQ_ITEMS.filter(
      (item) => item.question.toLowerCase().includes(q) || item.answer.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  const toggleFAQ = (index: number) => {
    setOpenIndex(openIndex === index ? null : index);
  };

  return (
    <section id="faq" className="fc-section fc-faq-section" aria-labelledby="faq-heading">
      <div className="fc-container">
        {/* Left-Aligned Technical Header & Search */}
        <div className="fc-section-header fc-section-header-left" style={{ marginBottom: '32px' }}>
          <div className="fc-section-eyebrow" style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <span className="fc-pulse-dot" style={{ background: '#E5484D', boxShadow: 'none', width: '6px', height: '6px' }} aria-hidden="true" />
            <ShinyText text="TECHNICAL TRANSPARENCY // FAQ" shineColor="#E5484D" />
          </div>
          <h2 id="faq-heading" className="fc-section-title" style={{ textAlign: 'left', marginTop: '12px' }}>
            Answers on Architecture &amp; Execution
          </h2>
          <p className="fc-section-desc" style={{ maxWidth: '640px', margin: '0', textAlign: 'left' }}>
            Direct, technical explanations of how Fire Crow handles source archives,
            container boundaries, and deterministic security reporting.
          </p>

          {/* Quick Filter Search */}
          <div style={{ maxWidth: '440px', margin: '22px 0 0', position: 'relative' }}>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search architecture questions (Docker, AI, retention)..."
              className="fc-faq-search-input"
              aria-label="Search frequently asked questions"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="fc-faq-search-clear"
                aria-label="Clear search query"
              >
                ✕
              </button>
            )}
          </div>
        </div>

        {/* Accordion List */}
        <div className="fc-faq-list">
          {filteredItems.length === 0 ? (
            <div style={{ textAlign: 'left', padding: '36px 0', color: 'var(--fc-warm-subtle)', fontFamily: 'var(--fc-font-mono)' }}>
              No questions found matching &ldquo;{searchQuery}&rdquo;.
            </div>
          ) : (
            filteredItems.map((item, idx) => {
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
                    <span className="fc-faq-toggle-icon" aria-hidden="true">
                      {isOpen ? (
                        <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                          <path d="M3 8h10" />
                        </svg>
                      ) : (
                        <svg width="12" height="12" viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                          <path d="M8 3v10M3 8h10" />
                        </svg>
                      )}
                    </span>
                  </button>

                  {isOpen && (
                    <div
                      id={answerId}
                      role="region"
                      aria-labelledby={buttonId}
                      className="fc-faq-answer"
                    >
                      {item.answer.split('\n\n').map((paragraph, pIdx) => (
                        <p key={pIdx} className="fc-faq-answer-p">
                          {paragraph}
                        </p>
                      ))}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>

        {/* Community / Docs footnote */}
        <div className="fc-faq-footer-note">
          <span>Need more technical details?</span>{' '}
          <a
            href="https://github.com/johan-droid/Fire-Crow-"
            target="_blank"
            rel="noreferrer"
            className="fc-faq-github-link"
          >
            Review the open documentation on GitHub ↗
          </a>
        </div>
      </div>
    </section>
  );
}

export default FAQSection;
