import { useEffect, useRef, useState, type CSSProperties, type ElementType, type ReactNode } from 'react';

interface RevealProps {
  children: ReactNode;
  /** Extra classes merged onto the reveal wrapper (e.g. existing card classes). */
  className?: string;
  /** Stagger offset in ms, applied as transition-delay once visible. */
  delay?: number;
  /** Rendered element — keeps grid/card DOM shapes unchanged. */
  as?: 'div' | 'section' | 'span' | 'li' | 'h2' | 'p';
}

/**
 * Scroll-triggered reveal wrapper (no animation dependencies).
 *
 * - Uses a one-shot IntersectionObserver; content stays mounted either way.
 * - `prefers-reduced-motion` (or no IntersectionObserver) renders visible
 *   immediately — content is never hidden from assistive tech or no-motion users.
 */
export function Reveal({ children, className = '', delay = 0, as = 'div' }: RevealProps) {
  const ref = useRef<HTMLElement | null>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
      setVisible(true);
      return;
    }
    if (typeof IntersectionObserver === 'undefined') {
      setVisible(true);
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setVisible(true);
            io.disconnect();
          }
        }
      },
      { threshold: 0.12, rootMargin: '0px 0px -8% 0px' },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  const Tag = as as ElementType;
  return (
    <Tag
      ref={ref}
      className={`fc-reveal${visible ? ' is-visible' : ''}${className ? ` ${className}` : ''}`}
      style={{ '--fc-reveal-delay': `${delay}ms` } as CSSProperties}
    >
      {children}
    </Tag>
  );
}
