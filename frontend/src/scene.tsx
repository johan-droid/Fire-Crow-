import { useEffect } from 'react';

/**
 * Pure-CSS 3D art scenes. No external dependencies — all depth comes from
 * CSS `perspective` / `transform-style: preserve-3d` layered in index.css.
 */

/** Rotating glass cube with orbiting rings, particle field and grid floor (landing hero). */
export function HeroScene() {
  return (
    <div className="hero-scene" aria-hidden="true">
      <div className="hero-scene-stage">
        <div className="hero-cube">
          <div className="cube-face cube-front" />
          <div className="cube-face cube-back" />
          <div className="cube-face cube-left" />
          <div className="cube-face cube-right" />
          <div className="cube-face cube-top" />
          <div className="cube-face cube-bottom" />
        </div>
        <div className="hero-ring ring-a" />
        <div className="hero-ring ring-b" />
        <div className="hero-ring ring-c" />
      </div>

      <div className="hero-grid-floor" />

      {Array.from({ length: 16 }).map((_, i) => (
        <i
          key={i}
          className={`hero-particle hp-${i % 4}`}
          style={{
            left: `${(i * 61) % 96}%`,
            top: `${18 + ((i * 37) % 64)}%`,
            animationDelay: `${(i % 8) * -1.1}s`,
            animationDuration: `${7 + (i % 5)}s`,
          }}
        />
      ))}

      <div className="hero-glow hero-glow-orange" />
      <div className="hero-glow hero-glow-blue" />
      <div className="hero-glow hero-glow-purple" />
    </div>
  );
}

/** Drifting aurora orbs, twinkling starfield and receding grid (login + dashboard). */
export function AuroraBackdrop({ variant }: { variant: 'login' | 'dashboard' }) {
  return (
    <div className={`aurora-backdrop aurora-${variant}`} aria-hidden="true">
      <div className="aurora-orb orb-a" />
      <div className="aurora-orb orb-b" />
      <div className="aurora-orb orb-c" />

      <div className="aurora-starfield">
        {Array.from({ length: 42 }).map((_, i) => (
          <i
            key={i}
            className={`aurora-star as-${i % 3}`}
            style={{
              left: `${(i * 41) % 100}%`,
              top: `${(i * 29 + 7) % 100}%`,
              animationDelay: `${(i % 9) * -0.7}s`,
            }}
          />
        ))}
      </div>

      <div className="aurora-grid" />
    </div>
  );
}

/** Adds `.reveal` to matched elements and flips them to `.is-visible` as they scroll into view. */
export function useScrollReveal(active: boolean, selector: string) {
  useEffect(() => {
    if (!active) return;
    const els = Array.from(document.querySelectorAll<HTMLElement>(selector));
    if (els.length === 0) return;

    if (!('IntersectionObserver' in window)) {
      els.forEach((el) => el.classList.add('is-visible'));
      return;
    }

    const io = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add('is-visible');
            io.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -40px 0px' },
    );

    els.forEach((el) => {
      el.classList.add('reveal');
      io.observe(el);
    });

    return () => {
      io.disconnect();
      els.forEach((el) => el.classList.remove('reveal', 'is-visible'));
    };
  }, [active, selector]);
}
