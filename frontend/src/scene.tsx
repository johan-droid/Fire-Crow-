import { useEffect, useRef, useState, type ReactNode, type MouseEvent } from 'react';

/**
 * 3D Interactive Art Scenes & Parallax Physics.
 * Uses HTML5 3D Canvas rendering + CSS 3D `perspective` and `preserve-3d`.
 */

/** Interactive 3D Canvas node field + laser connections + particle physics */
function HeroCanvas3D() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animId: number;
    let width = (canvas.width = canvas.parentElement?.clientWidth || window.innerWidth);
    let height = (canvas.height = canvas.parentElement?.clientHeight || 600);

    const handleResize = () => {
      if (!canvas || !canvas.parentElement) return;
      width = canvas.width = canvas.parentElement.clientWidth;
      height = canvas.height = canvas.parentElement.clientHeight;
    };
    window.addEventListener('resize', handleResize);

    // 3D Particles array (responsive density)
    const count = width < 768 ? 25 : 35;
    const particles = Array.from({ length: count }).map(() => ({
      x: (Math.random() - 0.5) * width * 1.2,
      y: (Math.random() - 0.5) * height * 1.2,
      z: Math.random() * 800 + 100,
      vx: (Math.random() - 0.5) * 0.6,
      vy: (Math.random() - 0.5) * 0.6,
      vz: (Math.random() - 0.5) * 0.8,
      size: Math.random() * 2 + 1,
      hue: Math.random() > 0.5 ? 210 : 270, // Blue/Purple cyber hues
    }));

    let mouseX = 0;
    let mouseY = 0;
    let targetMouseX = 0;
    let targetMouseY = 0;

    const handleMouseMove = (e: globalThis.MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      targetMouseX = e.clientX - rect.left - width / 2;
      targetMouseY = e.clientY - rect.top - height / 2;
    };
    window.addEventListener('mousemove', handleMouseMove);

    const render = () => {
      // Smooth mouse damping
      mouseX += (targetMouseX - mouseX) * 0.05;
      mouseY += (targetMouseY - mouseY) * 0.05;

      ctx.clearRect(0, 0, width, height);

      const fov = 400;
      const cx = width / 2 + mouseX * 0.1;
      const cy = height / 2 + mouseY * 0.1;

      // Project & render particles
      const projected = particles.map((p) => {
        p.x += p.vx;
        p.y += p.vy;
        p.z += p.vz;

        if (p.x < -width) p.x = width;
        if (p.x > width) p.x = -width;
        if (p.y < -height) p.y = height;
        if (p.y > height) p.y = -height;
        if (p.z < 50) p.z = 900;
        if (p.z > 900) p.z = 50;

        const scale = fov / (fov + p.z);
        const px = p.x * scale + cx;
        const py = p.y * scale + cy;
        const alpha = Math.min(1, Math.max(0.1, (1 - p.z / 900) * 0.8));

        return { px, py, scale, alpha, hue: p.hue, size: p.size * scale };
      });

      // Draw dynamic web lines between close 3D nodes
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const dx = projected[i].px - projected[j].px;
          const dy = projected[i].py - projected[j].py;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist < 110) {
            const lineAlpha = (1 - dist / 110) * projected[i].alpha * 0.4;
            ctx.beginPath();
            ctx.moveTo(projected[i].px, projected[i].py);
            ctx.lineTo(projected[j].px, projected[j].py);
            ctx.strokeStyle = `rgba(41, 151, 255, ${lineAlpha})`;
            ctx.lineWidth = 0.75;
            ctx.stroke();
          }
        }
      }

      // Draw particle glowing dots
      projected.forEach((p) => {
        ctx.beginPath();
        ctx.arc(p.px, p.py, p.size * 1.5, 0, Math.PI * 2);
        ctx.fillStyle = `hsla(${p.hue}, 90%, 65%, ${p.alpha})`;
        ctx.shadowBlur = 12 * p.scale;
        ctx.shadowColor = p.hue === 210 ? '#2997ff' : '#bf5af2';
        ctx.fill();
        ctx.shadowBlur = 0;
      });

      animId = requestAnimationFrame(render);
    };

    render();

    return () => {
      cancelAnimationFrame(animId);
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
    };
  }, []);

  return <canvas ref={canvasRef} className="hero-canvas-3d" aria-hidden="true" />;
}

/** 3D Interactive Hero Scene featuring rotating Cyber Shield core & 3D Parallax layers */
export function HeroScene() {
  const [transform, setTransform] = useState('rotateX(0deg) rotateY(0deg)');

  const handleMouseMove = (e: MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;
    const rotX = (y / (rect.height / 2)) * -12;
    const rotY = (x / (rect.width / 2)) * 12;
    setTransform(`rotateX(${rotX.toFixed(2)}deg) rotateY(${rotY.toFixed(2)}deg)`);
  };

  const handleMouseLeave = () => {
    setTransform('rotateX(0deg) rotateY(0deg)');
  };

  return (
    <div
      className="hero-scene"
      aria-hidden="true"
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
    >
      {/* Dynamic 3D WebGL Canvas particle constellation */}
      <HeroCanvas3D />

      {/* CSS 3D Stage with mouse-tilt responsiveness */}
      <div className="hero-scene-stage" style={{ transform }}>
        {/* 3D Cyber Shield Core */}
        <div className="hero-cyber-shield">
          <div className="shield-plate plate-front">
            <svg viewBox="0 0 100 100" fill="none" stroke="currentColor" className="shield-svg">
              <path d="M50 10 L85 25 V50 C85 72 50 90 50 90 C50 90 15 72 15 50 V25 Z" strokeWidth="2.5" />
              <path d="M50 24 L72 35 V50 C72 66 50 78 50 78 C50 78 28 66 28 50 V35 Z" strokeWidth="1.5" strokeDasharray="3 3" opacity="0.7" />
              <circle cx="50" cy="48" r="8" fill="var(--accent)" />
            </svg>
          </div>
          <div className="shield-glow" />
        </div>

        {/* 3D Orbiting Rings */}
        <div className="hero-ring ring-a" />
        <div className="hero-ring ring-b" />
        <div className="hero-ring ring-c" />
        <div className="hero-ring ring-d" />

        {/* Floating 3D Parallax Badges */}
        <div className="hero-float-badge float-badge-1">
          <span className="badge-dot green" />
          <span>0 False Positives</span>
        </div>
        <div className="hero-float-badge float-badge-2">
          <span className="badge-dot purple" />
          <span>Docker Sandbox Verified</span>
        </div>
        <div className="hero-float-badge float-badge-3">
          <span className="badge-dot blue" />
          <span>LLM Reasoning Active</span>
        </div>
      </div>

      <div className="hero-grid-floor" />

      {/* Atmospheric Glow Orbs */}
      <div className="hero-glow hero-glow-orange" />
      <div className="hero-glow hero-glow-blue" />
      <div className="hero-glow hero-glow-purple" />
    </div>
  );
}

/** 3D Tilt Card wrapper component for interactive cards */
export function TiltCard({ children, className = '', style = {} }: { children: ReactNode; className?: string; style?: React.CSSProperties }) {
  const [tiltStyle, setTiltStyle] = useState({});

  const handleMouseMove = (e: MouseEvent<HTMLDivElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left - rect.width / 2;
    const y = e.clientY - rect.top - rect.height / 2;
    const rotX = (y / (rect.height / 2)) * -6;
    const rotY = (x / (rect.width / 2)) * 6;
    setTiltStyle({
      transform: `perspective(1000px) rotateX(${rotX.toFixed(2)}deg) rotateY(${rotY.toFixed(2)}deg) scale3d(1.015, 1.015, 1.015)`,
      transition: 'transform 0.1s ease-out',
    });
  };

  const handleMouseLeave = () => {
    setTiltStyle({
      transform: 'perspective(1000px) rotateX(0deg) rotateY(0deg) scale3d(1, 1, 1)',
      transition: 'transform 0.5s ease-in-out',
    });
  };

  return (
    <div
      className={`tilt-card-wrapper ${className}`}
      style={{ ...style, ...tiltStyle }}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
    >
      {children}
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

