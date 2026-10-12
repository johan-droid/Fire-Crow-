'use client';

import { useState, useRef, useEffect } from 'react';
import type { ReactNode } from 'react';
import './MiniatureGlassDock.css';

interface DockItem {
  id: string;
  label: string;
  icon: ReactNode;
  href?: string;
  onClick?: () => void;
  primary?: boolean;
}

interface MiniatureGlassDockProps {
  onNavigateLogin: () => void;
}

export function MiniatureGlassDock({ onNavigateLogin }: MiniatureGlassDockProps) {
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);
  const [mouseX, setMouseX] = useState<number | null>(null);
  const [isVisible, setIsVisible] = useState(true);
  const dockRef = useRef<HTMLDivElement>(null);
  const lastScrollY = useRef(0);

  // Auto-hide slightly when scrolling fast down, reveal on scroll up or hover
  useEffect(() => {
    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      if (currentScrollY > 200 && currentScrollY > lastScrollY.current + 30) {
        setIsVisible(false);
      } else if (currentScrollY < lastScrollY.current - 10 || currentScrollY < 200) {
        setIsVisible(true);
      }
      lastScrollY.current = currentScrollY;
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  const items: DockItem[] = [
    {
      id: 'top',
      label: 'Fire Crow Hero',
      href: '#top',
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
          <polyline points="9 22 9 12 15 12 15 22" />
        </svg>
      ),
    },
    {
      id: 'preview',
      label: 'Audit Walkthrough',
      href: '#preview',
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="4 17 10 11 4 5" />
          <line x1="12" y1="19" x2="20" y2="19" />
        </svg>
      ),
    },
    {
      id: 'workflow',
      label: '4-Stage Pipeline',
      href: '#workflow',
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="3" />
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
        </svg>
      ),
    },
    {
      id: 'trust',
      label: 'Security Guarantees',
      href: '#trust',
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        </svg>
      ),
    },
    {
      id: 'pricing',
      label: 'Transparent Pricing',
      href: '#pricing',
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="2" y="5" width="20" height="14" rx="2" />
          <line x1="2" y1="10" x2="22" y2="10" />
        </svg>
      ),
    },
    {
      id: 'github',
      label: 'GitHub Repository',
      href: 'https://github.com/johan-droid/Fire-Crow-',
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="currentColor">
          <path fillRule="evenodd" clipRule="evenodd" d="M12 2C6.477 2 2 6.477 2 12c0 4.42 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.008-.866-.013-1.7-2.782.603-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.464-1.11-1.464-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.831.092-.646.35-1.086.636-1.336-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.203 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.579.688.481C19.137 20.162 22 16.418 22 12c0-5.523-4.477-10-10-10z" />
        </svg>
      ),
    },
    {
      id: 'launch',
      label: 'Launch Console',
      onClick: onNavigateLogin,
      primary: true,
      icon: (
        <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <line x1="5" y1="12" x2="19" y2="12" />
          <polyline points="12 5 19 12 12 19" />
        </svg>
      ),
    },
  ];

  const handleMouseMove = (e: React.MouseEvent<HTMLDivElement>) => {
    if (dockRef.current) {
      const rect = dockRef.current.getBoundingClientRect();
      setMouseX(e.clientX - rect.left);
    }
  };

  const handleMouseLeave = () => {
    setMouseX(null);
    setHoveredIndex(null);
  };

  return (
    <aside
      className={`fc-glass-dock-wrapper ${isVisible ? 'is-visible' : 'is-hidden'}`}
      aria-label="Quick Navigation Dock"
    >
      <div
        ref={dockRef}
        className="fc-glass-dock"
        onMouseMove={handleMouseMove}
        onMouseLeave={handleMouseLeave}
        role="toolbar"
        aria-label="Navigation dock"
      >
        {/* Miniature Telemetry Status Indicator */}
        <div className="fc-dock-telemetry-badge" title="3 containerized engines active, 0 code retention">
          <span className="fc-dock-pulse" aria-hidden="true" />
          <span className="fc-dock-telemetry-text">AIRGAPPED</span>
        </div>

        <div className="fc-dock-divider" aria-hidden="true" />

        {/* Dock Items */}
        <div className="fc-dock-items-group">
          {items.map((item, index) => {
            const isHovered = hoveredIndex === index;

            // Calculate magnification physics based on mouse distance
            let scale = 1;
            if (mouseX !== null && dockRef.current) {
              const itemElement = dockRef.current.querySelectorAll('.fc-dock-item')[index];
              if (itemElement) {
                const rect = itemElement.getBoundingClientRect();
                const dockRect = dockRef.current.getBoundingClientRect();
                const itemCenter = rect.left + rect.width / 2 - dockRect.left;
                const distance = Math.abs(mouseX - itemCenter);
                if (distance < 90) {
                  scale = 1 + (1 - distance / 90) * 0.28;
                }
              }
            }

            const itemContent = (
              <>
                <span className="fc-dock-icon">{item.icon}</span>
                {isHovered && (
                  <span className="fc-dock-tooltip" role="tooltip">
                    {item.label}
                  </span>
                )}
              </>
            );

            if (item.href) {
              const isExternal = item.href.startsWith('http');
              return (
                <a
                  key={item.id}
                  href={item.href}
                  target={isExternal ? '_blank' : undefined}
                  rel={isExternal ? 'noreferrer' : undefined}
                  className={`fc-dock-item ${item.primary ? 'is-primary' : ''}`}
                  style={{ transform: `scale(${scale})` }}
                  onMouseEnter={() => setHoveredIndex(index)}
                  onMouseLeave={() => setHoveredIndex(null)}
                  aria-label={item.label}
                >
                  {itemContent}
                </a>
              );
            }

            return (
              <button
                key={item.id}
                type="button"
                onClick={item.onClick}
                className={`fc-dock-item ${item.primary ? 'is-primary' : ''}`}
                style={{ transform: `scale(${scale})` }}
                onMouseEnter={() => setHoveredIndex(index)}
                onMouseLeave={() => setHoveredIndex(null)}
                aria-label={item.label}
              >
                {itemContent}
              </button>
            );
          })}
        </div>
      </div>
    </aside>
  );
}

export default MiniatureGlassDock;
