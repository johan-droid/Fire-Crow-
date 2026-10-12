import { useId, type CSSProperties, type SVGProps } from 'react';

export interface LogoProps extends SVGProps<SVGSVGElement> {
  size?: number;
  className?: string;
  monochrome?: boolean;
}

export interface FireCrowSymbolProps extends LogoProps {
  animated?: boolean;
  state?: 'idle' | 'scanning' | 'alert' | 'static';
}

/**
 * Next Lab — Parent Brand Geometric Symbol.
 *
 * An engineered isometric prism with an offset forward accelerator vector ('>').
 * Represents experimental engineering, precision coordinates, and forward momentum.
 * Scales down to 14px and renders crisp in monochrome or full palette.
 */
export function NextLabSymbol({
  size = 28,
  className = '',
  monochrome = false,
  style,
  ...props
}: LogoProps) {
  const primaryStroke = monochrome ? 'currentColor' : '#F2F4F7';
  const accentFill = monochrome ? 'currentColor' : '#E5484D';
  const gridStroke = monochrome ? 'currentColor' : 'rgba(232, 235, 240, 0.25)';

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`nextlab-symbol ${className}`}
      aria-label="Next Lab Symbol"
      style={{ flexShrink: 0, ...style }}
      {...props}
    >
      {/* Outer engineered hexagonal boundary */}
      <path
        d="M16 2.5L28.5 9.75V22.25L16 29.5L3.5 22.25V9.75L16 2.5Z"
        stroke={primaryStroke}
        strokeWidth="1.5"
        strokeLinejoin="round"
      />

      {/* Internal structural isometric axes */}
      <path
        d="M16 2.5V16M28.5 22.25L16 16M3.5 22.25L16 16"
        stroke={gridStroke}
        strokeWidth="1"
        strokeDasharray="2 2"
      />

      {/* Experimental Laboratory Forward Vector Node (N / >) */}
      <path
        d="M9 13.5L16 9.5L23 13.5L16 17.5L9 13.5Z"
        fill="rgba(232, 235, 240, 0.05)"
        stroke={primaryStroke}
        strokeWidth="1.25"
        strokeLinejoin="round"
      />

      {/* Burnt-Orange Forward Acceleration Vector */}
      <path
        d="M13 19.5L18.5 16L13 12.5"
        stroke={accentFill}
        strokeWidth="2.2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />

      {/* Precision coordinate anchor dot */}
      <circle cx="21" cy="16" r="1.5" fill={accentFill} />
    </svg>
  );
}

/**
 * Next Lab — Wordmark.
 * Precision editorial display typography.
 */
export function NextLabWordmark({
  size = 18,
  showInc = false,
  className = '',
}: {
  size?: number;
  showInc?: boolean;
  className?: string;
}) {
  return (
    <span
      className={`nextlab-wordmark ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '6px',
        fontFamily: 'var(--fc-font-display, "Space Grotesk", sans-serif)',
        fontWeight: 700,
        letterSpacing: '-0.02em',
        fontSize: `${size}px`,
        color: '#F2F4F7',
        lineHeight: 1,
      }}
    >
      <span>NEXT LAB</span>
      {showInc && (
        <span
          className="nextlab-inc-badge"
          style={{
            fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
            fontSize: `${Math.max(10, size * 0.55)}px`,
            fontWeight: 600,
            color: 'var(--fc-text-secondary, #A6AEB9)',
            letterSpacing: '0.04em',
            background: 'rgba(255, 255, 255, 0.06)',
            border: '1px solid rgba(255, 255, 255, 0.14)',
            padding: '2px 5px',
            borderRadius: '4px',
            textTransform: 'uppercase',
          }}
        >
          .inc
        </span>
      )}
    </span>
  );
}

/**
 * Fire Crow — Flagship Security Product Crest.
 *
 * An animatic, pattern-based geometric corvid crest framed in a tactical hexagonal perimeter.
 * Eliminates all raster noise and generative artifacts in favor of pure mathematical vector geometry:
 * - Razor aerodynamic feather blades in faceted graphite/charcoal.
 * - Sinuous ember crimson throat flame plume with gentle respiratory breathing motion.
 * - Piercing corvid slit eye with intelligence glint animation.
 * - Open tactical hexagon shield with precision coordinate notches.
 *
 * Supports clean states:
 * - `idle`: subtle respiratory flame pulse & periodic eye glint
 * - `scanning`: tactical radar sweep across shield perimeter & intensified eye focus
 * - `alert`: high-tempo warning pulse
 * - `static`: zero animation (also enforced automatically via prefers-reduced-motion)
 */
export function FireCrowSymbol({
  size = 32,
  className = '',
  monochrome = false,
  animated = true,
  state = 'idle',
  style,
  ...props
}: FireCrowSymbolProps) {
  const uid = useId().replace(/:/g, '');
  const activeState = animated ? state : 'static';

  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={`firecrow-symbol fc-sym-${uid} state-${activeState} ${className}`}
      aria-label="Fire Crow Security Crest"
      style={{
        flexShrink: 0,
        display: 'inline-block',
        verticalAlign: 'middle',
        overflow: 'visible',
        ...style,
      }}
      {...props}
    >
      <defs>
        {/* Tactical shield perimeter gradient */}
        <linearGradient id={`fc-shield-grad-${uid}`} x1="32" y1="10" x2="78" y2="75" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#FF4D4D'} />
          <stop offset="45%" stopColor={monochrome ? 'currentColor' : '#E5484D'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#8B151B'} />
        </linearGradient>

        {/* Fiery ember throat plume gradients */}
        <linearGradient id={`fc-flame-core-${uid}`} x1="68" y1="42" x2="45" y2="85" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#FF8A65'} />
          <stop offset="35%" stopColor={monochrome ? 'currentColor' : '#FF3838'} />
          <stop offset="75%" stopColor={monochrome ? 'currentColor' : '#D32F2F'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#800000'} />
        </linearGradient>
        <linearGradient id={`fc-flame-tongue-${uid}`} x1="60" y1="50" x2="48" y2="80" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#FFAB91'} />
          <stop offset="50%" stopColor={monochrome ? 'currentColor' : '#FF3D00'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#BF360C'} />
        </linearGradient>

        {/* Stealth graphite/charcoal feather facet gradients */}
        <linearGradient id={`fc-plumage-deep-${uid}`} x1="50" y1="20" x2="25" y2="70" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#2C2C34'} />
          <stop offset="50%" stopColor={monochrome ? 'currentColor' : '#1E1E24'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#121216'} />
        </linearGradient>
        <linearGradient id={`fc-plumage-mid-${uid}`} x1="60" y1="25" x2="30" y2="65" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#3F3F4A'} />
          <stop offset="60%" stopColor={monochrome ? 'currentColor' : '#282830'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#18181F'} />
        </linearGradient>
        <linearGradient id={`fc-plumage-light-${uid}`} x1="65" y1="22" x2="40" y2="45" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#555562'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#32323D'} />
        </linearGradient>

        {/* Aerodynamic beak gradients */}
        <linearGradient id={`fc-beak-upper-${uid}`} x1="68" y1="26" x2="84" y2="38" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#4A4A56'} />
          <stop offset="40%" stopColor={monochrome ? 'currentColor' : '#32323D'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#1C1C22'} />
        </linearGradient>
        <linearGradient id={`fc-beak-lower-${uid}`} x1="68" y1="38" x2="84" y2="38" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor={monochrome ? 'currentColor' : '#25252D'} />
          <stop offset="100%" stopColor={monochrome ? 'currentColor' : '#141418'} />
        </linearGradient>

        {/* Eye glow luminescent filter */}
        <filter id={`fc-glow-eye-${uid}`} x="-30%" y="-30%" width="160%" height="160%">
          <feGaussianBlur stdDeviation="1.2" result="blur" />
          <feMerge>
            <feMergeNode in="blur" />
            <feMergeNode in="SourceGraphic" />
          </feMerge>
        </filter>
      </defs>

      <style>{`
        .fc-sym-${uid} .fc-shield-path {
          stroke: url(#fc-shield-grad-${uid});
          stroke-width: 2.8;
          stroke-linecap: round;
          stroke-linejoin: round;
          transition: all 0.3s ease;
        }
        .fc-sym-${uid}.state-scanning .fc-shield-path {
          stroke-dasharray: 20 12;
          animation: fc-radar-${uid} 2.2s linear infinite;
        }
        .fc-sym-${uid}.state-idle .fc-flame-pulse,
        .fc-sym-${uid}:hover .fc-flame-pulse {
          transform-origin: 58px 50px;
          animation: fc-flame-breathe-${uid} 3.6s ease-in-out infinite alternate;
        }
        .fc-sym-${uid}.state-scanning .fc-flame-pulse {
          transform-origin: 58px 50px;
          animation: fc-flame-breathe-${uid} 1.6s ease-in-out infinite alternate;
        }
        .fc-sym-${uid}.state-idle .fc-eye-glint,
        .fc-sym-${uid}:hover .fc-eye-glint {
          transform-origin: 64px 31px;
          animation: fc-eye-flash-${uid} 4s ease-in-out infinite;
        }
        .fc-sym-${uid}.state-scanning .fc-eye-glint {
          transform-origin: 64px 31px;
          animation: fc-eye-flash-${uid} 1.8s ease-in-out infinite;
        }
        .fc-sym-${uid}.state-alert .fc-eye-glint {
          animation: fc-eye-strobe-${uid} 0.5s ease-in-out infinite;
        }
        .fc-sym-${uid}.state-static * {
          animation: none !important;
        }
        @keyframes fc-radar-${uid} {
          0% { stroke-dashoffset: 0; }
          100% { stroke-dashoffset: -64; }
        }
        @keyframes fc-flame-breathe-${uid} {
          0% { transform: scale(1) rotate(0deg); opacity: 0.94; }
          50% { transform: scale(1.025) rotate(0.4deg); opacity: 1; }
          100% { transform: scale(0.99) rotate(-0.3deg); opacity: 0.92; }
        }
        @keyframes fc-eye-flash-${uid} {
          0%, 82%, 100% { opacity: 0.92; filter: drop-shadow(0 0 1px #FF3838); }
          88%, 94% { opacity: 1; filter: drop-shadow(0 0 3.5px #FF6B4A); }
        }
        @keyframes fc-eye-strobe-${uid} {
          0%, 100% { opacity: 1; filter: drop-shadow(0 0 4px #FF3838); }
          50% { opacity: 0.4; filter: none; }
        }
        @media (prefers-reduced-motion: reduce) {
          .fc-sym-${uid} * {
            animation: none !important;
          }
        }
      `}</style>

      {/* 1. TACTICAL HEXAGONAL SHIELD PERIMETER */}
      <path
        className="fc-shield-path"
        d="M 32 32
           L 32 23
           L 34.5 23
           L 34.5 20.5
           L 51 9.5
           L 78 22.5
           L 78 48
           Q 78 62 66.5 73.5
           L 58 79"
      />
      {/* Precision telemetry tick marks on perimeter */}
      <line x1="77" y1="35" x2="80" y2="35" stroke={`url(#fc-shield-grad-${uid})`} strokeWidth="1.2" strokeLinecap="round" />
      <line x1="77" y1="42" x2="80" y2="42" stroke={`url(#fc-shield-grad-${uid})`} strokeWidth="1.2" strokeLinecap="round" />

      {/* 2. REAR SWEPT-BACK FEATHER BLADES */}
      {/* Blade 1 (Upper Crest / Nape) */}
      <path
        d="M 48 18.5 L 42 22 L 25 29 Q 32 30 36.5 32.5 Z"
        fill={`url(#fc-plumage-deep-${uid})`}
      />
      <path
        d="M 48 18.5 L 25 29 L 33 24 Z"
        fill={`url(#fc-plumage-light-${uid})`}
        opacity="0.5"
      />

      {/* Blade 2 */}
      <path
        d="M 43 27 L 36 32 L 20.5 39.5 Q 28 40.5 33.5 43 Z"
        fill={`url(#fc-plumage-mid-${uid})`}
      />
      <path
        d="M 43 27 L 20.5 39.5 L 30 34 Z"
        fill={`url(#fc-plumage-light-${uid})`}
        opacity="0.4"
      />

      {/* Blade 3 */}
      <path
        d="M 39 36 L 33 42 L 18.5 50.5 Q 26.5 50.5 32 53 Z"
        fill={`url(#fc-plumage-deep-${uid})`}
      />
      <path
        d="M 39 36 L 18.5 50.5 L 28 43 Z"
        fill={`url(#fc-plumage-light-${uid})`}
        opacity="0.35"
      />

      {/* Blade 4 */}
      <path
        d="M 37 46 L 32 52.5 L 22.5 63 Q 30 61.5 35 63 Z"
        fill={`url(#fc-plumage-mid-${uid})`}
      />
      <path
        d="M 37 46 L 22.5 63 L 30 54 Z"
        fill={`url(#fc-plumage-light-${uid})`}
        opacity="0.4"
      />

      {/* Blade 5 */}
      <path
        d="M 38 56 L 34.5 62.5 L 29.5 74.5 Q 37 70.5 42 71.5 Z"
        fill={`url(#fc-plumage-deep-${uid})`}
      />

      {/* Blade 6 (Lowest Taper Blade) */}
      <path
        d="M 41 65 L 39 71 L 38 82.5 Q 44 76 49 76.5 Z"
        fill={`url(#fc-plumage-mid-${uid})`}
      />

      {/* 3. INNER HEAD & BODY VOLUME */}
      <path
        d="M 48 18.5 Q 55 21 66 26.5 L 62 38 L 54 48 L 46 62 L 42 71.5 L 34.5 62.5 L 32 52.5 L 33 42 L 36 32 Z"
        fill={`url(#fc-plumage-deep-${uid})`}
      />

      {/* 4. BEAK & CHISELED HEAD ASSEMBLY */}
      {/* Crown top facet */}
      <path
        d="M 48 18.5 Q 57 20.5 67 26.5 L 63 35 L 52 28 Z"
        fill={`url(#fc-plumage-light-${uid})`}
        opacity="0.75"
      />

      {/* Upper aerodynamic hooked beak */}
      <path
        d="M 65 25.5 Q 74 29.5 84 38 Q 76 39.5 68 39.5 L 63 35 Z"
        fill={`url(#fc-beak-upper-${uid})`}
      />
      {/* Upper beak razor ridge highlight */}
      <path
        d="M 65 25.5 Q 74 29 84 38 Q 75 31.5 66 27.5 Z"
        fill="#71717A"
        opacity="0.45"
      />

      {/* Lower beak / precision mouth seam */}
      <path
        d="M 84 38 L 68 39.5 L 65.5 43.5 Q 74 42.5 84 38 Z"
        fill={`url(#fc-beak-lower-${uid})`}
      />

      {/* Chin anchor under beak */}
      <path
        d="M 68 39.5 L 65.5 43.5 L 63 45 L 60 41 Z"
        fill="#18181B"
      />

      {/* 5. FIERY EMBER PLUMAGE (THE ANIMATIC FIRE CROW CORE) */}
      <g className="fc-flame-pulse">
        {/* Base deep ruby shadow backing */}
        <path
          d="M 63 42 Q 66 50 63.5 60 Q 61 70 54 84 L 51 88 Q 51 81 54 75 Q 57 66 56 56 Q 55 49 51 44 Z"
          fill={monochrome ? 'currentColor' : '#7F1D1D'}
          opacity="0.85"
        />

        {/* Primary sweeping flame plume */}
        <path
          d="M 63.5 44 Q 67.5 53 64 64 Q 61 73 53.5 86 Q 50 89 48 84 Q 51 77 55 70 Q 59 62 58 53 Q 57 47 52 42.5 Z"
          fill={`url(#fc-flame-core-${uid})`}
        />

        {/* Secondary high-heat flame tongue */}
        <path
          d="M 58 48 Q 62.5 56 59 66 Q 56.5 73 50.5 81 Q 48.5 82.5 48 78 Q 51 72 53.5 65 Q 55.5 58 54 52 Z"
          fill={`url(#fc-flame-tongue-${uid})`}
        />

        {/* High-heat core incandescent lick */}
        <path
          d="M 57 51 Q 60 57 57.5 65 Q 55.5 71 50 77 Q 52 70 53.5 64 Q 54.5 58 53 53 Z"
          fill={monochrome ? 'currentColor' : '#FFAB91'}
          opacity="0.75"
        />
      </g>

      {/* 6. PIERCING PREDATORY CORVID EYE */}
      <g className="fc-eye-glint">
        {/* Deep socket recess */}
        <path d="M 61.5 29.5 L 67.5 30.5 L 64 33 Z" fill="#0F0F12" />
        {/* Glowing crimson eye slit */}
        <path
          d="M 62 30 Q 65 30.5 67 31 Q 64.5 32.2 62.5 31.8 Z"
          fill={monochrome ? 'currentColor' : '#FF3838'}
          filter={monochrome ? undefined : `url(#fc-glow-eye-${uid})`}
        />
        {/* High-intensity glint core */}
        <polygon points="63.5,30.7 65.5,30.9 64.5,31.5" fill={monochrome ? 'currentColor' : '#FFF59D'} />
      </g>

      {/* 7. BROW CHISELED ACCENT */}
      <path
        d="M 62 26 L 68 28 L 61 29.5 Z"
        fill={`url(#fc-plumage-light-${uid})`}
        opacity="0.6"
      />
    </svg>
  );
}

/**
 * Fire Crow Product Wordmark with optional NEXT LAB endorsement.
 */
export function FireCrowWordmark({
  size = 20,
  withEndorsement = true,
  className = '',
}: {
  size?: number;
  withEndorsement?: boolean;
  className?: string;
}) {
  return (
    <span
      className={`firecrow-wordmark-wrap ${className}`}
      style={{
        display: 'inline-flex',
        flexDirection: 'column',
        lineHeight: 1.1,
      }}
    >
      <span
        style={{
          fontFamily: 'var(--fc-font-display, "Space Grotesk", sans-serif)',
          fontSize: `${size}px`,
          fontWeight: 800,
          letterSpacing: '0.08em',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
        }}
      >
        <span style={{ color: 'var(--fc-text-primary, #F2F4F7)' }}>FIRE</span>
        <span style={{ color: 'var(--fc-accent, #E5484D)' }}>CROW</span>
      </span>

      {withEndorsement && (
        <span
          style={{
            fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
            fontSize: `${Math.max(9, size * 0.44)}px`,
            color: 'var(--fc-text-secondary, #A6AEB9)',
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            marginTop: '2px',
          }}
        >
          by Next Lab
        </span>
      )}
    </span>
  );
}

/**
 * FireCrowLogo — Master Comprehensive Animatic Brand Package.
 *
 * Faithfully implements the definitive Fire Crow brand emblem:
 * - Geometric pattern-based animatic raven crest with tactical shield.
 * - Bold display typography ("FIRE CROW").
 * - Precision motto subtitle ("SECURE · SCAN · REMEDIATE").
 * - Next Lab parent studio endorsement rule lockup.
 */
export interface FireCrowLogoProps {
  size?: number;
  variant?: 'full' | 'stacked' | 'horizontal' | 'symbol';
  animated?: boolean;
  state?: 'idle' | 'scanning' | 'alert' | 'static';
  theme?: 'dark' | 'light' | 'auto';
  showTagline?: boolean;
  showEndorsement?: boolean;
  className?: string;
  style?: CSSProperties;
}

export function FireCrowLogo({
  size = 56,
  variant = 'full',
  animated = true,
  state = 'idle',
  theme = 'auto',
  showTagline = true,
  showEndorsement = true,
  className = '',
  style,
}: FireCrowLogoProps) {
  if (variant === 'symbol') {
    return (
      <FireCrowSymbol
        size={size}
        animated={animated}
        state={state}
        className={className}
        style={style}
      />
    );
  }

  const isDark = theme === 'dark';
  const fireColor = isDark ? '#FFFFFF' : 'var(--fc-text-primary, #F2F4F7)';
  const crowColor = 'var(--fc-accent, #E5484D)';
  const taglineColor = isDark ? '#A1A1AA' : 'var(--fc-text-secondary, #A6AEB9)';
  const endorsementColor = isDark ? '#71717A' : 'var(--fc-text-muted, #6E7683)';
  const ruleColor = isDark ? 'rgba(255, 255, 255, 0.16)' : 'var(--fc-border, rgba(255, 255, 255, 0.09))';

  if (variant === 'horizontal') {
    return (
      <div
        className={`fc-logo-horizontal ${className}`}
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: `${Math.max(10, size * 0.3)}px`,
          ...style,
        }}
      >
        <FireCrowSymbol size={size} animated={animated} state={state} />

        <div style={{ display: 'flex', flexDirection: 'column', gap: '3px' }}>
          <div
            style={{
              fontFamily: 'var(--fc-font-display, "Space Grotesk", sans-serif)',
              fontSize: `${Math.max(14, size * 0.42)}px`,
              fontWeight: 800,
              letterSpacing: '0.12em',
              lineHeight: 1,
              display: 'flex',
              gap: '0.35em',
            }}
          >
            <span style={{ color: fireColor }}>FIRE</span>
            <span style={{ color: crowColor }}>CROW</span>
          </div>

          {showTagline && (
            <div
              style={{
                fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
                fontSize: `${Math.max(8, size * 0.18)}px`,
                fontWeight: 600,
                letterSpacing: '0.22em',
                color: taglineColor,
                textTransform: 'uppercase',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4em',
                lineHeight: 1,
              }}
            >
              <span>SECURE</span>
              <span style={{ color: crowColor }}>·</span>
              <span>SCAN</span>
              <span style={{ color: crowColor }}>·</span>
              <span>REMEDIATE</span>
            </div>
          )}

          {showEndorsement && (
            <div
              style={{
                fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
                fontSize: `${Math.max(7.5, size * 0.16)}px`,
                letterSpacing: '0.14em',
                color: endorsementColor,
                textTransform: 'uppercase',
                marginTop: '1px',
              }}
            >
              by Next Lab
            </div>
          )}
        </div>
      </div>
    );
  }

  // variant === 'full' or 'stacked'
  return (
    <div
      className={`fc-logo-package ${variant === 'stacked' ? 'is-stacked' : 'is-full'} ${className}`}
      style={{
        display: 'inline-flex',
        flexDirection: 'column',
        alignItems: 'center',
        textAlign: 'center',
        gap: `${Math.max(10, size * 0.22)}px`,
        ...style,
      }}
    >
      <FireCrowSymbol size={size} animated={animated} state={state} />

      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '6px' }}>
        {/* Brand Display Wordmark */}
        <div
          style={{
            fontFamily: 'var(--fc-font-display, "Space Grotesk", sans-serif)',
            fontSize: `${Math.max(18, size * 0.38)}px`,
            fontWeight: 800,
            letterSpacing: '0.16em',
            display: 'flex',
            alignItems: 'center',
            gap: '0.45em',
            lineHeight: 1,
          }}
        >
          <span style={{ color: fireColor }}>FIRE</span>
          <span style={{ color: crowColor }}>CROW</span>
        </div>

        {/* Tactical Security Motto Tagline */}
        {showTagline && (
          <div
            style={{
              fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
              fontSize: `${Math.max(9, size * 0.15)}px`,
              fontWeight: 600,
              letterSpacing: '0.26em',
              color: taglineColor,
              textTransform: 'uppercase',
              display: 'flex',
              alignItems: 'center',
              gap: '0.45em',
              marginTop: '1px',
            }}
          >
            <span>SECURE</span>
            <span style={{ color: crowColor }}>·</span>
            <span>SCAN</span>
            <span style={{ color: crowColor }}>·</span>
            <span>REMEDIATE</span>
          </div>
        )}

        {/* Corporate Endorsement with Geometric Rules */}
        {showEndorsement && variant === 'full' && (
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
              marginTop: '4px',
              fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
              fontSize: `${Math.max(8.5, size * 0.14)}px`,
              fontWeight: 500,
              letterSpacing: '0.22em',
              color: endorsementColor,
              textTransform: 'uppercase',
            }}
          >
            <span
              style={{
                width: '32px',
                height: '1px',
                backgroundColor: ruleColor,
                display: 'inline-block',
              }}
            />
            <span>NEXT LAB</span>
            <span
              style={{
                width: '32px',
                height: '1px',
                backgroundColor: ruleColor,
                display: 'inline-block',
              }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * Co-branded Dual Identity Lockup:
 * Highlights Fire Crow as the flagship security product while anchoring Next Lab as the parent company.
 */
export function BrandLockup({
  compact = false,
  className = '',
  style,
}: {
  compact?: boolean;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div
      className={`fc-brand-lockup ${className}`}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: compact ? '8px' : '12px',
        ...style,
      }}
    >
      <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
        <FireCrowSymbol size={compact ? 24 : 32} />
      </div>

      <div style={{ display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span
            style={{
              fontFamily: 'var(--fc-font-display, "Space Grotesk", sans-serif)',
              fontSize: compact ? '1rem' : '1.15rem',
              fontWeight: 800,
              letterSpacing: '0.04em',
              color: '#F2F4F7',
            }}
          >
            <span>FIRE </span>
            <span style={{ color: '#E5484D' }}>CROW</span>
          </span>
          <span
            className="fc-badge-sec"
            style={{
              fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
              fontSize: '0.62rem',
              fontWeight: 600,
              color: '#E5484D',
              background: 'rgba(201, 47, 56, 0.08)',
              border: '1px solid rgba(201, 47, 56, 0.25)',
              padding: '1px 6px',
              borderRadius: '10px',
              letterSpacing: '0.04em',
            }}
          >
            SEC-OPS
          </span>
        </div>

        <span
          className="fc-lockup-endorsement"
          style={{
            fontFamily: 'var(--fc-font-mono, "JetBrains Mono", monospace)',
            fontSize: '0.74rem',
            color: '#CBD5E1',
            letterSpacing: '0.07em',
            display: 'flex',
            alignItems: 'center',
            gap: '5px',
            marginTop: '2px',
          }}
        >
          <span>PRODUCT BY</span>
          <strong style={{ color: '#F2F4F7', fontWeight: 600 }}>NEXT LAB</strong>
        </span>
      </div>
    </div>
  );
}
