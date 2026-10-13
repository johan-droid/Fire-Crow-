import { LandingNavbar } from './landing/components/LandingNavbar';
import { HeroSection } from './landing/components/HeroSection';
import { ProductPreview } from './landing/components/ProductPreview';
import { NextLabBrandSection } from './landing/components/NextLabBrandSection';
import { CapabilitiesSection } from './landing/components/CapabilitiesSection';
import { WorkflowSection } from './landing/components/WorkflowSection';
import { TrustSection } from './landing/components/TrustSection';
import { PricingSection } from './landing/components/PricingSection';
import { FAQSection } from './landing/components/FAQSection';
import { FinalCTA } from './landing/components/FinalCTA';
import { LandingFooter } from './landing/components/LandingFooter';
import { Reveal } from './landing/components/Reveal';
import { Particles } from './landing/components/Particles';
import './landing/styles/landing.css';

export interface LandingPageUser {
  user_id?: string;
  username: string;
  email: string | null;
  credit_balance?: number;
}

export type UserProfile = LandingPageUser;

export interface LandingPageProps {
  user?: LandingPageUser | null;
  onNavigateLogin: () => void;
  onNavigateConsole?: () => void;
  onInitiateCheckout?: (amount: number, packageName: string) => Promise<void> | void;
}

/**
 * Next Lab // Fire Crow — Flagship Developer Security Auditing Platform
 *
 * Engineering-first brand identity: deep charcoal canvas, graphite surfaces,
 * warm off-white typography, restrained crimson, and distinctive burnt-orange accent.
 *
 * Enhanced with React Bits animated components:
 * - Particles WebGL2 3D Constellation Background
 * - SpotlightCard Pointer-Tracking Luminance & Noise Grain
 * - ShinyText Sheen Sweeps
 * - DecryptedText Cryptographic Glyph Cycling
 */
export default function LandingPage({
  user,
  onNavigateLogin,
  onNavigateConsole,
  onInitiateCheckout,
}: LandingPageProps) {
  return (
    <div className="fc-landing apple-landing-page" id="top">
      {/* Fixed ambient aurora — slow color depth behind every section */}
      <div className="fc-aurora" aria-hidden="true" />

      {/* React Bits: Subtle WebGL2 Cyber Particle Atmosphere */}
      <div
        style={{
          position: 'absolute',
          top: 0,
          left: 0,
          right: 0,
          height: '1100px',
          zIndex: 0,
          pointerEvents: 'none',
          opacity: 0.65,
          maskImage: 'linear-gradient(to bottom, black 60%, transparent 100%)',
          WebkitMaskImage: 'linear-gradient(to bottom, black 60%, transparent 100%)',
        }}
      >
        <Particles
          particleCount={75}
          particleSpread={12}
          speed={0.12}
          particleColors={['#E5484D', '#FF6B4A', '#818CF8', '#38BDF8']}
          connections={true}
          connectionDistance={115}
          glow={0.65}
          twinkle={0.35}
          opacity={0.8}
        />
      </div>

      {/* 01. Sticky Header Navigation with NEXT LAB + Fire Crow Co-Branding */}
      <LandingNavbar user={user} onNavigateLogin={onNavigateLogin} onNavigateConsole={onNavigateConsole} />

      <main id="main-content" style={{ position: 'relative', zIndex: 1 }}>
        {/* 02. High-Impact Value Proposition Hero with Terminal */}
        <HeroSection onNavigateLogin={onNavigateLogin} />

        {/* 03. Interactive Product Walkthrough (Canonical Findings, Pipeline, Ledger, AI Summary) */}
        <Reveal>
          <ProductPreview onNavigateLogin={onNavigateLogin} />
        </Reveal>

        {/* 04. Parent Brand & Engineering Studio (Next Lab Positioning & Pillars) */}
        <div id="studio" style={{ scrollMarginTop: '88px' }}>
          <Reveal>
            <NextLabBrandSection />
          </Reveal>
        </div>

        {/* 05. Verified Platform Capabilities */}
        <Reveal>
          <CapabilitiesSection />
        </Reveal>

        {/* 06. 4-Stage Execution Pipeline */}
        <Reveal>
          <WorkflowSection />
        </Reveal>

        {/* 07. Trust & Security Architecture Guarantees */}
        <Reveal>
          <TrustSection />
        </Reveal>

        {/* 08. Transparent Infrastructure Pricing Plans */}
        <Reveal>
          <PricingSection
            user={user}
            onNavigateLogin={onNavigateLogin}
            onInitiateCheckout={onInitiateCheckout}
          />
        </Reveal>

        {/* 09. Technical Architecture FAQ */}
        <Reveal>
          <FAQSection />
        </Reveal>

        {/* 10. Final Action Banner */}
        <Reveal>
          <FinalCTA onNavigateLogin={onNavigateLogin} />
        </Reveal>
      </main>

      {/* 11. Comprehensive Brand & Platform Footer */}
      <LandingFooter />
    </div>
  );
}
