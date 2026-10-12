import { LandingNavbar } from './landing/components/LandingNavbar';
import { HeroSection } from './landing/components/HeroSection';
import { ProductPreview } from './landing/components/ProductPreview';
import { NextLabBrandSection } from './landing/components/NextLabBrandSection';
import { CapabilitiesSection } from './landing/components/CapabilitiesSection';
import { WorkflowSection } from './landing/components/WorkflowSection';
import { TrustSection } from './landing/components/TrustSection';
import { FAQSection } from './landing/components/FAQSection';
import { FinalCTA } from './landing/components/FinalCTA';
import { LandingFooter } from './landing/components/LandingFooter';
import { Reveal } from './landing/components/Reveal';
import './landing/styles/landing.css';

export interface UserProfile {
  user_id: string;
  username: string;
  email: string | null;
  credit_balance?: number;
}

export interface LandingPageProps {
  onNavigateLogin: () => void;
}

/**
 * NEXT LAB.inc // Fire Crow — Flagship Developer Security Auditing Platform
 *
 * Engineering-first brand identity: deep charcoal canvas, graphite surfaces,
 * warm off-white typography, restrained crimson, and distinctive burnt-orange accent.
 *
 * Fire Crow is presented prominently as the flagship security product by NEXT LAB.inc,
 * backed by deterministic execution, container isolation, and canonical audit ledgers.
 */
export default function LandingPage({
  onNavigateLogin,
}: LandingPageProps) {
  return (
    <div className="fc-landing apple-landing-page" id="top">
      {/* 01. Sticky Header Navigation with NEXT LAB + Fire Crow Co-Branding */}
      <LandingNavbar onNavigateLogin={onNavigateLogin} />

      <main id="main-content">
        {/* 02. High-Impact Value Proposition Hero */}
        <HeroSection onNavigateLogin={onNavigateLogin} />

        {/* 03. Interactive Product Walkthrough (Canonical Findings, Pipeline, Ledger, AI Summary) */}
        <Reveal>
          <ProductPreview onNavigateLogin={onNavigateLogin} />
        </Reveal>

        {/* 04. Parent Brand & Engineering Studio (NEXT LAB.inc Positioning & Pillars) */}
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

        {/* 08. Technical Architecture FAQ */}
        <Reveal>
          <FAQSection />
        </Reveal>

        {/* 09. Final Action Banner */}
        <Reveal>
          <FinalCTA onNavigateLogin={onNavigateLogin} />
        </Reveal>
      </main>

      {/* 11. Comprehensive Brand & Platform Footer */}
      <LandingFooter />
    </div>
  );
}
