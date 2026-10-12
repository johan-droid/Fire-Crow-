import { useEffect, useRef } from 'react';
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
import './landing/styles/landing.css';

export interface UserProfile {
  user_id: string;
  username: string;
  email: string | null;
  credit_balance?: number;
}

export interface LandingPageProps {
  user: UserProfile | null;
  onNavigateLogin: () => void;
  onInitiateCheckout: (amount: number, packageName: string) => void;
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
  user,
  onNavigateLogin,
  onInitiateCheckout,
}: LandingPageProps) {
  const rootRef = useRef<HTMLDivElement | null>(null);

  // Subtle parallax on the ambient orbs — rAF-throttled, passive, and fully
  // disabled under prefers-reduced-motion so scrolling stays lightweight.
  useEffect(() => {
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;
    let raf = 0;
    const onScroll = () => {
      cancelAnimationFrame(raf);
      raf = requestAnimationFrame(() => {
        const root = rootRef.current;
        if (!root) return;
        const y = Math.min(window.scrollY, 1400);
        root.style.setProperty('--fc-parallax-a', `${y * 0.05}px`);
        root.style.setProperty('--fc-parallax-b', `${y * 0.09}px`);
      });
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      window.removeEventListener('scroll', onScroll);
      cancelAnimationFrame(raf);
    };
  }, []);

  return (
    <div className="fc-landing apple-landing-page" id="top" ref={rootRef}>
      {/* Precision ambient background lighting */}
      <div className="fc-orbs" aria-hidden="true">
        <div className="fc-orb fc-orb-a" />
        <div className="fc-orb fc-orb-b" />
        <div className="fc-orb fc-orb-c" />
        <div className="fc-orb fc-orb-d" />
      </div>

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

        {/* 08. Transparent Commercial Plans */}
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
