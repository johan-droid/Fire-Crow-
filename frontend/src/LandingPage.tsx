import { LandingNavbar } from './landing/components/LandingNavbar';
import { HeroSection } from './landing/components/HeroSection';
import { ProductPreview } from './landing/components/ProductPreview';
import { CapabilitiesSection } from './landing/components/CapabilitiesSection';
import { WorkflowSection } from './landing/components/WorkflowSection';
import { TrustSection } from './landing/components/TrustSection';
import { PricingSection } from './landing/components/PricingSection';
import { FAQSection } from './landing/components/FAQSection';
import { FinalCTA } from './landing/components/FinalCTA';
import { LandingFooter } from './landing/components/LandingFooter';
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
 * Fire Crow — Primary Landing Page (Ember Noir / Security Intelligence Redesign)
 *
 * Implements a restrained, technical, premium dark interface showcasing real scanner
 * architectures, canonical audit ledgers, container isolation, and deterministic reporting.
 */
export default function LandingPage({
  user,
  onNavigateLogin,
  onInitiateCheckout,
}: LandingPageProps) {
  return (
    <div className="fc-landing apple-landing-page" id="top">
      {/* 01. Sticky Frosted Header Navigation */}
      <LandingNavbar onNavigateLogin={onNavigateLogin} />

      <main id="main-content">
        {/* 02. High-Impact Value Proposition Hero */}
        <HeroSection onNavigateLogin={onNavigateLogin} />

        {/* 03. Interactive Product Demonstration (Audit Console Preview) */}
        <ProductPreview onNavigateLogin={onNavigateLogin} />

        {/* 04. Verified Platform Capabilities */}
        <CapabilitiesSection />

        {/* 05. 4-Stage Execution Pipeline */}
        <WorkflowSection />

        {/* 06. Trust & Security Architecture Guarantees */}
        <TrustSection />

        {/* 07. Transparent Commercial Plans */}
        <PricingSection
          user={user}
          onNavigateLogin={onNavigateLogin}
          onInitiateCheckout={onInitiateCheckout}
        />

        {/* 08. Technical Architecture FAQ */}
        <FAQSection />

        {/* 09. Final Action Banner */}
        <FinalCTA onNavigateLogin={onNavigateLogin} />
      </main>

      {/* 10. Comprehensive Product Footer */}
      <LandingFooter />
    </div>
  );
}
