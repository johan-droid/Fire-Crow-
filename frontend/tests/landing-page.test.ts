import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// The mounted landing page (LandingPage.tsx + landingData.ts + landing-site.css)
// is the real public surface. These assertions pin the honesty and navigation
// contract the free-tier deployment depends on: no claim the product cannot
// back, no form that fakes a submission, no dead nav link.
const cwd = process.cwd();
const page = readFileSync(join(cwd, 'src', 'LandingPage.tsx'), 'utf8');
const data = readFileSync(join(cwd, 'src', 'landing', 'data', 'landingData.ts'), 'utf8');
const css = readFileSync(join(cwd, 'src', 'landing', 'site', 'landing-site.css'), 'utf8');

describe('landing navigation covers every section', () => {
  it('every NAV href has a matching section id', () => {
    const hrefs = [...page.matchAll(/href: '(#[a-z]+)'/g)].map((m) => m[1]);
    assert.ok(hrefs.length >= 6, `expected the full nav, got ${hrefs.join(', ')}`);
    for (const href of hrefs) {
      const id = href.slice(1);
      assert.ok(
        page.includes(`id="${id}"`),
        `nav links to ${href} but no section carries id="${id}"`,
      );
    }
  });
});

describe('free-tier preview disclosure', () => {
  it('is rendered only for signed-out visitors', () => {
    assert.match(page, /\{!user && \(/, 'disclosure must be gated on signed-out state');
    assert.match(page, /className="lp-demo-note"/, 'disclosure element must exist');
  });

  it('states the wake delay and describes the execution mode honestly', () => {
    assert.match(page, /take up to a minute to wake/i);
    // The preview runs on the free tier: it discloses the execution mode and
    // warns about native mode's reduced isolation rather than claiming scanning
    // is always available or always fully isolated.
    assert.match(page, /reduced-isolation/i);
    assert.doesNotMatch(page, /guaranteed clean|always secure|zero risk/i);
  });

  it('stays visible, not merely decorative CSS', () => {
    assert.match(css, /\.lp-demo-note\s*\{[^}]*color:/, 'must define readable text colour');
  });
});

describe('audit sample is labelled as a sample', () => {
  it('keeps the fine print that the ledger is illustrative', () => {
    assert.match(page, /The audit shown is a sample/i);
  });
});

describe('access request never fakes a submission', () => {
  it('does not claim a request was received', () => {
    assert.doesNotMatch(page, /Request received/i, 'no phantom receipt');
    assert.doesNotMatch(page, /className="lp-sent"/, 'no fake success state');
    assert.doesNotMatch(page, /<form[\s>]/, 'no no-op form pretending to submit');
  });

  it('routes capacity requests to a real destination', () => {
    assert.match(page, /issues\/new/, 'must link to a real request channel');
  });
});

describe('capability claims match the implementation', () => {
  it('does not advertise PDF or SOC2 / ISO-27001 alignment', () => {
    // Report formats are Markdown | JSON | HTML only (routes_audit.rs); no
    // control-framework mapping exists anywhere in the backend.
    for (const banned of [/PDF/i, /SOC\s*2/i, /ISO[\s-]?27001/i]) {
      assert.doesNotMatch(data, banned, `capability copy must not claim ${banned}`);
    }
  });

  it('describes network isolation accurately (not "airgapped", not "zero egress")', () => {
    // Source scanners run --network=none; OSV reaches the internet only
    // through the filtering proxy. "Airgapped" overstates that.
    for (const src of [data, page]) {
      assert.doesNotMatch(src, /airgapped/i);
      assert.doesNotMatch(src, /zero network egress/i);
    }
  });
});
