import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const cwd = process.cwd();
const hero = readFileSync(join(cwd, 'src', 'landing', 'components', 'HeroSection.tsx'), 'utf8');
const techText = readFileSync(join(cwd, 'src', 'landing', 'components', 'TechText.tsx'), 'utf8');
const techTextCss = readFileSync(join(cwd, 'src', 'landing', 'components', 'TechText.css'), 'utf8');
const strokeText = readFileSync(join(cwd, 'src', 'landing', 'components', 'StrokeText.tsx'), 'utf8');

describe('TechText wordmark integration', () => {
  it('renders the FIRE CROW wordmark in the hero', () => {
    assert.ok(hero.includes("from './TechText'"), 'hero must import the TechText component');
    assert.ok(hero.includes('text="FIRE CROW"'), 'wordmark text must be FIRE CROW');
  });

  it('themes the wordmark ember-on-graphite with letter reveal', () => {
    assert.ok(hero.includes('accentColor="#E5484D"'), 'frame/label accent must be ember');
    assert.ok(hero.includes('color="#F2F4F7"'), 'letter fill must be off-white');
    assert.ok(hero.includes('reveal="letter"'), 'reveal mode must be letter');
  });

  it('keeps the canvas accessible and motion-safe', () => {
    assert.ok(techText.includes('role="img"'), 'canvas container must expose role=img');
    assert.ok(techText.includes('aria-label={text}'), 'canvas container must label the wordmark');
    assert.ok(techText.includes('prefers-reduced-motion'), 'idle sweep must respect reduced motion');
    assert.ok(techTextCss.includes('touch-action: pan-y'), 'canvas must not trap vertical touch scroll');
  });
});

describe('StrokeText punchline integration', () => {
  it('mounts the punchline in the hero H1', () => {
    assert.ok(hero.includes("from './StrokeText'"), 'hero must import the StrokeText component');
    assert.ok(hero.includes('text="before attackers do."'), 'animated payoff must be the punchline');
    assert.ok(hero.includes('fc-hero-punch'), 'H1 must carry the punchline composition class');
  });

  it('draws ember outlines into an off-white wipe fill', () => {
    assert.ok(hero.includes('strokeColor="#E5484D"'), 'outline draw must be ember');
    assert.ok(hero.includes('fillColor="#F2F4F7"'), 'fill must be off-white');
    assert.ok(hero.includes('fillMode="wipe"'), 'fill must arrive as a wipe');
    assert.ok(hero.includes('trigger="scroll"'), 'draw must trigger on scroll into view');
  });

  it('keeps the SVG accessible and motion-safe', () => {
    assert.ok(strokeText.includes('role="img"'), 'wordmark wrapper must expose role=img');
    assert.ok(strokeText.includes("aria-label={String(text ?? '')}"), 'wrapper must label the copy');
    assert.ok(strokeText.includes('prefers-reduced-motion'), 'timeline must settle instantly under reduced motion');
  });
});
