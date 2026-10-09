import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Static security guards over the shipped source: cheap tripwires so a future
// edit cannot silently reintroduce a known-bad pattern. Run from the frontend
// directory (npm test).
const SRC = join(process.cwd(), 'src');
const app = readFileSync(join(SRC, 'App.tsx'), 'utf8');
const client = readFileSync(join(SRC, 'api', 'client.ts'), 'utf8');
const all = app + client;

describe('session hygiene', () => {
  it('never stores tokens in web storage (cookies are HttpOnly)', () => {
    const hits = all.match(/(localStorage|sessionStorage)\.(getItem|setItem)\(([^)]*)\)/g) ?? [];
    for (const hit of hits) {
      assert.ok(!/token|session|auth|credential/i.test(hit), `suspicious storage use: ${hit}`);
    }
  });
  it('never clears auth cookies from JS (only the server logout response can)', () => {
    assert.ok(!/document\.cookie\s*=/.test(all), 'JS cookie writes found');
  });
  it('strips single-use OAuth codes from the URL on every path', () => {
    const strips = (app.match(/window\.history\.replaceState/g) ?? []).length;
    assert.ok(strips >= 2, `expected error+success stripping, found ${strips}`);
  });
});

describe('untrusted content', () => {
  it('has no raw HTML sinks', () => {
    assert.ok(!/dangerouslySetInnerHTML/.test(all), 'dangerouslySetInnerHTML found');
    assert.ok(!/\.innerHTML\s*=/.test(all), '.innerHTML assignment found');
  });
  it('every target=_blank link carries rel', () => {
    const links = all.match(/<a [^>]*target="_blank"[^>]*>/g) ?? [];
    assert.ok(links.length > 0, 'expected at least one external link fixture');
    for (const link of links) {
      assert.ok(/rel=/.test(link), `external link without rel: ${link}`);
    }
  });
});
