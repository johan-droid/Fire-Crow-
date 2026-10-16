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

// Vercel is the only thing serving the CSP header (dev Vite serves none), so
// both deployment configs are the whole attack surface for it.
const cspOf = (file: string): string => {
  const config = JSON.parse(readFileSync(file, 'utf8'));
  const headers: Array<{ headers: Array<{ key: string; value: string }> }> = config.headers ?? [];
  for (const entry of headers) {
    for (const header of entry.headers) {
      if (header.key === 'Content-Security-Policy') return header.value;
    }
  }
  throw new Error(`no Content-Security-Policy header in ${file}`);
};

const directivesOf = (csp: string): Record<string, string[]> => {
  const out: Record<string, string[]> = {};
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length > 0) out[tokens[0]] = tokens.slice(1);
  }
  return out;
};

describe('Content-Security-Policy (vercel.json)', () => {
  for (const file of ['../vercel.json', 'vercel.json']) {
    const relative = file;
    const csp = cspOf(join(process.cwd(), file));
    const directives = directivesOf(csp);

    it(`${relative}: script-src has no 'unsafe-inline'`, () => {
      const script = directives['script-src'] ?? [];
      assert.ok(script.length > 0, 'script-src directive missing');
      assert.ok(!script.includes("'unsafe-inline'"),
        `script-src allows inline: ${script.join(' ')}`);
    });
    it(`${relative}: connect-src allows no plain http: or websocket schemes`, () => {
      const connect = directives['connect-src'] ?? [];
      for (const banned of ['http:', 'ws:', 'wss:']) {
        assert.ok(!connect.includes(banned), `connect-src includes ${banned}: ${connect.join(' ')}`);
      }
    });
    it(`${relative}: no directive contains 'unsafe-eval'`, () => {
      assert.ok(!csp.includes('unsafe-eval'), `CSP allows unsafe-eval: ${csp}`);
    });
  }
});

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
