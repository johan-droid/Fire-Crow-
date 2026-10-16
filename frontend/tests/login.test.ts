import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(process.cwd(), 'src');
const loginPage = readFileSync(join(SRC, 'LoginPage.tsx'), 'utf8');
const app = readFileSync(join(SRC, 'App.tsx'), 'utf8');
const loginCss = readFileSync(join(SRC, 'login-site.css'), 'utf8');

describe('LoginPage structural & a11y standards', () => {
  it('exposes accessible input controls with labels and describedby error links', () => {
    assert.ok(loginPage.includes('id="lg-identifier"'), 'identifier input id missing');
    assert.ok(loginPage.includes('id="lg-password"'), 'password input id missing');
    assert.ok(loginPage.includes('aria-describedby'), 'error description linkage missing');
    assert.ok(loginPage.includes('aria-invalid='), 'aria-invalid binding missing');
    assert.ok(loginPage.includes('htmlFor={id}'), 'field label association missing');
  });

  it('exposes an accessible password visibility toggle with aria state', () => {
    assert.ok(loginPage.includes('lg-pw'), 'password toggle wrapper missing');
    assert.ok(loginPage.includes('aria-label={showPassword'), 'toggle aria-label missing');
    assert.ok(loginPage.includes('aria-pressed={showPassword}'), 'toggle aria-pressed state missing');
    assert.ok(loginPage.includes("showPassword ? 'text' : 'password'"), 'password type toggle condition missing');
  });

  it('announces errors with alert roles', () => {
    assert.ok(loginPage.includes('role="alert"'), 'alert role missing');
  });

  it('prevents duplicate submissions via disabled states', () => {
    assert.ok(loginPage.includes('disabled={isSubmitting}'), 'submit button disabled guard missing');
  });

  it('offers GitHub and password sign-in and links back to the landing page', () => {
    assert.ok(loginPage.includes('onGitHubLogin'), 'GitHub sign-in missing');
    assert.ok(loginPage.includes('onNavigateLanding'), 'landing navigation missing');
  });

  it('states the three engineering guarantees in plain language', () => {
    assert.ok(loginPage.includes('Your code is deleted after the run.'), 'code retention guarantee missing');
    assert.ok(loginPage.includes('The score comes from findings only.'), 'deterministic score guarantee missing');
    assert.ok(loginPage.includes('A failed scan says so.'), 'failure honesty guarantee missing');
  });
});

describe('App.tsx integration with credentials & session routing', () => {
  it('wires onPasswordLogin and onRegister handlers to LoginPage', () => {
    assert.ok(app.includes('onPasswordLogin={handlePasswordLogin}'), 'onPasswordLogin binding missing');
    assert.ok(app.includes('onRegister={handleRegister}'), 'onRegister binding missing');
    assert.ok(app.includes('const handlePasswordLogin'), 'handlePasswordLogin implementation missing');
    assert.ok(app.includes('const handleRegister'), 'handleRegister implementation missing');
  });

  it('preserves return-to destination redirect on unauthenticated console access', () => {
    assert.ok(app.includes('returnTo: location.pathname'), 'returnTo state navigation missing');
  });

  it('redirects already-authenticated users away from /login', () => {
    assert.ok(app.includes('if (isLogin && user && authState === \'authenticated\')'), 'authenticated user redirect check missing');
  });
});

describe('login-site.css responsive styling & scoping', () => {
  it('scopes all styles under lg- classes', () => {
    assert.ok(loginCss.includes('.lg-grid'), '.lg-grid missing');
    assert.ok(loginCss.includes('.lg-form-side'), '.lg-form-side missing');
    assert.ok(loginCss.includes('.lg-panel'), '.lg-panel missing');
  });

  it('collapses to one column on small screens', () => {
    assert.ok(loginCss.includes('@media (max-width: 900px)'), 'mobile media query missing');
  });

  it('keeps visible keyboard focus', () => {
    assert.ok(loginCss.includes(':focus-visible'), 'focus-visible styling missing');
  });
});

describe('Turnstile API-only contract (FC-RELEASE-017 finding 3)', () => {
  it('no credential submit path sends a turnstile_token (no widget exists)', () => {
    // The backend rejects tokenless logins with 403 when CF_TURNSTILE_ENABLED
    // is set, but no frontend widget exists and the shipped CSP would block
    // the challenge script — so the flag is API-only until G7 wires the
    // widget. This pins that contract: enabling the flag today bricks browser
    // logins, and the G7 change must deliberately update this test.
    for (const [name, src] of [['LoginPage.tsx', loginPage], ['App.tsx', app]] as const) {
      assert.ok(
        !src.includes('turnstile_token'),
        `${name} must not reference turnstile_token until the G7 widget lands`,
      );
    }
  });
});
