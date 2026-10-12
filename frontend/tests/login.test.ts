import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const SRC = join(process.cwd(), 'src');
const loginPage = readFileSync(join(SRC, 'LoginPage.tsx'), 'utf8');
const app = readFileSync(join(SRC, 'App.tsx'), 'utf8');
const authCss = readFileSync(join(SRC, 'auth.css'), 'utf8');

describe('LoginPage structural & a11y standards', () => {
  it('exposes accessible input controls with labels and describedby error links', () => {
    assert.ok(loginPage.includes('id="fc-auth-identifier"'), 'identifier input id missing');
    assert.ok(loginPage.includes('id="fc-auth-password"'), 'password input id missing');
    assert.ok(loginPage.includes('aria-describedby'), 'error description linkage missing');
    assert.ok(loginPage.includes('aria-invalid='), 'aria-invalid binding missing');
    assert.ok(loginPage.includes('htmlFor="fc-auth-identifier"'), 'identifier label missing');
    assert.ok(loginPage.includes('htmlFor="fc-auth-password"'), 'password label missing');
  });

  it('exposes an accessible password visibility toggle with aria state', () => {
    assert.ok(loginPage.includes('fc-auth-pw-toggle'), 'password toggle button missing');
    assert.ok(loginPage.includes('aria-label='), 'toggle aria-label missing');
    assert.ok(loginPage.includes('aria-pressed='), 'toggle aria-pressed state missing');
    assert.ok(loginPage.includes('showPassword ?'), 'password type toggle condition missing');
  });

  it('announces errors within an assertive alert container', () => {
    assert.ok(loginPage.includes('role="alert"'), 'alert role missing');
    assert.ok(loginPage.includes('aria-live="assertive"'), 'assertive aria-live attribute missing');
  });

  it('prevents duplicate submissions via disabled states', () => {
    assert.ok(loginPage.includes('disabled={isSubmitting}'), 'submit button disabled guard missing');
    assert.ok(loginPage.includes('fc-auth-spinner'), 'loading spinner missing');
  });

  it('contains Next Lab studio endorsement and Fire Crow product symbols', () => {
    assert.ok(loginPage.includes('NextLabSymbol'), 'NextLabSymbol missing');
    assert.ok(loginPage.includes('FireCrowSymbol'), 'FireCrowSymbol missing');
    assert.ok(loginPage.includes('NEXT LAB'), 'NEXT LAB text missing');
  });

  it('contains the three deterministic engineering guarantees', () => {
    assert.ok(loginPage.includes('Zero Code Retention'), 'Zero Code Retention guarantee missing');
    assert.ok(loginPage.includes('Deterministic Ledgers'), 'Deterministic Ledgers guarantee missing');
    assert.ok(loginPage.includes('Airgapped Execution'), 'Airgapped Execution guarantee missing');
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

describe('auth.css responsive styling & token scoping', () => {
  it('scopes all styles under fc-auth classes', () => {
    assert.ok(authCss.includes('.fc-auth-shell'), '.fc-auth-shell missing');
    assert.ok(authCss.includes('.fc-auth-container'), '.fc-auth-container missing');
    assert.ok(authCss.includes('.fc-auth-brand-panel'), '.fc-auth-brand-panel missing');
    assert.ok(authCss.includes('.fc-auth-form-panel'), '.fc-auth-form-panel missing');
  });

  it('supports responsive collapsing on mobile screens', () => {
    assert.ok(authCss.includes('@media (max-width: 860px)'), 'mobile media query missing');
    assert.ok(authCss.includes('.fc-auth-mobile-brand'), 'mobile brand element missing');
  });

  it('supports prefers-reduced-motion', () => {
    assert.ok(authCss.includes('@media (prefers-reduced-motion: reduce)'), 'prefers-reduced-motion missing');
  });
});
