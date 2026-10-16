# ADR 004: Fail-Closed Frontend Routing and Separation of Backend Origin

## Status
**Accepted**

## Context
In modern Jamstack and SPA deployments, developers frequently configure edge rewrites in platforms like Vercel or Netlify (e.g. `/api/*` ➔ `https://api.backend-host.com/:splat`) to avoid configuring CORS during early development.

However, this pattern introduces severe production security and operational vulnerabilities:
1. **Preview Environment Leakage**: When developers push a branch or open a pull request, Vercel creates an ephemeral preview deployment (e.g., `fire-crow-git-feat-test.vercel.app`). If `vercel.json` contains a hardcoded `/api` proxy rule pointing to production or staging backends, untrusted preview deployments could issue mutating requests, submit fake audits, or abuse backend API rate limits.
2. **Masked CORS Misconfigurations**: Edge-level proxying masks browser-level CORS requirements, leading to unexpected failures when external integrations or alternate frontends connect.
3. **Session Cookie Confusion**: Proxying cross-domain traffic through the same domain creates ambiguity around cookie domains, potentially exposing session cookies across preview subdomains.

## Decision
FireCrow enforces **Fail-Closed Frontend Routing** and explicit cross-origin separation:
1. **No Backend Proxy in `vercel.json`**: The `vercel.json` configuration contains strictly a client-side Single Page Application fallback rewrite:
   ```json
   {
     "cleanUrls": true,
     "rewrites": [
       { "source": "/(.*)", "destination": "/" }
     ]
   }
   ```
   > **Amendment (2026-10-17).** The original example used `"destination": "/index.html"`.
   > With `cleanUrls: true` Vercel strips the extension, so that destination resolved to
   > `/index` and the SPA fallback silently broke — every deep link returned a 404. The
   > decision is unchanged; only the destination form is corrected. See
   > `docs/deployment/frontend.md` §3 and the guard in `frontend/tests/routing.test.ts`.
2. **Explicit Client-Side Origin Target**: The frontend client (`api.ts`) sends requests directly to the backend origin configured via the `VITE_API_URL` environment variable (e.g., `https://api.firecrow.dev`). If `VITE_API_URL` is omitted, requests default safely to `/api`, which fails closed with 404 in decoupled deployments, preventing accidental data transfer.
3. **Strict Backend CORS Whitelisting**: The Axum backend explicitly validates the `Origin` header against an allowlist configured via `CORS_ALLOWED_ORIGINS` (e.g., `https://firecrow.dev,https://staging.firecrow.dev`).

## Consequences
### Positive
- **Zero Risk of Accidental Proxying**: Vercel preview builds cannot automatically forward traffic to production backend clusters.
- **Fail-Closed Security Posture**: A misconfigured frontend fails immediately and visibly rather than silently forwarding sensitive tokens to wrong destinations.
- **Clean Cookie Isolation**: Session cookies set with `SameSite=Lax` and explicit domain boundaries prevent cross-subdomain tampering.

### Negative / Trade-offs
- Local development requires either running both services on configured ports with CORS enabled, or using Vite's local dev server proxy configured in `vite.config.ts`.
