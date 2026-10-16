# Frontend Deployment Guide (Vercel)

This guide documents the production deployment of the FireCrow React 19 single-page application to **Vercel**.

---

## 1. Vercel Project Configuration

| Setting | Value | Rationale |
| :--- | :--- | :--- |
| **Framework Preset** | `Vite` | Automatically configures build commands and output directories. |
| **Root Directory** | `frontend` | Isolates frontend build from backend Rust crates. |
| **Build Command** | `npm run build` | Compiles TypeScript and creates optimized Vite bundle in `dist/`. |
| **Output Directory** | `dist` | Contains compiled HTML, JS, CSS, and static assets. |
| **Node.js Version** | `20.x` | Aligns with LTS runtime. |

---

## 2. Environment Variables Configuration

Set these variables in the **Vercel Project Settings ➔ Environment Variables**:

| Variable | Target Environment | Production Example | Description |
| :--- | :--- | :--- | :--- |
| `VITE_API_URL` | Production & Preview | `https://api.firecrow.dev` | Fully qualified domain of the Axum backend service. |

---

## 3. Fail-Closed Routing & `vercel.json`

The frontend routing is governed by `frontend/vercel.json`:

```json
{
  "cleanUrls": true,
  "rewrites": [
    { "source": "/(.*)", "destination": "/" }
  ],
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "X-XSS-Protection", "value": "1; mode=block" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" }
      ]
    }
  ]
}
```

> **`cleanUrls` and the catch-all rewrite.** With `cleanUrls: true`, Vercel strips
> the extension from rewrite destinations. A destination of `/index.html`
> therefore resolves to `/index`, which does not exist — the SPA fallback
> silently stops working and every deep link (`/login`, `/console/overview`)
> returns Vercel's branded 404 (whose inline script is then blocked by the CSP
> above, producing misleading console errors). Use `"/"` as the destination, or
> drop `cleanUrls`. `frontend/tests/routing.test.ts` fails if a `.html`
> destination is ever reintroduced under `cleanUrls`.

### Dry run: the config invariants CI enforces

Configuration that is *present* but silently ineffective is this project's
recurring failure shape, so the invariants are asserted against the real files
rather than left to review:

| Invariant | Enforced by |
| --- | --- |
| SPA fallback exists; no `.html` rewrite destination under `cleanUrls` | `frontend/tests/routing.test.ts` |
| The two `vercel.json` files (root and `frontend/`) never drift in rewrites or security headers | `frontend/tests/deploy-config.test.ts` |
| The shipped CSP permits every resource `index.html` references and forbids inline script/handlers | `frontend/tests/deploy-config.test.ts` |
| Every env key `render.yaml` sets is actually read by the backend (a typo would otherwise be set and ignored) | `backend/src/config.rs` (`every_render_yaml_env_key_is_read_by_the_backend`) |
| `render.yaml` never pins `PORT`; the Docker healthcheck follows `$PORT` | `backend/src/config.rs` |

Run them locally with `npm test` (frontend) and `cargo test` (backend).

### Architectural Rationale: Absence of `/api` Proxy Rewrite
In traditional setups, developers often configure a rewrite like:
```json
{ "source": "/api/(.*)", "destination": "https://api.backend.com/api/$1" }
```
**In FireCrow, this proxy rewrite is strictly absent.**
- **Preview Isolation**: Ephemeral preview branches cannot accidentally proxy requests to production or staging backend servers.
- **Fail-Closed Security**: If `VITE_API_URL` is omitted or points to an invalid host, the browser fails closed immediately instead of routing through ambiguous edge proxies.
- **Clean Cross-Origin Boundary**: Direct fetch requests with `credentials: 'include'` leverage standard browser CORS mechanisms, ensuring the backend's `CORS_ALLOWED_ORIGINS` policy remains the authoritative gatekeeper.

---

## 4. Verification After Vercel Deployment

1. Check deployment URL in browser: `https://firecrow.dev`
2. Verify asset loads: `index.html`, hashed JS chunks, and `fire-crow-logo.png`.
3. Open Developer Tools Network tab:
   - Ensure requests to `/api/auth/session` route to `https://api.firecrow.dev/api/auth/session` (or configured API URL).
   - Ensure responses return with valid CORS headers (`Access-Control-Allow-Origin: https://firecrow.dev`).
