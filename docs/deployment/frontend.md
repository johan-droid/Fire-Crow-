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
| `VITE_APP_NAME` | All Environments | `FireCrow` | Display name for header and title tags. |

---

## 3. Fail-Closed Routing & `vercel.json`

The frontend routing is governed by `frontend/vercel.json`:

```json
{
  "rewrites": [
    { "source": "/(.*)", "destination": "/index.html" }
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
