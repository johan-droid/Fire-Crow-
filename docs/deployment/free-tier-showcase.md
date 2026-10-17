# Free Tier Showcase Deployment Guide (Vercel + Render + Docker Daemon)

This guide documents the end-to-end configuration for deploying **Fire Crow** completely on free-tier cloud platforms (Vercel + Render + Remote Docker Daemon) with all features operating properly for live demonstrations and portfolio showcasing.

---

## Architecture Topology (Free Tier)

```mermaid
flowchart TD
    subgraph Clients["Browser Client"]
        Browser["User Browser\n(credentials: include)"]
    end

    subgraph Vercel["Frontend Tier (Vercel Free Tier)"]
        SPA["Fire Crow React 19 SPA\n(Vite Bundle, Security Headers, Google Fonts)"]
    end

    subgraph Render["Backend Tier (Render Free Tier)"]
        API["Axum 0.7 REST + SSE API\n(firecrow-backend Container)"]
        DB[("PostgreSQL 16\n(firecrow-db)")]
    end

    subgraph DockerHost["Scanner Execution Tier (Docker Daemon)"]
        Proxy["docker-socket-proxy (private network only)\nLeast-Privilege Socket Filter"]
        Engine["Docker Engine Runtime\nEphemeral Scanners (Gitleaks, Semgrep, OSV)"]
    end

    Browser -->|HTTPS| SPA
    Browser -->|Cross-Origin HTTPS (SameSite=none)| API
    API -->|Internal SSL| DB
    API -->|"DOCKER_HOST (over authenticated private channel)"| Proxy
    Proxy --> Engine
```

---

## 1. Frontend Deployment (Vercel)

### Step 1: Import Repository
1. Log in to [Vercel](https://vercel.com) and click **Add New... ➔ Project**.
2. Select your `Fire-Crow-` repository.
3. Configure the build parameters:
   - **Framework Preset**: `Vite`
   - **Root Directory**: `./` (or `frontend`)
   - **Build Command**: `npm --prefix frontend run build` (or `npm run build` if Root is `frontend`)
   - **Install Command**: `npm --prefix frontend install`
   - **Output Directory**: `frontend/dist` (or `dist` if Root is `frontend`)

### Step 2: Environment Variables on Vercel
In the Vercel project settings under **Environment Variables**, configure:

| Variable | Value | Description |
| :--- | :--- | :--- |
| `VITE_API_URL` | `https://firecrow-backend.onrender.com` | Base URL of your deployed Render backend (the client appends `/api/v1` automatically; a value ending in `/api/v1` also works) |

---

## 2. Backend & Database Deployment (Render)

Deploying via Render Blueprint (`render.yaml`) automatically provisions both the PostgreSQL database and the web service.

### Step 1: Deploy with Blueprint
1. Log in to [Render](https://render.com) and select **New ➔ Blueprint**.
2. Connect your `Fire-Crow-` repository.
3. Render reads `render.yaml` and sets up:
   - **firecrow-db**: Managed PostgreSQL 16 on Render Free Tier.
   - **firecrow-backend**: Docker Web Service running on Render Free Tier.

### Step 2: Configure Environment Variables in Render Dashboard
Review and complete the environment variables in the Render Dashboard under **firecrow-backend ➔ Environment**:

| Variable | Value | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | *(Auto-wired from `firecrow-db`)* | Connection to PostgreSQL |
| `SECRET_KEY` | *(Auto-generated 48 bytes)* | HMAC signing key for JWTs and session cookies |
| `ENCRYPTION_KEY` | *(Auto-generated 48 bytes)* | AES-256-GCM encryption key for stored secrets |
| `FRONTEND_URL` | `https://your-firecrow-app.vercel.app` | URL of your deployed Vercel frontend |
| `CORS_ORIGINS` | `https://your-firecrow-app.vercel.app` | Whitelisted cross-origin origin |
| `AUTH_COOKIE_SAMESITE` | `none` | **Critical for Cross-Origin Auth**: Allows browsers to send session cookies between Vercel and Render |
| `AUTH_COOKIE_SECURE` | `true` | Mandated by modern browsers when `SameSite=none` is used |
| `DOCKER_HOST` | `tcp://<proxy-mesh-hostname>:2375` | Endpoint of the least-privilege Docker socket proxy, reachable **only** over an authenticated private network (Tailscale/WireGuard mesh) — never a public IP |
| `GEMINI_API_KEY` | `AIzaSy...` | Google Gemini API key for automated executive narrative reports |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Optimized model for fast, deterministic security summaries |

---

## 3. Scanner Execution on Render — Not Supported

> **Render Free Tier cannot run Fire Crow's scanner workload.** The G1
> egress-isolation control depends on Docker network primitives
> (`internal: true` networks + a proxy sidecar). Render provides no equivalent,
> and its free-tier web services cannot configure the host Docker daemon with
> Fire Crow's authorization plugin or run a privileged nested daemon.

**Real scanner execution is BLOCKED on Render.** This is a hard limitation, not
a configuration gap. Do not present Render free tier as a supported
real-scanning environment.

### What this means in practice

- The frontend health probe (`/api/v1/health/deep`) returns `"docker": "unavailable"`.
- The scan modal displays an error: "Scan engine unavailable in this deployment —
  the backend cannot reach a Docker daemon, so audits cannot run here."
- If a scan is somehow submitted, the pipeline runs, scanners fail at the
  `docker run` step, and the job finalizes as `failed` — never as a clean result.

### Supported deployment architecture

Real scanner execution requires a Docker-capable host where the operator controls
the daemon configuration. See **`docs/deployment/backend.md`** for the full
guide, including:

- mTLS authentication between backend and daemon
- Docker authorization plugin (content-level boundary)
- Scanner image pinning (gitleaks v8.18.4, OSV v2.2.4, Semgrep 1.96.0)
- Restricted networking (`scanners-internal` network + egress-proxy sidecar)
- Resource limits (CPU, memory, PID ceilings)
- Container cleanup (`--rm` + force-remove on timeout/cancel)

### Hard requirement: no public Docker endpoint

The Docker API has no meaningful authentication of its own. A plain `tcp://` port `2375` endpoint reachable from the public internet is a full host-compromise vector — **even behind TLS**, because TLS only encrypts the channel: it grants no authorization. Never publish the daemon or the socket proxy on a public IP.



---

## 4. Verifying Showcase Health

Once both services are deployed, verify capability readiness:

1. **Readiness Probe**:
   ```bash
   curl -s https://firecrow-backend.onrender.com/api/v1/health/ready
   # Output: {"status":"ready","database":"connected"}
   ```
2. **Capability Check**:
   ```bash
   curl -s https://firecrow-backend.onrender.com/api/v1/health/deep
   # Output: {"status":"healthy","database":"ok","local_storage":"ok","docker":"configured","version":"1.0.0"}
   ```
3. **Frontend Connection**:
   - Open your Vercel URL `https://your-firecrow-app.vercel.app` in your browser.
   - Verify the top navigation bar displays the green **Online** status indicator.
   - Submit a test repository audit to verify secret, dependency, and SAST scanner passes.
