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
        Proxy["docker-socket-proxy (Port 2375)\nLeast-Privilege Socket Filter"]
        Engine["Docker Engine Runtime\nEphemeral Scanners (Gitleaks, Semgrep, OSV)"]
    end

    Browser -->|HTTPS| SPA
    Browser -->|Cross-Origin HTTPS (SameSite=none)| API
    API -->|Internal SSL| DB
    API -->|DOCKER_HOST tcp://...:2375| Proxy
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
| `VITE_API_URL` | `https://firecrow-backend.onrender.com` | Base URL of your deployed Render backend |
| `VITE_APP_NAME` | `FireCrow` | Application brand name |

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
| `DOCKER_HOST` | `tcp://<docker-host>:2375` | Endpoint of the Docker daemon / socket proxy |
| `GEMINI_API_KEY` | `AIzaSy...` | Google Gemini API key for automated executive narrative reports |
| `GEMINI_MODEL` | `gemini-1.5-flash` | Optimized model for fast, deterministic security summaries |

---

## 3. Providing the Docker Daemon for Ephemeral Scanners

Fire Crow requires access to a Docker daemon to launch isolated micro-containers for **Gitleaks**, **Semgrep**, and **OSV-Scanner**. Because Render Free Tier web services do not run host Docker engines or allow `/var/run/docker.sock` mounts, you provide Docker access through `DOCKER_HOST`.

### Option A: Free Cloud Virtual Machine (Oracle Cloud / AWS EC2 / Fly.io)
Deploy `docker-socket-proxy` on an unmetered free tier Linux instance (e.g., Oracle Cloud Always Free 1-4 OCPU ARM instance or AWS EC2 t4g.small):

1. Clone `Fire-Crow-` on the instance and launch the filtered proxy:
   ```bash
   docker compose up -d docker-socket-proxy
   ```
2. The proxy exposes port `2375` restricted to container operations (`CONTAINERS: 1`, `IMAGES: 1`, `ALLOW_START: 1`).
3. Set in Render:
   ```env
   DOCKER_HOST=tcp://your-vps-ip:2375
   ```

### Option B: Cloudflare Tunnel / Tailscale to Local Docker (For Live Demos)
If showcasing Fire Crow live during an interview, portfolio review, or hackathon:

1. Start the proxy locally:
   ```bash
   docker compose up -d docker-socket-proxy
   ```
2. Expose port `2375` using Cloudflare Tunnel or Tailscale:
   ```bash
   cloudflared tunnel --url tcp://localhost:2375
   ```
3. Set the tunnel domain in Render as `DOCKER_HOST=tcp://<tunnel-domain>:2375`.

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
