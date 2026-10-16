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

## 3. Providing the Docker Daemon for Ephemeral Scanners

Fire Crow requires access to a Docker daemon to launch isolated micro-containers for **Gitleaks**, **Semgrep**, and **OSV-Scanner**. Because Render Free Tier web services do not run host Docker engines or allow `/var/run/docker.sock` mounts, you provide Docker access through `DOCKER_HOST`.

> **Important — scanner isolation is unavailable on Render.** The G1
> egress-isolation control depends on Docker network primitives
> (`internal: true` networks + a proxy sidecar). Render provides no equivalent,
> so **Render is not a supported platform for the scanner workload**. The
> guidance below describes how to point the *backend* at a Docker daemon, but
> doing so does not reproduce the enforced egress boundary that the supported
> Docker Compose architecture provides. See the egress acceptance report in
> `evidence/FC-FINAL-20261016/FC-EGRESS-ACCEPTANCE.md`.

### Hard requirement: no public Docker endpoint

The Docker API has no meaningful authentication of its own. A plain `tcp://` port `2375` endpoint reachable from the public internet is a full host-compromise vector — **even behind TLS**, because TLS only encrypts the channel: it grants no authorization, so anyone who can complete the handshake has unrestricted Docker API access. Never publish the daemon or the socket proxy on a public IP, and never front it with a public tunnel URL. Instead:

- Reach the daemon only through an **authenticated, mutually-authenticated (mTLS) private channel**, with the daemon's authorization plugin enabled.
- The **Docker authorization plugin** (`docker-authz-plugin/`) is the actual content boundary: it inspects request bodies at the daemon and denies privileged creates, host binds, capability additions, and dangerous endpoints. A path/method socket proxy alone is a category filter, not a containment boundary — it cannot see request bodies.
- Reach the daemon only through an **authenticated private channel** (the two options below).

The authorization plugin plus mTLS is the boundary in both options: the backend never touches `/var/run/docker.sock` directly, and the plugin's deny-by-default policy (`Privileged: false`, `CapDrop: [ALL]`, approved images only, `firecrow-scan-*` names only) caps what a compromised backend could ask Docker to do — but only if the endpoint is unreachable except through the mTLS channel.

### Option A: Free Cloud Virtual Machine (Oracle Cloud / AWS EC2 / Fly.io)
Deploy the daemon with the authorization plugin on an unmetered free tier Linux instance (e.g., Oracle Cloud Always Free 1-4 OCPU ARM instance or AWS EC2 t4g.small):

1. Clone `Fire-Crow-` on the instance, generate certificates, and start the daemon with the plugin:
   ```bash
   scripts/generate-docker-tls-certs.sh certs/docker-tls
   # daemon flags: --authorization-plugin=firecrow --tlsverify --tlscacert/--tlscert/--tlskey
   ```
2. The TLS listener stays bound to the instance's private interface only — do **not** publish port `2376` to the public internet.
3. Join the Render backend and the instance to the same private mesh network (e.g., Tailscale or WireGuard), then set in Render:
   ```env
   DOCKER_HOST=tcp://<daemon-mesh-hostname>:2376
   DOCKER_TLS_VERIFY=1
   DOCKER_CERT_PATH=/etc/firecrow/docker-tls
   ```
   The hostname must only resolve and connect inside the authenticated mesh.

### Option B: Cloudflare Tunnel / Tailscale to Local Docker (For Live Demos)
If showcasing Fire Crow live during an interview, portfolio review, or hackathon:

1. Start the daemon with the authorization plugin and mTLS locally (bound to a private interface only):
   ```bash
   scripts/generate-docker-tls-certs.sh certs/docker-tls
   ```
2. Reach it over an authenticated private channel only:
   - **Tailscale**: add the machine to your tailnet and point `DOCKER_HOST` at the daemon's tailnet address (peers must be logged into your tailnet to connect).
   - **cloudflared**: use a Cloudflare Tunnel with an Access-protected **private network** route, so only members with valid Access credentials can connect.
   - Do **not** run `cloudflared tunnel --url tcp://localhost:2376` or any other public quick-tunnel URL: that republishes a Docker endpoint for anyone on the internet.
3. Set the private endpoint in Render as `DOCKER_HOST=tcp://<daemon-mesh-hostname>:2376` with the TLS variables above.

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
