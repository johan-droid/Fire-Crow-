# ☁️ Cloudflare Deployment & Integration Manual — Fire Crow

This guide covers deploying and configuring **Fire Crow** on Cloudflare infrastructure, using Cloudflare Pages for the frontend, Cloudflare R2 for report artifact storage, Cloudflare Tunnels for zero-trust backend access, Cloudflare Turnstile for bot defense, and Cloudflare WAF headers.

---

## 🏗️ Architecture Overview

```mermaid
graph TD
    User[User Browser] -->|HTTPS| CFEdge[Cloudflare Edge Network]
    CFEdge -->|Pages Assets| Pages[Cloudflare Pages (React SPA)]
    CFEdge -->|WAF & Turnstile| WAF[Cloudflare WAF / Turnstile]
    WAF -->|Encrypted Tunnel| Tunnel[Cloudflare Tunnel Connector]
    Tunnel -->|Internal Port 8000| Backend[Axum Rust Server]
    Backend -->|Database| Neon[PostgreSQL / Neon DB]
    Backend -->|Report Artifacts| R2[Cloudflare R2 Bucket]
```

---

## ⚡ 1. Deploy Frontend to Cloudflare Pages

### Prerequisites
- Install Cloudflare CLI (`wrangler` is included in `devDependencies`)
- Log in to your Cloudflare account: `npx wrangler login`

### Command Line Deployment
Run the following build and deploy command from the workspace root:

```bash
# Build Vite static bundle and deploy to Cloudflare Pages
npm run cf:deploy
```

Or from inside `frontend/`:
```bash
cd frontend
npm run deploy
```

### Automatic Git Integration (Cloudflare Dashboard)
1. Go to **Cloudflare Dashboard > Workers & Pages > Create application > Pages > Connect to Git**.
2. Select your `Fire-Crow-` repository.
3. Configure build settings:
   - **Framework preset**: `Vite`
   - **Build command**: `npm run build`
   - **Build output directory**: `dist`
   - **Root directory**: `frontend`
4. Environment Variables:
   - `VITE_BACKEND_URL`: `https://api.firecrow.dev` (Your API domain)

---

## 📦 2. Configure Cloudflare R2 Object Storage

Cloudflare R2 provides zero-egress fee object storage for audit report PDFs, code scan zip archives, and attack graph JSON dumps.

### Step 1: Create an R2 Bucket
1. Open **Cloudflare Dashboard > R2 > Create bucket**.
2. Name your bucket: `firecrow-artifacts`.

### Step 2: Create API Credentials
1. Go to **R2 > Manage R2 API Tokens**.
2. Create an API token with **Object Read & Write** permissions.
3. Note down your `Access Key ID`, `Secret Access Key`, and `Endpoint URL`.

### Step 3: Configure Backend Environment
Add the R2 credentials to your `backend/.env.local` or environment variables:

```env
# Cloudflare R2 Storage Configuration
R2_ACCESS_KEY_ID="your_r2_access_key_id"
R2_SECRET_ACCESS_KEY="your_r2_secret_access_key"
R2_ENDPOINT_URL="https://<ACCOUNT_ID>.r2.cloudflarestorage.com"
R2_BUCKET_NAME="firecrow-artifacts"
```

---

## 🔒 3. Cloudflare Tunnel (Zero Trust Backend Access)

Cloudflare Tunnels expose the Rust Axum backend securely to the internet without opening inbound ports on your server.

### Option A: Using Docker Compose with Cloudflare Tunnel

```bash
# Set your Cloudflare Tunnel token in env
export TUNNEL_TOKEN="eyJh..."

# Launch the full stack behind Cloudflare Tunnel
docker-compose -f backend/cloudflare/docker-compose.cloudflare.yml up -d
```

### Option B: Manual cloudflared setup

1. Install `cloudflared`:
   ```bash
   sudo apt-get install cloudflared
   ```
2. Authenticate and create a tunnel:
   ```bash
   cloudflared tunnel login
   cloudflared tunnel create firecrow-tunnel
   ```
3. Copy `backend/cloudflare/tunnel-config.yml` to `/etc/cloudflared/config.yml` and replace `FIRE_CROW_TUNNEL_ID`.
4. Run the tunnel:
   ```bash
   cloudflared tunnel run firecrow-tunnel
   ```

---

## 🛡️ 4. Cloudflare Turnstile Bot Defense

Cloudflare Turnstile is configured in Fire Crow to protect registration, MFA enrollment, and audit execution endpoints from bot automation.

### Step 1: Create Turnstile Site
1. Go to **Cloudflare Dashboard > Turnstile > Add Site**.
2. Domain: `app.firecrow.dev` (or your custom domain).
3. Widget Mode: **Managed** (or Non-interactive).

### Step 2: Set Environment Variables
Add to `backend/.env.local`:

```env
CF_TURNSTILE_ENABLED=true
CF_TURNSTILE_SITE_KEY="0x4AAAAAA..."
CF_TURNSTILE_SECRET_KEY="0x4AAAAAA..."
```

### Step 3: Test Verification API
Query the built-in Cloudflare status endpoint:

```bash
curl -X GET https://api.firecrow.dev/api/v1/verify/cloudflare/status
```

---

## 🌍 5. Edge Security Headers & Real IP Handling

Fire Crow automatically extracts real client IP addresses from Cloudflare Edge headers:
- `CF-Connecting-IP`: Extracted as visitor IP for authentication logs & rate limiting.
- `CF-Ray`: Logged for request tracing across Cloudflare edge nodes.
- `CF-IPCountry`: Logged in audit telemetry for security analytics.

The included `frontend/public/_headers` file applies HSTS, CSP, and immutability caching for frontend build assets automatically.

---

## 🔍 Verification Checklist

- [x] Frontend builds cleanly: `npm run cf:build`
- [x] Cloudflare Pages router configured (`_redirects` & `wrangler.jsonc`)
- [x] Cloudflare edge security headers added (`_headers`)
- [x] Real Client IP extraction implemented in Axum middleware (`CF-Connecting-IP`)
- [x] Tower-Governor rate limiter updated for Cloudflare edge IPs (`CloudflareKeyExtractor`)
- [x] Cloudflare R2 object storage SDK integration (`aws-sdk-s3` -> R2 endpoint)
- [x] Cloudflare Turnstile siteverify service & status route (`/api/v1/verify/cloudflare/status`)
- [x] Cloudflare Tunnel configuration & Docker Compose template created
