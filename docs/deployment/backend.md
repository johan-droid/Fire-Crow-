# Backend Deployment Guide (Render & Cloud Hosts)

This guide documents the production deployment of the FireCrow Axum backend service to **Render** or custom Linux container environments.

---

## 1. Multi-Stage Dockerfile Architecture (`backend/Dockerfile`)

The backend is packaged using a multi-stage Docker build optimizing for small image size and minimal attack surface:

```dockerfile
# Stage 1: Build binary
FROM rust:1-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY scanners ./scanners
RUN cargo build --release --locked

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim AS runner
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libssl3 \
    docker.io \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/target/release/firecrow /app/firecrow
COPY --from=builder /app/scanners /app/scanners
COPY migrations /app/migrations

ENV PORT=8080
ENV HOST=0.0.0.0
ENV WORK_DIR=/tmp/firecrow

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

ENTRYPOINT ["/app/firecrow"]
```

---

## 2. Infrastructure as Code Blueprint (`render.yaml`)

```yaml
services:
  - type: web
    name: firecrow-backend
    env: docker
    dockerfilePath: backend/Dockerfile
    dockerContext: backend
    plan: free
    region: oregon
    healthCheckPath: /health
    envVars:
      - key: DATABASE_URL
        fromDatabase:
          name: firecrow-db
          property: connectionString
      - key: SECRET_KEY
        generateValue: true
      - key: ENCRYPTION_KEY
        generateValue: true
      - key: FRONTEND_URL
        sync: false
      - key: CORS_ORIGINS
        sync: false
      - key: AUTH_COOKIE_SAMESITE
        value: "none"
      - key: AUTH_COOKIE_SECURE
        value: "true"
      - key: DOCKER_HOST
        sync: false
      # T1 (mTLS): the backend authenticates to the Docker daemon with a
      # client certificate. DOCKER_TLS_VERIFY and DOCKER_CERT_PATH are fixed
      # constants in sandbox.rs; the certificate material must be mounted at
      # /etc/firecrow/docker-tls. The daemon must run the authorization plugin.
      - key: DOCKER_TLS_VERIFY
        value: "1"
      - key: DOCKER_CERT_PATH
        value: "/etc/firecrow/docker-tls"
      - key: GEMINI_API_KEY
        sync: false
      - key: GEMINI_MODEL
        value: "gemini-1.5-flash"
      - key: REDIS_URL
        sync: false
      # NOTE (FC-RELEASE-017 finding 7): no WORKSPACE_DIR key. The binary's
      # workspace base is the compile-time config::WORKSPACE_DIR
      # (env!("CARGO_MANIFEST_DIR") == /app via the builder WORKDIR); a
      # runtime value would be silently ignored, so no such variable is set.

databases:
  - name: firecrow-db
    databaseName: firecrow
    user: firecrow
    plan: free
    region: oregon
```

---

## 3. Database Connection & Pool Sizing

- **Managed Database**: PostgreSQL 16 (Neon Serverless Postgres or AWS RDS).
- **SSL Mandate**: Production connection strings must include `sslmode=require`.
- **Pool Sizing**:
  - `max_connections`: 20 per backend instance.
  - `min_connections`: 5 idle.
  - `connect_timeout`: 10 seconds.
- **Migration Execution**: Migrations in `backend/migrations/` execute automatically upon startup via SQLx migrator or manually via CI deployment step.

---

## 4. Host Sizing & Scaling Guidelines

| Component | Minimum Specification | Recommended Production |
| :--- | :--- | :--- |
| **CPU** | 1 vCPU | 2–4 vCPUs |
| **RAM** | 2 GB | 4 GB – 8 GB |
| **Ephemeral Disk** | 10 GB SSD | 30 GB SSD |
| **Docker Socket** | Mounted `/var/run/docker.sock` | Mounted `/var/run/docker.sock` |

> [!IMPORTANT]
> **Docker Daemon Access**: Because the Axum backend spawns ephemeral Docker micro-containers for Gitleaks, Semgrep, and OSV-Scanner, the host runner must have the Docker daemon running and reachable. **Render Free Tier is NOT supported** — its web services cannot configure the host Docker daemon with the required authorization plugin or enforce the network isolation boundary. Deploy on a Docker-capable host you control (e.g. AWS EC2 / DigitalOcean Droplet / Hetzner / Oracle Cloud free tier).

## 5. Supported Docker-Host Deployment Architecture

Real scanner execution requires a host where the operator controls the Docker daemon configuration. The backend connects to the daemon exclusively through an mTLS channel; it never mounts `/var/run/docker.sock` directly.

### 5.1 mTLS Authentication

The backend authenticates to the Docker daemon with a client certificate:

```bash
scripts/generate-docker-tls-certs.sh certs/docker-tls
# Daemon flags: --authorization-plugin=firecrow --tlsverify --tlscacert/--tlscert/--tlskey
```

The backend's environment:

```env
DOCKER_HOST=tcp://<daemon-host>:2376
DOCKER_TLS_VERIFY=1
DOCKER_CERT_PATH=/etc/firecrow/docker-tls
```

`DOCKER_TLS_VERIFY` and `DOCKER_CERT_PATH` are fixed constants in `sandbox.rs`; only `DOCKER_HOST` is operator configuration. The certificate is mounted read-only at `/etc/firecrow/docker-tls`.

### 5.2 Docker Authorization Plugin

The daemon runs with `--authorization-plugin=firecrow`. This plugin is the content-level boundary: it inspects request bodies at the daemon and denies privileged creates, host binds, capability additions, and dangerous endpoints. A path/method socket proxy alone is a category filter, not a containment boundary — it cannot see request bodies.

Source: `docker-authz-plugin/` directory. The plugin's deny-by-default policy: `Privileged: false`, `CapDrop: [ALL]`, approved images only, `firecrow-scan-*` names only.

### 5.3 Scanner Image Pinning

Three scanners run in ephemeral containers, all pinned to explicit versions (never `latest`):

| Scanner | Image | Network |
|---------|-------|---------|
| Gitleaks (secrets) | `ghcr.io/gitleaks/gitleaks:v8.18.4` | `--network=none` |
| OSV-Scanner (dependencies) | `ghcr.io/google/osv-scanner:v2.2.4` | `--network=scanners-internal` |
| Semgrep (SAST) | `semgrep/semgrep:1.96.0` | `--network=none` |

### 5.4 Restricted Networking

OSV-Scanner is the sole scanner with network access. It attaches **only** to the `scanners-internal` network (`internal: true`, no external route). Egress flows solely through the filtering-proxy sidecar (`egress-proxy` on port 3128). Scanner containers have no direct external route — the sidecar is the only path out.

The OSV egress proxy enforces a strict allowlist: `api.osv.dev` and `osv.dev` on ports 443/53 only. All other destinations are blocked (loopback, RFC1918, cloud metadata, documentation ranges).

Provision the network before first `up`:
```bash
docker network create --driver bridge --internal --subnet 172.28.0.0/16 --name scanners-internal
```

### 5.5 Resource Limits

Every scanner run is bounded:

| Resource | Gitleaks | OSV-Scanner | Semgrep |
|----------|----------|-------------|---------|
| CPU | 1.0 | 1.0 | 2.0 |
| Memory | 512m | 512m | 2g |
| PID limit | 256 | 256 | 512 |
| Timeout | 300s | 300s | 600s |
| stdout cap | 16MB | 16MB | 16MB |
| stderr cap | 1MB | 1MB | 1MB |

The sandbox also enforces: `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`, `--user=65534:65534` (nobody), `--init` (tini as PID 1), and `--rm` (auto-remove on exit).

### 5.6 Container Cleanup

- `--rm` flag: Docker removes the container on normal exit.
- On timeout or cancellation: the backend force-removes the container by name (`docker rm -f <name>`).
- Output streams are capped during streaming (not buffered), so a scanner cannot exhaust worker memory.
- A scanner that floods stdout/stderr is reported as `FAILED`, never as a result.
