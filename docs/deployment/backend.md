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
> **Docker Daemon Access**: Because the Axum backend spawns ephemeral Docker micro-containers for Gitleaks, Semgrep, and OSV-Scanner, the host runner must have the Docker daemon running and the socket accessible. On Render, select an environment with Docker engine support or deploy on a Linux Virtual Machine (e.g. AWS EC2 / DigitalOcean Droplet / Hetzner).
