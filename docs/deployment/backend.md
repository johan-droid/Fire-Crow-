# Backend Deployment Guide (Render & Cloud Hosts)

This guide documents the production deployment of the FireCrow Axum backend service to **Render** or custom Linux container environments.

---

## 1. Multi-Stage Dockerfile Architecture (`backend/Dockerfile`)

The backend is packaged using a multi-stage Docker build optimizing for small image size and minimal attack surface:

```dockerfile
# Stage 1: Build binary
FROM rust:1.85-bookworm AS builder
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
    name: firecrow-api
    env: docker
    dockerfilePath: backend/Dockerfile
    dockerContext: backend
    plan: standard
    region: oregon
    healthCheckPath: /health
    envVars:
      - key: PORT
        value: 8080
      - key: DATABASE_URL
        fromDatabase:
          name: firecrow-db
          property: connectionString
      - key: SESSION_SECRET
        generateValue: true
      - key: JWT_SECRET
        generateValue: true
      - key: JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        value: "15"
      - key: CORS_ALLOWED_ORIGINS
        value: "https://firecrow.dev,https://www.firecrow.dev"
      - key: GEMINI_API_KEY
        sync: false
      - key: GEMINI_MODEL
        value: "gemini-1.5-flash"
      - key: WORK_DIR
        value: "/tmp/firecrow"
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
