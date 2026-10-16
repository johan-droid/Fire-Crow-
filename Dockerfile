# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy backend manifests and source code from repository root
COPY backend/Cargo.toml backend/Cargo.lock ./
COPY backend/src ./src
COPY backend/migrations ./migrations
COPY backend/scanners ./scanners

# Build release binary with optimization
RUN cargo build --release --locked --bin firecrow-backend

# Runtime stage
FROM debian:bookworm-slim AS runner

WORKDIR /app

# Install runtime dependencies including docker CLI for containerized scanner execution
# F-G2-05: The bundled Docker CLI must speak API >= 1.44 (daemon MinAPIVersion).
# Debian bookworm's docker.io package is pinned to 20.10/24.0 (API 1.41/1.43),
# which is below the minimum. Download the official Docker CLI binary instead.
ARG DOCKER_CLI_VERSION=29.1.3
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
    | tar -xz -C /usr/local/bin --strip-components=1 docker/docker \
    && rm -rf /var/lib/apt/lists/*

# Create a dedicated non-root runtime user and application directories.
# Phase A (F1): the backend reaches Docker only through the least-privilege
# socket proxy (DOCKER_HOST); it holds no Docker socket mount and needs no
# root privileges of its own. Numeric UID/GID so the identity survives image
# rebuilds and user-namespace remapping. No over-broad permission workarounds:
# owned directories carry the ownership instead.
RUN groupadd --system --gid 10001 firecrow \
    && useradd --system --uid 10001 --gid firecrow --no-create-home \
        --shell /bin/false firecrow \
    # All four workspace dirs the app creates at boot (config::ensure_workspace_dirs)
    # must pre-exist here: the compose profile runs this image with
    # `read_only: true`, so create_dir_all at startup would hit EROFS and abort.
    # Only workspace/storage is a mounted volume; the rest are boot-time
    # layout only (runtime temp goes to /tmp, a tmpfs).
    && mkdir -p /app/workspace/storage /app/workspace/reports /app/workspace/temp /app/workspace/scans /app/scanners/semgrep \
    && chown -R 10001:10001 /app/workspace /app/scanners \
    # T1 (mTLS): the backend connects to the Docker daemon over TLS. The
    # client certificate is mounted read-only at /etc/firecrow/docker-tls.
    && mkdir -p /etc/firecrow/docker-tls \
    && chown -R 10001:10001 /etc/firecrow/docker-tls

# Copy compiled binary from builder
COPY --from=builder /app/target/release/firecrow-backend /usr/local/bin/firecrow-backend

# Copy migrations and scanner rulepack
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/scanners /app/scanners

ENV HOST=0.0.0.0
ENV PORT=8000

EXPOSE 8000

# FC-CONTRACT-01: the runtime port is injected by the platform (Render sets
# PORT); the healthcheck must follow it instead of assuming 8000.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f "http://localhost:${PORT:-8000}/health" || exit 1

# Phase A (F1): never root. Port 8000 needs no privilege; the workspace the
# backend writes to is owned by this user (see above).
USER 10001:10001

CMD ["firecrow-backend"]
