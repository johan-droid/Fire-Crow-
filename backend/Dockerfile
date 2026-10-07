# syntax=docker/dockerfile:1
FROM rust:1.85-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy backend manifests and source code
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY scanners ./scanners

# Build release binary with optimization
RUN cargo build --release --bin firecrow-backend

# Runtime stage
FROM debian:bookworm-slim AS runner

WORKDIR /app

# Install runtime dependencies including docker CLI for containerized scanner execution
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    docker.io \
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
    && mkdir -p /app/workspace/storage /app/scanners/semgrep \
    && chown -R 10001:10001 /app/workspace /app/scanners

# Copy compiled binary from builder
COPY --from=builder /app/target/release/firecrow-backend /usr/local/bin/firecrow-backend

# Copy migrations and scanner rulepack
COPY --from=builder /app/migrations /app/migrations
COPY --from=builder /app/scanners /app/scanners

ENV HOST=0.0.0.0
ENV PORT=8000
ENV WORKSPACE_DIR=/app

EXPOSE 8000

HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/health || exit 1

# Phase A (F1): never root. Port 8000 needs no privilege; the workspace the
# backend writes to is owned by this user (see above).
USER 10001:10001

CMD ["firecrow-backend"]
