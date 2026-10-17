# syntax=docker/dockerfile:1
FROM rust:1-bookworm AS builder

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

# Native scanner binaries for the docker-free execution mode
# (SCANNER_EXECUTION_MODE=native). Pinned to the SAME versions as the container
# images, and each verified against its published SHA-256 before installation —
# a swapped or corrupted download fails the build rather than shipping a
# tampered scanner. Semgrep is deliberately NOT installed here: it is a large
# Python toolchain whose runtime memory footprint exceeds the free tier, so
# native mode reports it unavailable (partial coverage, never clean) rather than
# bloating the image. See docs/deployment/native-scanning.md.
ARG GITLEAKS_VERSION=8.18.4
ARG GITLEAKS_SHA256=ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d
ARG OSV_SCANNER_VERSION=2.2.4
ARG OSV_SCANNER_SHA256=7702cd1e5d9f5059dd9570f4ad967f27d3c5f5391b371ec937b384c238177f55
RUN set -eu; \
    curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tgz" | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks.tgz; \
    curl -fsSL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_amd64"; \
    echo "${OSV_SCANNER_SHA256}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/gitleaks /usr/local/bin/osv-scanner

# Create a dedicated non-root runtime user and application directories.
# Phase A (F1): the backend reaches Docker only through the mTLS channel
# (DOCKER_HOST=tcp://...:2376); it holds no Docker socket mount and needs no
# root privileges of its own. Numeric UID/GID so the identity survives image
# rebuilds and user-namespace remapping. No over-broad permission workarounds:
# owned directories carry the ownership instead.
RUN groupadd --system --gid 10001 firecrow \
    && useradd --system --uid 10001 --gid firecrow --no-create-home \
        --shell /bin/false firecrow \
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
# Default only: Render injects the real runtime PORT at deploy time and the
# Rust service reads it (config crate Environment source, no prefix). Local
# `docker run`/compose without an explicit -e PORT keeps working on 8000.
ENV PORT=8000
ENV CONTAINER=true

EXPOSE 8000

# Shell form (not exec/JSON form) so $PORT expands at container runtime:
# the probe follows wherever the platform told the app to listen. Render's
# own healthCheckPath (/health, see render.yaml) probes independently of this.
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD sh -c 'curl -f http://localhost:${PORT:-8000}/health || exit 1'

# Phase A (F1): never root. Port 8000 needs no privilege; the workspace the
# backend writes to is owned by this user (see above).
USER 10001:10001

CMD ["firecrow-backend"]
