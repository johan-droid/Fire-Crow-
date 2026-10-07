# syntax=docker/dockerfile:1
FROM rust:1.82-bookworm AS builder

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

# Create application workspace and configuration directories
RUN mkdir -p /app/workspace/storage /app/scanners/semgrep

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

CMD ["firecrow-backend"]
