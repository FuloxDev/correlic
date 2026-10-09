# Correlic All-in-One Docker Image
# Bundles: PostgreSQL 16 + Neo4j 5 + Backend (API+Telemetry) + Agent (eBPF) + UI + Proxy
#
# Usage:
#   docker run -d --name correlic --restart unless-stopped \
#     --privileged --pid=host \
#     -v /sys/kernel:/sys/kernel:ro \
#     -v correlic-data:/var/lib/correlic \
#     -p 127.0.0.1:3001:3001 \
#     ghcr.io/fuloxdev/correlic:v1.0.1
#
# On first start the container prints the dashboard API key and an admin
# email/password (docker logs correlic); they are also stored in
# /var/lib/correlic/dashboard-credentials inside the data volume.
# Dashboard: http://localhost:3001
#
# Graph switch: the image bundles Neo4j and starts it by default
# (CORRELIC_GRAPH=on). Add `-e CORRELIC_GRAPH=off` to run on PostgreSQL
# alone: supervisord never starts Neo4j and NEO4J_URI stays unset for both
# backend planes, which drops the two graph look-back rules
# (ai.data_exfiltration, ai.excessive_writes) and the Neo4j timeline and
# keeps everything else. The Neo4j data directory in the volume is
# preserved, so the switch can be flipped back later.
#
# Built for linux/amd64 and linux/arm64 (.github/workflows/release-images.yml).
# The Go stages are pinned to $BUILDPLATFORM and cross-compile with
# GOARCH=$TARGETARCH; the Node.js build stages and the runtime stage run per
# platform (under QEMU when cross-building). Every apt source used by the
# runtime stage publishes arm64 packages: Debian bookworm (openjdk-17),
# PostgreSQL pgdg (amd64/arm64), NodeSource (amd64/arm64) and Neo4j
# (architecture-independent deb).

ARG VERSION=dev

# ============================================================
# Stage 1: Build backend Go binaries
# ============================================================
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder-backend
ARG TARGETARCH

RUN apk add --no-cache git

WORKDIR /build
COPY backend/go.mod backend/go.sum ./
RUN go mod download

COPY backend/ .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /correlic-api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /correlic-telemetry ./cmd/telemetry
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /correlic-admin ./cmd/admin

# ============================================================
# Stage 2: Build agent Go binary (needs eBPF toolchain)
# ============================================================
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder-agent
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang llvm libbpf-dev linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY agent/go.mod agent/go.sum ./
RUN go mod download

COPY agent/ .
# go generate emits the eBPF objects for amd64 and arm64; GOARCH picks the set.
RUN go generate ./internal/ebpf/...
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -ldflags="-s -w" -o /correlic-agent ./cmd/agent

# ============================================================
# Stage 3: Build Next.js UI
# ============================================================
FROM node:24-alpine AS builder-ui

WORKDIR /build
COPY ui/package.json ui/package-lock.json ./
RUN npm ci

COPY ui/ .
ENV NEXT_TELEMETRY_DISABLED=1
ENV PROXY_BASE_URL=http://localhost:8788
RUN npm run build

# ============================================================
# Stage 4: Build UI Proxy
# ============================================================
FROM node:24-alpine AS builder-proxy

WORKDIR /build
COPY ui-proxy/package.json ui-proxy/package-lock.json ./
RUN npm ci --omit=dev

COPY ui-proxy/index.js ./

# ============================================================
# Stage 5: Runtime — all services in one image
# ============================================================
FROM debian:bookworm-slim AS runtime

ARG VERSION=dev
ENV CORRELIC_VERSION=${VERSION}

# Install base tools first
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates gnupg lsb-release bash openssl procps supervisor \
    && rm -rf /var/lib/apt/lists/*

# Add PostgreSQL 16 apt repo
RUN mkdir -p /etc/apt/keyrings \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc | gpg --dearmor -o /etc/apt/keyrings/pgdg.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/pgdg.gpg] http://apt.postgresql.org/pub/repos/apt bookworm-pgdg main" > /etc/apt/sources.list.d/pgdg.list

# Add Node.js 20 apt repo
RUN curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" > /etc/apt/sources.list.d/nodesource.list

# Install PostgreSQL 16, Node.js 20, Java 17
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-16 postgresql-client-16 \
    nodejs \
    openjdk-17-jre-headless \
    && rm -rf /var/lib/apt/lists/*

# Install Neo4j 5
RUN curl -fsSL https://debian.neo4j.com/neotechnology.gpg.key | gpg --dearmor -o /etc/apt/keyrings/neo4j.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/neo4j.gpg] https://debian.neo4j.com stable 5" > /etc/apt/sources.list.d/neo4j.list \
    && apt-get update && apt-get install -y --no-install-recommends neo4j \
    && rm -rf /var/lib/apt/lists/*

# Keep Neo4j's data (including its auth store) on the persisted data volume.
RUN mkdir -p /var/lib/correlic/neo4j && chown -R neo4j:neo4j /var/lib/correlic/neo4j \
    && if grep -q '^server.directories.data=' /etc/neo4j/neo4j.conf; then \
         sed -i 's|^server.directories.data=.*|server.directories.data=/var/lib/correlic/neo4j|' /etc/neo4j/neo4j.conf; \
       else echo 'server.directories.data=/var/lib/correlic/neo4j' >> /etc/neo4j/neo4j.conf; fi

# Create directory structure
RUN mkdir -p \
    /opt/correlic/bin \
    /opt/correlic/migrations \
    /opt/correlic/ui \
    /opt/correlic/ui-proxy \
    /opt/correlic/certs \
    /opt/correlic/scripts \
    /var/lib/correlic \
    /var/log/correlic

# Copy Go binaries from build stages
COPY --from=builder-backend /correlic-api /opt/correlic/bin/
COPY --from=builder-backend /correlic-telemetry /opt/correlic/bin/
COPY --from=builder-backend /correlic-admin /opt/correlic/bin/
COPY --from=builder-agent /correlic-agent /opt/correlic/bin/

# Copy migrations
COPY --from=builder-backend /build/migrations/ /opt/correlic/migrations/

# Copy UI (Next.js standalone)
COPY --from=builder-ui /build/.next/standalone/ /opt/correlic/ui/
COPY --from=builder-ui /build/.next/static/ /opt/correlic/ui/.next/static/
COPY --from=builder-ui /build/public/ /opt/correlic/ui/public/

# Copy UI Proxy
COPY --from=builder-proxy /build/ /opt/correlic/ui-proxy/

# Copy scaffolding
COPY entrypoint.sh /opt/correlic/entrypoint.sh
COPY supervisord.conf /etc/supervisor/conf.d/correlic.conf
COPY scripts/generate-certs.sh /opt/correlic/scripts/generate-certs.sh
COPY scripts/healthcheck.sh /opt/correlic/scripts/healthcheck.sh

RUN chmod +x /opt/correlic/entrypoint.sh \
    /opt/correlic/scripts/generate-certs.sh \
    /opt/correlic/scripts/healthcheck.sh \
    /opt/correlic/bin/*

# PostgreSQL data dir permissions
RUN mkdir -p /var/lib/correlic/postgresql && chown -R postgres:postgres /var/lib/correlic/postgresql

VOLUME ["/var/lib/correlic"]
EXPOSE 3001

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD /opt/correlic/scripts/healthcheck.sh

ENTRYPOINT ["/opt/correlic/entrypoint.sh"]
