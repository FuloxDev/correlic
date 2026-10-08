# Correlic Agent Dockerfile
# Two-stage: generate eBPF objects, then build the Go binary.
# Built for linux/amd64 and linux/arm64 (see .github/workflows/release-images.yml).

# Build stage — needs clang for bpf2go. Pinned to the build host's platform so
# Go cross-compiles for the target instead of running under emulation: one
# `go generate` emits the eBPF objects for amd64 and arm64, and GOARCH picks the
# matching set at build time.
FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS builder
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Generate eBPF objects (bpf2go compiles .bpf.c → Go)
RUN go generate ./internal/ebpf/...

# Build the agent binary for the image's target architecture (amd64 or arm64)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -v -o /correlic-agent ./cmd/agent

# Runtime stage — minimal, per target platform
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /correlic-agent /app/correlic-agent

ENTRYPOINT ["/app/correlic-agent"]
