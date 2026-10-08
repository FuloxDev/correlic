# Correlic Agent Dockerfile
# Two-stage: generate eBPF objects, then build the Go binary

# Build stage — needs clang for bpf2go
FROM golang:1.26-bookworm AS builder

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

# Build the agent binary (explicitly target linux/amd64)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -v -o /correlic-agent ./cmd/agent

# Runtime stage — minimal
FROM alpine:3.20 AS runtime

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /correlic-agent /app/correlic-agent

ENTRYPOINT ["/app/correlic-agent"]
