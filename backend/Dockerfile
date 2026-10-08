# Correlic Backend Dockerfile
# Builds both API and Telemetry plane binaries.
# Built for linux/amd64 and linux/arm64 (see .github/workflows/release-images.yml).

# Build stage — pinned to the build host's platform; Go cross-compiles for the
# target (GOARCH=$TARGETARCH) instead of running under emulation.
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS builder
ARG TARGETARCH

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o /api ./cmd/api
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o /telemetry ./cmd/telemetry
RUN CGO_ENABLED=0 GOOS=linux GOARCH=$TARGETARCH go build -o /admin ./cmd/admin

# Runtime stage (per target platform)
FROM alpine:3.20

RUN apk add --no-cache ca-certificates bash

WORKDIR /app

COPY --from=builder /api /app/api
COPY --from=builder /telemetry /app/telemetry
COPY --from=builder /admin /app/admin
COPY migrations /app/migrations
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh

EXPOSE 8080 8081

ENTRYPOINT ["/app/entrypoint.sh"]
