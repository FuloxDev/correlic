# Correlic Backend Dockerfile
# Builds both API and Telemetry plane binaries

# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -o /api ./cmd/api
RUN CGO_ENABLED=0 go build -o /telemetry ./cmd/telemetry
RUN CGO_ENABLED=0 go build -o /admin ./cmd/admin

# Runtime stage
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
