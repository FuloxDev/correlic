# Correlic

Runtime security monitoring for AI coding agents. A kernel-level agent watches
what Claude Code, Cursor, Copilot, aider and similar tools actually do on a
machine (processes, files, network, DNS), keeps only the activity inside an AI
process tree, and ships it to a backend that runs AI-gated detection rules,
correlates multi-step attack chains into incidents, and lets you investigate
them with your own LLM key.

Everything runs on your own infrastructure. There is no hosted component.

## Layout

| Directory | What it is | Stack |
|---|---|---|
| `backend/` | API server (:8080), telemetry ingest (:8081), `correlic-admin` CLI, MCP server. Detection engine, correlation, incidents, notifications, BYOK AI layer. All design docs live in `backend/docs/`. | Go 1.24, PostgreSQL 14+, Neo4j 5 (optional) |
| `agent/` | Host agent. Linux eBPF, macOS kqueue/FSEvents/lsof, Windows ETW + Security audit. | Go 1.25, cilium/ebpf |
| `ui/` | Dashboard: findings, incidents with AI chat, baselines, block rules, timeline. | Next.js 16, React 19 |
| `ui-proxy/` | Small Express service that holds the mTLS client certificate between the dashboard and the backend. | Node 20 |
| `install/` | `docker-compose.yml`, Linux installer and `.deb`/`.rpm` scaffolding, Windows installer scripts, cert generation. | bash, PowerShell |
| `Dockerfile`, `entrypoint.sh`, `supervisord.conf` | All-in-one image bundling PostgreSQL, Neo4j, backend, agent, dashboard and proxy. | Debian |
| `paper-supplementary/` | Machine-readable rule set, chain patterns and never-baseline list from the accompanying paper. | YAML (CC BY 4.0) |

## Quick start

### All-in-one container (Linux host)

```bash
docker run -d --name correlic \
  --privileged --pid=host \
  -v /sys/kernel:/sys/kernel:ro \
  -v correlic-data:/var/lib/correlic \
  -p 3001:3001 \
  ghcr.io/correlic/correlic:latest
docker logs correlic        # first start prints the generated dashboard API key
open http://localhost:3001
```

The agent needs a Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`).

### Docker Compose

```bash
cd install
cp .env.example .env        # set DB_PASSWORD, NEO4J_PASSWORD, LLM_ENCRYPTION_KEY
docker compose up -d
docker compose logs bootstrap   # shows the generated API key
```

### From source

```bash
# backend (needs PostgreSQL; Neo4j optional)
cd backend
export DATABASE_URL=postgres://correlic:correlic@localhost:5432/correlic
go run ./cmd/admin migrate up
go run ./cmd/admin bootstrap --name Local --certs-dir .certs   # org, admin user, API key, certs, agent.yaml
TLS_CERT_FILE=.certs/server.crt TLS_KEY_FILE=.certs/server.key MTLS_CA_FILE=.certs/ca.crt \
LLM_ENCRYPTION_KEY=$(openssl rand -hex 32) go run ./cmd/api
# in another shell
TLS_CERT_FILE=.certs/server.crt TLS_KEY_FILE=.certs/server.key MTLS_CA_FILE=.certs/ca.crt go run ./cmd/telemetry

# agent (Linux; needs clang, llvm, libbpf-dev for the eBPF objects)
cd agent
go generate ./internal/ebpf/...
sudo CORRELIC_CONFIG=../backend/.certs/agent.yaml go run ./cmd/agent

# dashboard
cd ui-proxy && BACKEND_API=https://localhost:8080 MTLS_CA=../backend/.certs/ca.crt \
  MTLS_CERT=../backend/.certs/client.crt MTLS_KEY=../backend/.certs/client.key node index.js
cd ui && PROXY_BASE_URL=http://localhost:8788 npm run dev     # http://localhost:3001
```

Log in to the dashboard with the API key printed by `bootstrap`, or with the
admin email and password it created.

## How it fits together

```
monitored host                         backend                         dashboard
┌────────────────────┐   mTLS + key   ┌──────────────────────┐          ┌──────────┐
│ kernel hooks       │ ─────────────▶ │ :8081 telemetry plane│          │ browser  │
│ (eBPF / ESF / ETW) │ /ingest/events │ :8080 API plane      │ ◀─────── │ Next.js  │
│ lineage tracker    │                │ ingest → 13 rules →  │  mTLS    │ ui-proxy │
│ dispatcher         │                │ chains → incidents   │          └──────────┘
└────────────────────┘                │ PostgreSQL + Neo4j   │
                                      └──────────────────────┘
```

Authentication is local only. API keys and user sessions live in the backend's
PostgreSQL database. `CORRELIC_API_URL` can point the backend, the agent
(`correlic_api_url`) and the dashboard at an external key-validation server,
but it is empty by default and nothing depends on it.

## Documentation

Start with `backend/docs/SYSTEM_REFERENCE.md`, then `ARCHITECTURE.md`,
`DETECTION_ENGINE.md` and `API_REFERENCE.md`. Each component directory also
has a short `CLAUDE.md` with build notes.

## Development

CI (`.github/workflows/ci.yml`) runs `go build/vet/test` for `backend/` and
`agent/`, generates the eBPF objects, and builds the four Node projects.
Release workflows build the container images and the Linux and Windows
install bundles from this repository alone.

## License

MIT, see `LICENSE`. Every feature is available to everyone; there are no
tiers, licence keys or usage limits. The eBPF programs in
`agent/internal/ebpf/bpf/` are dual-licensed GPL-2.0 OR BSD-3-Clause, as the
kernel requires, and `paper-supplementary/` is CC BY 4.0. Third-party software
redistributed in the install bundles is listed in `NOTICE.md`.
