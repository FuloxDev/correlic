# Correlic

Runtime security monitoring for AI coding agents. A kernel-level agent watches
what Claude Code, Cursor, Copilot, aider and similar tools actually do on a
machine (processes, files, network, DNS), keeps the activity inside an AI
process tree, and ships it to a backend that runs detection rules, correlates
multi-step attack chains into incidents, and lets you investigate them with
your own LLM key.

Everything runs on your own infrastructure. There is no hosted component and
no telemetry to the project.

**Current release: [v1.0.1](https://github.com/FuloxDev/correlic/releases/tag/v1.0.1)** (2026-10-08).
Each release ships container images on `ghcr.io/fuloxdev`, a Linux bundle
(tar.gz, `.deb`, `.rpm`) and a Windows bundle, each with SHA-256 checksums.
Changes are listed in `CHANGELOG.md`.

## Layout

| Directory | What it is | Stack |
|---|---|---|
| `backend/` | API server (:8080), telemetry ingest (:8081), `correlic-admin` CLI, MCP server. Detection engine, correlation, incidents, notifications, BYOK AI layer. Design docs in `backend/docs/`. | Go 1.26, PostgreSQL 14+, Neo4j 5 (optional) |
| `agent/` | Host agent. Linux eBPF (complete), Windows ETW + Security audit, macOS kqueue + polling (early). | Go 1.26, cilium/ebpf |
| `ui/` | Dashboard: findings, incidents with AI chat, baselines, block rules, timeline. | Next.js 16, React 19 |
| `ui-proxy/` | Small Express service that holds the mTLS client certificate between the dashboard and the backend. Loopback only. | Node 24 LTS |
| `install/` | `docker-compose.yml`, Linux installer and `.deb`/`.rpm` scaffolding, Windows installer scripts, cert generation. | bash, PowerShell |
| `Dockerfile`, `entrypoint.sh`, `supervisord.conf` | All-in-one image bundling PostgreSQL, Neo4j, backend, agent, dashboard and proxy. | Debian |
| `paper-supplementary/` | Machine-readable rule set, chain patterns and never-baseline list from the accompanying paper. | YAML (CC BY 4.0) |

## Quick start

Every install creates two credentials on first start: a dashboard admin (an
API key plus an email/password) and a separate, restricted key for the agent.
The dashboard listens on localhost only.

### All-in-one container (Linux host)

```bash
docker run -d --name correlic --restart unless-stopped \
  --privileged --pid=host \
  -v /sys/kernel:/sys/kernel:ro \
  -v correlic-data:/var/lib/correlic \
  -p 127.0.0.1:3001:3001 \
  ghcr.io/fuloxdev/correlic:v1.0.1
docker logs correlic        # first start prints the dashboard API key and admin password
open http://localhost:3001
```

`ghcr.io/fuloxdev/correlic:latest` always points at the newest release; pin
the version tag for reproducible installs.
The credentials are also kept in `/var/lib/correlic/dashboard-credentials`
inside the data volume (`docker exec correlic cat /var/lib/correlic/dashboard-credentials`).
The agent needs a Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`).

### Docker Compose

```bash
cd install
cp .env.example .env        # set DB_PASSWORD, NEO4J_PASSWORD, LLM_ENCRYPTION_KEY
docker compose up -d
docker compose logs bootstrap   # shows the dashboard API key and admin password
```

### Linux installer (systemd, no Docker)

```bash
curl -sSL https://raw.githubusercontent.com/FuloxDev/correlic/main/install/install.sh | sudo bash
```

It downloads the v1.0.1 bundle (`correlic-linux-v1.0.1.tar.gz`), verifies it
against `SHA256SUMS-linux.txt`, installs PostgreSQL and Neo4j if missing,
creates the credentials and starts five systemd units. Set
`CORRELIC_BUNDLE_URL` to install a different build. For package-managed hosts
the release also carries
[`correlic_1.0.1_amd64.deb`](https://github.com/FuloxDev/correlic/releases/download/v1.0.1/correlic_1.0.1_amd64.deb)
and
[`correlic-1.0.1-1.x86_64.rpm`](https://github.com/FuloxDev/correlic/releases/download/v1.0.1/correlic-1.0.1-1.x86_64.rpm).

Linux is supported on x86_64 (amd64) and arm64 (aarch64): Apple Silicon
Linux VMs, AWS Graviton, Raspberry Pi 5 with a BTF-enabled kernel, and any
other arm64 machine running Linux 5.8+ with BTF. The installer picks the
bundle for the machine it runs on. The arm64 assets
(`correlic-linux-<version>-arm64.tar.gz`, `correlic_<version>_arm64.deb`,
`correlic-<version>-1.aarch64.rpm`) and the linux/arm64 container images are
published from the first release after v1.0.1.

### Windows

```powershell
irm https://raw.githubusercontent.com/FuloxDev/correlic/main/install/install.ps1 | iex
```

The script downloads
[`correlic-windows-v1.0.1.zip`](https://github.com/FuloxDev/correlic/releases/download/v1.0.1/correlic-windows-v1.0.1.zip)
(PostgreSQL, Neo4j, a Java runtime and Node.js are bundled, about 590 MB),
installs it and starts Correlic. To add only the agent on another Windows
machine, run `install/install-agent.ps1` from the same release.

### AI tool hooks (all platforms, no kernel driver needed)

`correlic-hook` is a small binary that Claude Code and Cursor run on every
tool call. It records the command, file or URL the AI used, with the session
it belongs to, and can deny a call that matches one of your block rules before
it runs. It needs no root and no kernel driver, so it also works on a Mac
without a paid Apple account, where it is the only host-level signal; next to
the Linux or Windows agent it adds exact attribution to the kernel events.

```bash
# the binary ships in bin/ next to correlic-agent (or: cd agent && go build ./cmd/correlic-hook)
cat > ~/.correlic/hook.yaml <<'YAML'
telemetry_url: "https://localhost:8081"
api_key: "<agent api key>"          # correlic-admin create-api-key --type agent
tls_ca_file: "/opt/correlic/certs/ca.crt"
YAML
correlic-hook setup        # registers it in ~/.claude/settings.json and ~/.cursor/hooks.json
correlic-hook test         # sends one synthetic event and prints the backend's answer
```

Only commands, paths, URLs, names and ids are sent — never file contents,
tool output or prompts. See `backend/docs/HOOKS.md`.

### From source

Needs Go 1.26+, Node 22+ (the bundles ship Node 24 LTS), PostgreSQL, `openssl`, and on Linux `clang`, `llvm`
and `libbpf-dev` for the eBPF objects. Neo4j is optional: detection works
without it; process-tree views and graph-based incident context need it.

```bash
# 1. backend: migrations, org, admin, keys, certificates, agent config
cd backend
export DATABASE_URL=postgres://correlic:correlic@localhost:5432/correlic
go run ./cmd/admin migrate up
go run ./cmd/admin bootstrap --name Local --certs-dir "$PWD/.certs"
#    prints: api_key=... (dashboard), agent_api_key=... (agent), email=/password=
#    writes: .certs/{ca,server,client}.{crt,key} and .certs/agent.yaml

# 2. run both backend planes (two shells)
export TLS_CERT_FILE=$PWD/.certs/server.crt TLS_KEY_FILE=$PWD/.certs/server.key MTLS_CA_FILE=$PWD/.certs/ca.crt
LLM_ENCRYPTION_KEY=$(openssl rand -hex 32) go run ./cmd/api
go run ./cmd/telemetry

# 3. agent (Linux, as root)
cd ../agent
go generate ./internal/ebpf/...
go build -o correlic-agent ./cmd/agent
sudo CORRELIC_CONFIG=$PWD/../backend/.certs/agent.yaml ./correlic-agent

# 4. dashboard (two shells)
cd ../ui-proxy && npm ci && BACKEND_API=https://localhost:8080 MTLS_CA=../backend/.certs/ca.crt \
  MTLS_CERT=../backend/.certs/client.crt MTLS_KEY=../backend/.certs/client.key node index.js
cd ../ui && npm ci && PROXY_BASE_URL=http://localhost:8788 npm run dev     # http://localhost:3001
```

Log in with the dashboard API key or the admin email and password that
`bootstrap` printed.

## How it fits together

```
monitored host                         backend                         dashboard
┌────────────────────┐   mTLS + key   ┌──────────────────────┐          ┌──────────┐
│ kernel hooks       │ ─────────────▶ │ :8081 telemetry plane│          │ browser  │
│ (eBPF / ETW)       │ /ingest/events │ :8080 API plane      │ ◀─────── │ Next.js  │
│ lineage tracker    │                │ ingest → 13 rules →  │  mTLS    │ ui-proxy │
│ dispatcher         │                │ chains → incidents   │          └──────────┘
└────────────────────┘                │ PostgreSQL (+ Neo4j) │
                                      └──────────────────────┘
```

Authentication is local only. API keys, users and sessions live in the
backend's PostgreSQL database. Keys have a type: agent keys can only reach the
ingest, heartbeat and agent endpoints; dashboard keys and sessions carry the
user's role (`admin` or `member`), and configuration changes require `admin`.

## Status

- Linux agent (amd64 and arm64): eBPF collectors for exec, exit, fork, file
  open, connect, bind, unlink, setuid and DNS; tested on kernels 5.8 to 6.18.
- Windows agent: ETW and Security audit log; block rules enforced.
- macOS agent: best-effort preview, built from source. On macOS 13 or newer
  it gets Endpoint Security process and file events with real PIDs through
  Apple's own `/usr/bin/eslogger` (run as root with Full Disk Access; no
  Apple Developer account needed); otherwise kqueue process events plus
  polling for files. Network stays on lsof polling and there is no DNS.
  There are no signed or notarized macOS builds and no native Endpoint
  Security client, because both require a paid Apple Developer Program
  membership that the project does not maintain. For full coverage on a Mac,
  run the coding agent inside a Linux VM or container with the Linux agent
  (on Apple Silicon that VM is arm64, which the Linux agent supports), and
  run the backend and dashboard with Docker.
- AI tool hooks: `correlic-hook` for Claude Code and Cursor on Linux, macOS
  and Windows; records every tool call as an `ai_tool_call` event and denies
  calls that match block rules. See `backend/docs/HOOKS.md`.
- Detection: 13 AI-gated rules and 11 chain patterns; see
  `backend/docs/DETECTION_ENGINE.md`.

## Documentation

Start with `backend/docs/SYSTEM_REFERENCE.md`, then `ARCHITECTURE.md`,
`DETECTION_ENGINE.md` and `API_REFERENCE.md`. Each component directory also
has a short `CLAUDE.md` with build notes. `SECURITY.md` has the disclosure
policy and deployment notes; `CONTRIBUTING.md` the build and test commands.

## Development

CI (`.github/workflows/ci.yml`) builds, vets and tests `backend/` and
`agent/` (with eBPF generation) and lints and builds `ui/` and `ui-proxy/`.
Release workflows build the container images and the Linux and Windows
install bundles from this repository alone: dispatch `release-images`,
`build-linux-bundle` and `build-windows-bundle` on `main` with the version
(for example `v1.0.1`). The bundle workflows create a draft GitHub release;
publishing it creates the tag. Bump the version pinned in `install/` and in
this README in the same change.

## License

MIT, see `LICENSE`. Every feature is available to everyone; there are no
tiers, licence keys or usage limits. The eBPF programs in
`agent/internal/ebpf/bpf/` are dual-licensed GPL-2.0 OR BSD-3-Clause, as the
kernel requires, and `paper-supplementary/` is CC BY 4.0. Third-party software
redistributed in the install bundles is listed in `NOTICE.md`.
