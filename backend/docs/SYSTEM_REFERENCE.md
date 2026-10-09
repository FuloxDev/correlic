# Correlic — System Reference

> Master reference document for the Correlic platform. Start here for AI context.
> Scope: 4 core repos (backend, agent, UI, proxy). Excludes correlic-web and correlic-api (product website).

## What is Correlic?

Correlic is a distributed security observability platform that monitors AI coding agents (Claude Code, Cursor, Copilot, etc.) by collecting kernel-level telemetry, detecting threats in real-time, correlating incidents, and providing AI-powered investigation tools. It answers: "What did the AI agent do on my machine, and was any of it malicious?"

## Repository Map

| Repo | Language | Purpose |
|------|----------|---------|
| `backend/` | Go 1.26+ | API server — event ingestion, detection engine, incident correlation, 80+ API endpoints |
| `agent/` | Go 1.26+ | Kernel telemetry collector — eBPF (Linux), ETW (Windows), kqueue + polling (macOS, preview); also builds `correlic-hook` (AI tool hooks, all platforms) |
| `ui/` | Next.js 16 / React 19 / TypeScript | Web dashboard — findings, incidents, baselines, block rules, AI chat |
| `correlic-ui-proxy/` | Node.js | HTTPS reverse proxy — TLS termination, routes /api/* → backend, /* → UI |

## Architecture (5 Layers)

```
1. COLLECTION   Agent (eBPF/ESF/ETW) → kernel events → canonical schema → HTTPS dispatch
                correlic-hook (Claude Code / Cursor tool hooks) → ai_tool_call events → same endpoint
                     ↓
2. PROCESSING   Backend: sampling (90% reduction) → detection (13 rules + 11 chains)
                → baseline suppression → incident clustering → notification
                     ↓
3. STORAGE      PostgreSQL 14+ (events, findings, incidents, baselines, users)
                Neo4j 5+ (optional: process trees, attack chains, AI label propagation)
                     ↓
4. AI           3-layer context (profile/rollups/patterns) → BYOK LLM providers
                → tool-calling → threaded incident chat → dossier pre-computation
                     ↓
5. PRESENTATION Next.js UI → dashboard, findings, incidents, baselines, block rules
```

## Backend Binaries

| Binary | Entry Point | Purpose |
|--------|-------------|---------|
| `api` | `cmd/api/main.go` | HTTP server on :8080 — all endpoints |
| `admin` | `cmd/admin/main.go` | CLI — migrations, org/user/key management |
| `telemetry` | `cmd/telemetry/main.go` | Async telemetry processing plane |
| `mcp` | `cmd/mcp/main.go` | Model Context Protocol server for Claude Code / Claude Desktop / Cursor (`docs/MCP_SERVER.md`) |

## Tech Stack

- **Backend:** Go, standard library `net/http` (`http.NewServeMux()`), pgx driver
- **Databases:** PostgreSQL 14+ (JSONB), Neo4j 5+ (optional, graceful degradation)
- **Agent:** Go, cilium/ebpf (Linux), ESF (macOS), ETW (Windows)
- **Frontend:** Next.js 16, React 19, TypeScript, TailwindCSS, Recharts, React Query
- **Auth:** Session-based + Google OAuth + API keys + mTLS, bcrypt, RBAC
- **TLS:** TLS 1.2+, optional mTLS for agent auth

## Event Flow (10 Steps)

```
1. Kernel event (syscall/tracepoint/ETW)
2. Agent collects → parses → normalizes → classifies
3. Agent dispatches → POST /ingest/events (batched, rate-limited, deduped)
4. Backend authenticates (mTLS/API key) → validates
5. Sampling: AlwaysKeep → Suspicious → BenignDrop → Probabilistic
6. Store: PostgreSQL (telemetry_events + events) + Neo4j process tree (Tier 1)
7. AI attribution: track AI agent session UUIDs
8. Detection engine: 13 rules evaluate → findings (baseline/exception/cooldown suppression)
9. Chain correlation: 11 patterns → chain findings → incident clustering
10. Notification: in-app + webhook / Slack / Discord / e-mail / syslog delivery
```

## Detection System

- **13 detection rules** (all AI-gated via Neo4j `IsAIProcess()` check):
  - `ai.credential_access` (critical) — SSH keys, /etc/shadow, crypto files
  - `ai.unauthorized_exec` (high) — curl, wget, nc, ncat, shells, network primitives
  - `ai.excessive_writes` (dynamic) — path diversity scoring for write bursts
  - `ai.data_exfiltration` (critical) — read-then-exfiltrate correlation (15min window)
  - `ai.unexpected_network` (dynamic) — non-standard ports, IMDS, high-risk internal
  - `ai.suspicious_dns` (dynamic) — Tor, suspicious TLDs, paste services
  - `ai.persistence` (critical) — cron, systemd, SSH config, registry Run keys
  - `ai.privilege_escalation` (critical) — sudo, su, LOLBins, sensitive privileges
  - `ai.code_tampering` (high) — CI/CD configs, Dockerfiles, dependency manifests
  - `ai.container_escape` (critical) — runtime sockets, namespace files, host mounts
  - `ai.discovery` (low) — recon burst detection (3+ commands in 60s)
  - `ai.command_activity` (low) — catch-all command audit trail
  - `ai.file_activity` (low) — catch-all file access audit trail

- **11 chain patterns** (multi-step attack sequences):
  - credential_theft, reverse_shell_setup, lateral_movement, full_compromise
  - persistence_backdoor, supply_chain_attack, data_staging
  - credential_persistence, privesc_credential_exfil, recon_to_escalation, container_breakout

- **Severity dampening:** confidence < 0.60 → critical downgraded to high, high to medium
- **Cooldown:** rate-limits repeat findings (10min default, 15min for credential_access, 5min for network)
- **Baseline suppression:** learned normal behavior auto-suppresses matching findings
- **Exception suppression:** per-org rule exceptions with context filtering

## Storage Schema (Key Tables)

| Table | Purpose |
|-------|---------|
| `telemetry_events` | Raw agent events (1-day retention) |
| `events` | Canonical events (30-day retention) |
| `findings` | Detection findings (90-day retention) |
| `incidents` | Grouped findings (365-day retention) |
| `behavioral_baselines` | Learned normal behavior |
| `block_rules` | Process termination rules |
| `block_events` | Block execution log |
| `notification_endpoints` | Channel config (webhook, Slack, Discord, e-mail, syslog); secrets sealed |
| `notifications` | In-app notification feed |
| `notification_deliveries_v2` | External delivery queue |
| `ai_system_profiles` | Layer 1 AI context |
| `ai_context_windows` | Layer 2 hierarchical rollups |
| `ai_learned_patterns` | Layer 3 verdict patterns |
| `ai_agent_sessions` | AI process session tracking |
| `safe_domains` | Domain allowlist for network rules |
| `rule_exceptions` | Per-org detection suppression |
| `detection_rule_settings` | Per-org tunable thresholds |
| `organizations` | Multi-tenant orgs |
| `users` | User accounts (email, role, password_hash) |
| `api_keys` | Hashed API keys |
| `agents` | Registered agents |
| `audit_events` | Action audit trail |

## Auth Model

- **Agent auth:** mTLS client certificates OR API key (Bearer token)
- **User auth:** Session-based login (email/password, bcrypt) OR Google OAuth
- **RBAC:** admin vs regular user roles (`middleware/role_guard.go`)
- **Rate limiting:** configurable per-minute (default 300, `CORRELIC_RATE_LIMIT_PER_MIN`)
- **Multi-tenancy:** all queries scoped by `org_id`
- **Audit:** all authenticated actions logged to `audit_events`

## Feature → Doc Index

| Feature | Documentation |
|---------|---------------|
| System design + components | `docs/ARCHITECTURE.md` |
| Detection engine (13 rules + 11 chains) | `docs/DETECTION_ENGINE.md` |
| Correlation engine (Tier 1/2 + Neo4j) | `docs/CORRELATION_ENGINE.md` |
| AI intelligence (3-layer context) | `docs/AI_INTELLIGENCE.md` |
| AI layer (LLM providers, tools, chat) | `docs/AI_LAYER.md` |
| Incident engine (clustering + assembly) | `docs/INCIDENT_ENGINE.md` |
| Alert/notification engine | `docs/ALERT_ENGINE.md` |
| Behavioral baselines | `docs/BEHAVIOURAL_ENGINE.md` |
| Block rules & enforcement | `docs/BLOCK_RULES.md` |
| Authentication & RBAC | `docs/AUTH_AND_RBAC.md` |
| API reference (80+ endpoints) | `docs/API_REFERENCE.md` |
| Query & timeline services | `docs/QUERY_AND_TIMELINE.md` |
| Data retention | `docs/DATA_RETENTION.md` |
| Enrichment APIs | `docs/ENRICHMENT.md` |
| Linux agent (eBPF) | `docs/LINUX_AGENT.md` |
| Windows agent (ETW + USN) | `docs/WINDOWS_AGENT.md` |
| macOS agent (ESF + kqueue) | `docs/MACOS_AGENT.md` |
| AI tool hooks (correlic-hook, `ai_tool_call`) | `docs/HOOKS.md` |
| 4-layer architecture | `docs/LAYERS.md` |
| AI process race conditions | `docs/ai_process_tracking.md` |
| Suspicious file patterns | `docs/suspicious-files-reference.md` |
| Roadmap | `docs/ROADMAP.md` |

## Backend Package Map

| Package | Purpose |
|---------|---------|
| `internal/ingest/` | Ingestion pipeline: sampler, sampling_rules, live_ingest |
| `internal/detection/` | Detection engine, cooldown, baselines, chain correlator |
| `internal/detection/ai_pack/` | 13 AI detection rules |
| `internal/correlation/` | Event buffer, worker, window manager, process tree writer |
| `internal/incident/` | Incident correlator, store, context assembler |
| `internal/notification/` | Manager, delivery worker, webhook / Slack / Discord / e-mail / syslog senders, config validation |
| `internal/ai/intelligence/` | 3-layer context: profile, rollups, patterns, worker |
| `internal/ai/provider/` | BYOK LLM providers (OpenAI, Anthropic, Gemini, Groq) |
| `internal/ai/dossier/` | Pre-computed LLM context for incidents |
| `internal/ai/conversation/` | Threaded chat store |
| `internal/ai/attribution/` | AI process session tracking |
| `internal/storage/` | PostgreSQL stores (agents, orgs, users, findings, etc.) |
| `internal/storage/neo4j/` | Neo4j graph persistence + queries |
| `internal/storage/eventstore/` | Canonical event store |
| `internal/api/` | HTTP handlers (80+ endpoints) |
| `internal/api/middleware/` | Auth, RBAC, rate limiting, audit, mTLS |
| `internal/query/` | Query service, timeline service, investigation service |
| `internal/enrichment/` | IP/ASN/BGP enrichment |
| `internal/maintenance/` | Data retention cleanup |
| `internal/event/` | Canonical event schema |
| `internal/model/` | Data models |
| `internal/config/` | Environment loading |
| `internal/service/` | Business logic (agent inventory) |
| `internal/mcp/` | MCP server (stdio JSON-RPC), REST client, tool catalogue (`docs/MCP_SERVER.md`) |
| `internal/secrets/` | AES-256-GCM cipher under `LLM_ENCRYPTION_KEY` for stored secrets |

## Agent Package Map

| Package | Purpose |
|---------|---------|
| `cmd/agent/` | Entry point + platform-specific startup (linux/darwin/windows) |
| `cmd/correlic-hook/`, `internal/hook/` | Claude Code / Cursor hook binary: `ai_tool_call` events, block-rule denial, spool |
| `internal/ebpf/` | eBPF programs (12 C files) + collectors + runners (Linux) |
| `internal/darwin/` | ESF + FSEvents + kqueue + lsof collectors (macOS) |
| `internal/windows/` | ETW + USN Journal + audit subscribers (Windows) |
| `internal/dispatch/` | Buffered dispatcher + HTTP sink + rate limiter + dedupe |
| `internal/transport/` | HTTPS client to backend (heartbeat, telemetry, events, approvals) |
| `internal/event/` | Canonical event types (Event, Actor, Target) |
| `internal/lineage/` | AI process lineage tracking (session UUID inheritance) |
| `internal/normalize/` | Exec classification + cleanup |
| `internal/enforcer/` | Soft-block enforcement (kill process) |
| `internal/approvals/` | Approval gate + UI |
| `internal/config/` | YAML configuration loading |

## Environment Variables (Backend)

| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `postgres://correlic:correlic@localhost:5432/correlic` | PostgreSQL connection |
| `NEO4J_URI` | — | Neo4j connection; unset = graph features disabled, detection still runs |
| `NEO4J_USERNAME` | `neo4j` | Neo4j auth |
| `NEO4J_PASSWORD` | — | Neo4j auth |
| `TLS_CERT_FILE` | — | Server TLS certificate |
| `TLS_KEY_FILE` | — | Server TLS key |
| `MTLS_CA_FILE` | — | CA cert for client mTLS verification |
| `ALLOW_API_KEY_AUTH` | `true` | Enable API key auth (vs mTLS-only) |
| `CORRELIC_RATE_LIMIT_PER_MIN` | `300` | API rate limit |
| `LLM_ENCRYPTION_KEY` | — (required by `cmd/api`) | Encryption key for BYOK LLM API keys; any string, hashed to 32 bytes |
| `GOOGLE_CLIENT_ID` | — | Google OAuth client ID |
| `FRONTEND_URL` | `http://localhost:3001` | Dashboard URL used in email links |
| `ENABLE_DEBUG_ENDPOINTS` | `false` | Enable /debug/pprof/* |
| `SAMPLING_ENABLED` | `true` | Enable event sampling |
| `RETENTION_EVENTS_DAYS` | `30` | Canonical event retention |
| `RETENTION_FINDINGS_DAYS` | `90` | Finding retention |
| `RETENTION_INCIDENTS_DAYS` | `365` | Incident retention |
| `RETENTION_TELEMETRY_DAYS` | `30` | Raw telemetry retention |
| `RETENTION_CLEANUP_INTERVAL` | `1h` | Cleanup sweep interval |
| `TRUST_PROXY_HEADERS` | `false` | Use `X-Forwarded-For` for rate limiting (set when behind the ui-proxy only) |
