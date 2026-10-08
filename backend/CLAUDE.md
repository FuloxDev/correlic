# Correlic Backend — Claude Code Context

## Purpose
Go API server. Receives telemetry from agents (Linux/macOS/Windows), applies intelligent sampling (90% reduction), runs 13 detection rules + 11 chain patterns, correlates incidents, stores events in PostgreSQL + Neo4j (optional), and serves 80+ API endpoints to the UI.

## Tech Stack
- Go 1.26+, standard library `net/http` (`http.NewServeMux()`), pgx driver (via `database/sql`)
- PostgreSQL 14+ (JSONB for event payloads)
- Neo4j 5+ (optional — graph database for process trees + attack chains)
- Env vars: `DATABASE_URL`, `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_PASSWORD`, `TLS_CERT_FILE`, `TLS_KEY_FILE`, `MTLS_CA_FILE`, `ALLOW_API_KEY_AUTH`, `ENABLE_DEBUG_ENDPOINTS`, `CORRELIC_RATE_LIMIT_PER_MIN`, `LLM_ENCRYPTION_KEY`, `GOOGLE_CLIENT_ID`, `FRONTEND_URL`

## Directory Structure
```
correlic-backend/
├── cmd/
│   ├── api/main.go         # HTTP server entry point (port 8080)
│   ├── admin/main.go       # CLI: migrations, org management
│   ├── telemetry/main.go   # Async telemetry processing plane
│   └── mcp/main.go         # Model Context Protocol server
├── internal/
│   ├── ingest/             # Ingestion pipeline + sampling
│   │   ├── sampler.go      # Sampling decision logic (SECURITY-FIRST order!)
│   │   └── sampling_rules.go  # 80+ detection patterns + user watchlists
│   ├── event/              # Canonical event types/schemas
│   ├── storage/            # DB access layer (PostgreSQL + Neo4j)
│   │   ├── neo4j/          # Neo4j graph persistence + queries
│   │   └── eventstore/     # Canonical event store
│   ├── api/                # HTTP handlers (80+ endpoints)
│   │   └── middleware/     # Auth, RBAC, rate limiting, audit, mTLS
│   ├── ai/                 # AI intelligence layers
│   │   ├── intelligence/   # 3-layer context (profile, windows, patterns)
│   │   ├── provider/       # BYOK LLM providers (OpenAI, Anthropic, Gemini, Groq)
│   │   ├── dossier/        # Pre-computed LLM context for incidents
│   │   ├── conversation/   # Threaded chat store
│   │   └── attribution/    # AI process session tracking
│   ├── correlation/        # Event correlation (Tier 1 real-time + Tier 2 batched)
│   ├── detection/          # Detection engine (13 rules + 11 chain patterns)
│   │   └── ai_pack/        # AI detection rules
│   ├── incident/           # Incident clustering + context assembly
│   ├── notification/       # Alert delivery (webhook, Slack, in-app)
│   ├── enrichment/         # Event enrichment (IP resolution)
│   ├── query/              # Query services (PostgreSQL + Neo4j timeline)
│   ├── service/            # Business logic (agent inventory)
│   ├── maintenance/        # Data retention cleanup
│   ├── model/              # Data models
│   ├── config/             # Environment loading
│   ├── mcp/                # MCP integration
│   └── tier/               # Tier/subscription logic
├── migrations/             # consolidated SQL migrations (schema, seed, incremental)
├── docs/                   # Architecture & design docs (start here for AI context)
│   ├── SYSTEM_REFERENCE.md # Master AI context doc — START HERE
│   ├── ARCHITECTURE.md     # System design + component overview
│   ├── DETECTION_ENGINE.md # 13 rules + 11 chains + engine architecture
│   ├── CORRELATION_ENGINE.md # Tier 1/2 correlation + Neo4j schema
│   ├── AI_INTELLIGENCE.md  # 3-layer AI context system
│   ├── AI_LAYER.md         # LLM providers, tool-calling, conversation threading
│   ├── INCIDENT_ENGINE.md  # Finding → incident clustering
│   ├── ALERT_ENGINE.md     # Notification delivery pipeline
│   ├── BEHAVIOURAL_ENGINE.md # Behavioral baseline learning
│   ├── BLOCK_RULES.md      # Block rules & enforcement
│   ├── AUTH_AND_RBAC.md    # Authentication & authorization
│   ├── API_REFERENCE.md    # Complete 80+ endpoint reference
│   ├── LINUX_AGENT.md      # eBPF-based Linux agent
│   ├── WINDOWS_AGENT.md    # ETW + USN Windows agent
│   ├── MACOS_AGENT.md      # ESF + kqueue macOS agent
│   ├── HOOKS.md            # correlic-hook: Claude Code / Cursor tool hooks (ai_tool_call)
│   ├── LAYERS.md           # 4-layer architecture overview
│   ├── ROADMAP.md          # v0.3 status + planned features
│   ├── ai_process_tracking.md  # AI process race condition handling
│   └── suspicious-files-reference.md  # Full detection pattern list
└── go.mod
```

## Key API Endpoints
| Method | Path | Purpose |
|--------|------|---------|
| POST | `/ingest/events` | Agent canonical event ingestion (primary entry) |
| GET | `/api/v1/findings` | List detection findings |
| PATCH | `/api/v1/findings/{id}` | Resolve finding (allow/dismiss/investigate) |
| GET | `/api/v1/incidents` | List incidents |
| GET | `/api/v1/incidents/{id}` | Full incident detail + timeline |
| POST | `/api/v1/incidents/{id}/explain` | AI explain incident |
| POST | `/api/v1/incidents/{id}/chat` | AI threaded chat about incident |
| GET/POST | `/api/v1/baselines` | Behavioral baseline management |
| GET/POST | `/api/v1/block-rules` | Block rule CRUD |
| GET/POST | `/api/v1/exceptions` | Rule exception management |
| GET | `/api/v1/detection/settings` | Per-org rule thresholds |
| GET | `/api/v1/notifications` | In-app notifications |
| GET/POST | `/api/v1/notification-endpoints` | Webhook/Slack config |
| POST | `/auth/sessions` | Login (email/password) |
| POST | `/auth/google` | Google OAuth sign-in |
| GET | `/dashboard/stats` | Dashboard metrics |
| GET | `/health` | Health check |

See `docs/API_REFERENCE.md` for the complete 80+ endpoint reference.

## CRITICAL: Sampling Order (security-first)
```go
// CORRECT — suspicious check BEFORE benign drop
if IsAlwaysKeep(evt)  { return true  }  // privilege_escalation, credential_access
if IsSuspicious(evt)  { return true  }  // cat /etc/shadow → KEPT
if IsBenignProcess(evt) { return false } // /bin/ls → dropped
return rand.Float64() < sampleRate       // probabilistic
```
NEVER reorder these — benign check before suspicious is a security hole.

## Detection Patterns
80+ patterns across 12 categories in `internal/ingest/sampling_rules.go`:
SSH keys · Cloud credentials (.aws/, .kube/, .gcloud/) · /etc/shadow, /etc/passwd
Container secrets · DB configs · Certs · /proc/, /sys/kernel/ · Logs · Browser data

## Database Schema (Key Tables)
```sql
telemetry_events (id, org_id, agent_id, event_type, event_ts, payload JSONB, received_at)
events (id, host_id, ts, type, source, actor JSONB, target JSONB, context JSONB)
findings (id, org_id, host_id, detection_id, severity, confidence, status, context JSONB, incident_id)
incidents (id, org_id, host_id, severity, finding_ids TEXT[], status, context_summary JSONB)
behavioral_baselines (id, org_id, host_id, signal_type, pattern, source, status)
block_rules (id, org_id, name, pattern JSONB, enabled)
block_events (id, host_id, block_rule_id, event_id, action, blocked_at)
notifications (id, org_id, category, severity, reference_type, reference_id, read, dismissed)
notification_endpoints (id, org_id, type, config JSONB, min_severity)
organizations (id, name) · users (id, org_id, email, role) · api_keys (id, org_id, key_hash)
```

## Running
```bash
export DATABASE_URL="postgres://correlic:correlic@localhost:5432/correlic"
go run ./cmd/admin migrate up
go run ./cmd/admin bootstrap --name Local --certs-dir "$PWD/.certs"   # org, admin, keys, certs, agent.yaml
TLS_CERT_FILE=.certs/server.crt TLS_KEY_FILE=.certs/server.key MTLS_CA_FILE=.certs/ca.crt \
LLM_ENCRYPTION_KEY=$(openssl rand -hex 32) go run ./cmd/api        # :8080 (mTLS required)
TLS_CERT_FILE=.certs/server.crt TLS_KEY_FILE=.certs/server.key MTLS_CA_FILE=.certs/ca.crt go run ./cmd/telemetry   # :8081

# Tests
go test ./...
```

## Admin CLI (`cmd/admin`)
```bash
go run ./cmd/admin migrate up|status
go run ./cmd/admin bootstrap --name <org> --certs-dir <dir>          # everything a fresh install needs
go run ./cmd/admin create-org --name <name>                           # prints org_id=
go run ./cmd/admin create-user --org-id <id> --email <e> --name <n> --role admin|member   # prints user_id=, password=
go run ./cmd/admin create-service-account --org-id <id> --email <e> --name <n> --role member   # prints user_id=
go run ./cmd/admin create-api-key --org-id <id> --user-id <uid> --name <n> [--type service|agent]   # prints api_key=
go run ./cmd/admin enroll-client-cert --org-id <id> --name <n> --cert-file <client.crt>
```
Agent keys (`--type agent`) only reach ingest, heartbeat and agent endpoints; dashboard keys and sessions carry the user's role.

## Docs (read these for deep context)
- `docs/SYSTEM_REFERENCE.md` — **START HERE** — master AI context doc
- `docs/ARCHITECTURE.md` — system design + all components
- `docs/DETECTION_ENGINE.md` — 13 rules + 11 chains
- `docs/AI_INTELLIGENCE.md` — 3-layer AI context system
- `docs/INCIDENT_ENGINE.md` — incident clustering
- `docs/ai_process_tracking.md` — AI process race condition handling
- `docs/suspicious-files-reference.md` — full detection pattern list
