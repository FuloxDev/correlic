# Correlic Architecture Overview

## System Design Philosophy

Correlic is designed as a **distributed security observability platform** with clear separation of concerns:

1. **Data Collection Layer** (Agent) — Platform-specific kernel telemetry:
   - **Linux**: eBPF tracepoints/kprobes (synchronous, zero-loss)
   - **macOS**: Endpoint Security Framework (ESF) with AUTH/NOTIFY events
   - **Windows**: ETW (Event Tracing for Windows) + Windows Security Audit (Event 4688/4657/4672)
2. **Processing Layer** (Backend) — Event ingestion, sampling, 13 detection rules + 11 chain patterns, severity dampening, block rule enforcement
3. **Storage Layer** (PostgreSQL + Neo4j) — Time-series events + process tree graph. Neo4j is **optional** — the system gracefully degrades when unavailable (graph features disabled, detection rules requiring graph context won't fire)
4. **AI Intelligence Layer** — 3-layer context system (system profile, hierarchical rollups, learned patterns) for AI-powered incident analysis
5. **Presentation Layer** (UI + Proxy) — Visualization, baselines, block rules, incident management

### Block Rules System
Active block rules terminate matching processes in real-time via the agent's soft-block enforcer. Rules are synced from backend to agent every 30 seconds. Blocked findings appear in a dedicated "Blocked" tab in the UI with `status=blocked`.

### AI Intelligence System
Three context layers feed the AI reasoning engine:
- **Layer 1 (System Profile)**: AI agents, network baselines, PATH dirs, tools — updated hourly
- **Layer 2 (Context Windows)**: Hierarchical rollups (1-min → 1-hr → 24-hr → weekly) — navigation indexes for temporal context
- **Layer 3 (Learned Patterns)**: Verdicts from user feedback (dismiss/allow/block) — real-time learning
- **On-demand micro-context**: 5-min + 30-min summaries built at query time for instant AI response quality

See `docs/AI_INTELLIGENCE.md` for the complete AI context assembly flow.

---

## High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                      Monitored Hosts                          │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Linux: eBPF programs (exec, fork, exit, connect,     │  │
│  │         fileopen, dns, setuid, unlink, bind, accept)   │  │
│  │  macOS: ESF + FSEvents + kqueue + lsof                 │  │
│  │  Windows: ETW + USN Journal + Security Audit           │  │
│  └────────────────────────────────────────────────────────┘  │
│         ▲                                                     │
│         │ Ring Buffers / ETW Sessions                         │
│         ▼                                                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Correlic Agent (Go)                                    │  │
│  │  • Event parsing, normalization, classification        │  │
│  │  • AI process lineage tracking (session UUIDs)         │  │
│  │  • Rate limiting, deduplication, buffered dispatch     │  │
│  │  • Block rule enforcement (soft-block / kill)          │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────────┘
                           │ HTTPS (mTLS / API key auth)
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Backend Infrastructure                     │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Backend API (Go, standard library net/http)           │  │
│  │  ┌──────────────────────────────────────────────────┐  │  │
│  │  │  Ingestion Pipeline (POST /ingest/events)        │  │  │
│  │  │  1. Authentication (mTLS + API key validation)   │  │  │
│  │  │  2. Event parsing & validation                   │  │  │
│  │  │  3. Intelligent sampling (90% reduction)         │  │  │
│  │  │  4. Storage (PostgreSQL + Neo4j)                 │  │  │
│  │  │  5. AI attribution (session tracking)            │  │  │
│  │  │  6. Tier 1: Process tree writer (Neo4j)          │  │  │
│  │  │  7. Detection engine (13 rules)                  │  │  │
│  │  │  8. Chain correlation (11 patterns)              │  │  │
│  │  │  9. Incident correlation & notification          │  │  │
│  │  │  10. Behavioral baseline learning                │  │  │
│  │  │  11. Tier 2: Streaming correlation (batched)     │  │  │
│  │  └──────────────────────────────────────────────────┘  │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  PostgreSQL 14+ (primary store)                        │  │
│  │  • telemetry_events, events, findings, incidents      │  │
│  │  • baselines, block_rules, notifications, users       │  │
│  │  • JSONB for flexible event payloads                   │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Neo4j 5+ (optional — graph database)                  │  │
│  │  • Process tree relationships (PROCESS_PARENT)        │  │
│  │  • Activity edges (NET_CONNECT, FILE_WRITE, etc.)     │  │
│  │  • AI label propagation (20-level BFS)                │  │
│  │  • Attack chain visualization                          │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────┬───────────────────────────────────┘
                           │ HTTPS
                           ▼
┌──────────────────────────────────────────────────────────────┐
│                    Frontend Infrastructure                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  UI Proxy (Node.js)                                    │  │
│  │  • TLS termination                                     │  │
│  │  • Routes /api/* → Backend, /* → UI                    │  │
│  └────────────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Web UI (Next.js / React / TypeScript)                 │  │
│  │  • Real-time event timeline                            │  │
│  │  • Process tree visualization                          │  │
│  │  • Incident management + AI chat                       │  │
│  │  • Findings, baselines, block rules management         │  │
│  │  • Notification center + webhook/Slack config          │  │
│  │  • Dashboard with stats and trends                     │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

---

## Component Details

### 1. Correlic Agent (Kernel Telemetry Collection)

**Location:** `Correlic-agent/`

**Purpose:** Collect kernel-level telemetry from monitored hosts across Linux, macOS, and Windows.

**Key Components:**

- **Linux — eBPF Programs** (`internal/ebpf/bpf/*.bpf.c`)
  - 12 eBPF programs: execsnoop, fork, exit, connect, accept, bind, fileopen, dns, setuid, unlink, tls, msg
  - Ring buffer data flow → Go collectors → canonical events

- **macOS — ESF + Polling** (`internal/darwin/`)
  - Endpoint Security Framework (Big Sur+), FSEvents, kqueue, lsof
  - Process, file, network, DNS monitoring

- **Windows — ETW + USN** (`internal/windows/`)
  - 4 ETW kernel providers + Windows Security Audit (Event 4688/4657/4672)
  - NTFS USN Journal for file tracking
  - Command-line caching, credential redaction

- **Cross-platform** (`internal/dispatch/`, `internal/lineage/`, `internal/normalize/`)
  - Buffered dispatcher with rate limiting and deduplication
  - AI process lineage tracking (session UUID inheritance)
  - Exec classification (primary/helper/shell/runtime)

**Event Types:**
- `process_exec` — Process execution (execve / CreateProcess)
- `process_exit` — Process termination
- `net_connect` — TCP/UDP outbound connections
- `net_accept` — Inbound connection accept
- `net_dns` — DNS queries
- `file_open` — File open operations
- `file_write` — File write operations (USN Journal)
- `ai_tool_call` — One Claude Code / Cursor tool call reported by `correlic-hook` (source `hook`, all platforms, no kernel driver)

See `docs/LINUX_AGENT.md`, `docs/WINDOWS_AGENT.md`, `docs/MACOS_AGENT.md` and `docs/HOOKS.md` for platform details.

---

### 2. Backend API (Event Processing & Detection)

**Location:** `correlic-backend/`

**Purpose:** Receive, process, detect threats, correlate incidents, and serve APIs.

**Binaries:**

| Binary | Location | Purpose |
|--------|----------|---------|
| `api` | `cmd/api/main.go` | HTTP server (port 8080) — ingestion, detection, all API endpoints |
| `admin` | `cmd/admin/main.go` | CLI tool — migrations, org management, API key creation |
| `telemetry` | `cmd/telemetry/main.go` | Asynchronous telemetry processing plane |
| `mcp` | `cmd/mcp/main.go` | Model Context Protocol server (LLM-native interface) |

**Technology Stack:**
- Go 1.26+
- Standard library `net/http` (router: `http.NewServeMux()`)
- pgx database driver (via `database/sql` wrapper)
- PostgreSQL 14+ (JSONB for event payloads)
- Neo4j 5+ (optional — graph database for process trees + attack chains)
- TLS 1.2+ with optional mTLS for agent authentication

**Key Subsystems:**

| Subsystem | Package | Doc |
|-----------|---------|-----|
| Ingestion pipeline | `internal/ingest/` | `docs/ARCHITECTURE.md` (this file) |
| Detection engine (13 rules + 11 chains) | `internal/detection/` | `docs/DETECTION_ENGINE.md` |
| Correlation engine (Tier 1 + Tier 2) | `internal/correlation/` | `docs/CORRELATION_ENGINE.md` |
| AI intelligence (3-layer context) | `internal/ai/intelligence/` | `docs/AI_INTELLIGENCE.md` |
| AI layer (LLM providers, tool-calling) | `internal/ai/` | `docs/AI_LAYER.md` |
| Incident engine (clustering + assembly) | `internal/incident/` | `docs/INCIDENT_ENGINE.md` |
| Behavioral baselines | `internal/detection/baseline.go` | `docs/BEHAVIOURAL_ENGINE.md` |
| Notification engine | `internal/notification/` | `docs/ALERT_ENGINE.md` |
| Block rules & enforcement | `internal/storage/block_rule_store.go` | `docs/BLOCK_RULES.md` |
| Auth & RBAC | `internal/api/middleware/` | `docs/AUTH_AND_RBAC.md` |
| Query & timeline | `internal/query/` | `docs/QUERY_AND_TIMELINE.md` |
| Data retention | `internal/maintenance/` | `docs/DATA_RETENTION.md` |

**API Endpoints:** 80+ routes. See `docs/API_REFERENCE.md` for the complete reference.

Key endpoint groups:
- `POST /ingest/events` — Agent event ingestion (primary entry point)
- `/api/v1/findings/*` — Detection findings CRUD
- `/api/v1/incidents/*` — Incident management + AI explain/chat
- `/api/v1/baselines/*` — Behavioral baseline management
- `/api/v1/block-rules/*` — Block rule CRUD + enforcement
- `/api/v1/detection/settings/*` — Per-org rule tuning
- `/api/v1/exceptions/*` — Rule exception management
- `/api/v1/notifications/*` — In-app notifications + webhook/Slack endpoints
- `/auth/*` — Sessions, Google OAuth, password reset, email verification
- `/dashboard/*` — Stats and trends
- `/neo4j/*` — Graph-powered process trees and attack paths
- `/query/*` — Container, port, connection, process queries

---

### 3. UI Proxy (TLS Termination)

**Location:** `correlic-ui-proxy/`

**Purpose:** Thin Node.js HTTPS reverse proxy for TLS termination and request routing.

**Routing:**
- `/api/*` → Backend (port 8080)
- `/*` → UI (port 3000)

---

### 4. Web UI (Visualization & Management)

**Location:** `correlic-ui/`

**Purpose:** Provide web interface for security analysts to manage and investigate threats.

**Key Features:**
- **Event Timeline** — Chronological view of all events
- **Process Tree** — Visualize parent-child relationships (Neo4j-powered)
- **Incident Management** — View, investigate, resolve incidents with AI chat
- **Findings Dashboard** — Detection findings with allow/dismiss/block actions
- **Behavioral Baselines** — Manage learned normal behavior
- **Block Rules** — Create and manage process termination rules
- **Notification Center** — In-app feed + webhook/Slack configuration
- **Dashboard** — Aggregated stats, trends, activity feed

**Technology Stack:**
- Next.js 16+
- React 19, TypeScript
- TailwindCSS
- React Query for data fetching
- Recharts for visualizations
- Framer Motion for animations

---

## Security Architecture

### Authentication & Authorization
- **Agent → Backend:** mTLS (mutual TLS) with client certificates, or API key authentication (Bearer token). Configurable via `ALLOW_API_KEY_AUTH` env var.
- **UI → Backend:** Session-based authentication with bcrypt password hashing. Google OAuth supported.
- **RBAC:** Role-based access control (admin vs regular users) via `middleware/role_guard.go`.
- **Multi-tenancy:** Organization-based isolation — every query filters by `org_id`.
- **Rate limiting:** Configurable per-minute rate limit (default: 300/min) via `CORRELIC_RATE_LIMIT_PER_MIN`.
- **Audit logging:** All authenticated actions logged to `audit_events` table.

### Data Security
- **In-transit:** TLS 1.2+ for all communication
- **At-rest:** PostgreSQL encryption (optional)
- **API keys:** Hashed with bcrypt
- **Credential redaction:** Applied at agent (Windows Security Audit) + backend (exec runner)

### eBPF Security
- **Verifier:** All eBPF programs verified by kernel
- **Capabilities:** Requires CAP_BPF or root
- **Isolation:** eBPF programs run in kernel sandbox

---

## Scalability Considerations

### Current Scale
- **Single backend:** ~1000 agents, ~70 events/sec per agent
- **Database:** PostgreSQL with time-series optimizations
- **Storage:** ~1GB per million events (with sampling)
- **Detection:** <5ms per event (all 13 rules)

### Future Scale (Roadmap)
- **Horizontal scaling:** Multiple backend instances with load balancer
- **Event streaming:** Kafka for event buffering
- **Time-series DB:** ClickHouse or TimescaleDB for better performance
- **Distributed tracing:** OpenTelemetry integration

---

## Deployment Models

### 1. Single-Host Development
- All components on one machine
- Docker Compose for orchestration (`install/docker-compose.yml`)
- Suitable for testing and development

### 2. Multi-Host Production
- Agents on all monitored hosts
- Centralized backend + database
- UI proxy with TLS
- Suitable for small-medium deployments

### 3. Kubernetes (Planned)
- DaemonSet for agents
- Deployment for backend (with HPA)
- StatefulSet for PostgreSQL
- Ingress for UI proxy

---

## Key Design Decisions

### Why eBPF?
- **Performance:** Kernel-level monitoring with <1% overhead
- **Safety:** Verified programs, no kernel crashes
- **Visibility:** Access to kernel data structures
- **Portability:** Works across kernel versions (CO-RE)

### Why Go?
- **Performance:** Compiled, concurrent, low memory
- **eBPF support:** Excellent libraries (cilium/ebpf)
- **Simplicity:** Easy to deploy (single binary)

### Why PostgreSQL?
- **JSONB:** Flexible schema for event payloads
- **Indexes:** Fast time-series queries
- **Reliability:** ACID guarantees
- **Familiarity:** Well-known, easy to operate

### Why Neo4j (Optional)?
- **Process trees:** Parent-child relationships with unlimited depth traversal
- **Attack chains:** BFS/DFS for multi-hop attack path visualization
- **AI labeling:** Propagate AI session labels through process hierarchies
- **Graceful degradation:** System fully functional without it; graph-dependent features simply disabled

### Why Intelligent Sampling?
- **Data volume:** Reduce storage by 90%
- **Signal-to-noise:** Keep security-relevant events
- **Cost:** Lower infrastructure costs
- **Performance:** Faster queries on smaller dataset

---

## Next Steps

See [ROADMAP.md](./ROADMAP.md) for planned features and improvements.
