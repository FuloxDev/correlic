# Correlation Engine

The correlation engine maps all kernel/AI events into a connected graph, establishing process trees, activity edges, and AI attribution. It operates in two tiers: real-time process tree building and batched activity correlation.

## What needs the graph (Neo4j is opt-in)

Neo4j is an optional upgrade. Both backend planes start without it whenever
`NEO4J_URI` is empty (the default in every install profile: `docker compose up`
without `--profile graph`, `install.sh --without-neo4j`, `install.ps1 -NoNeo4j`,
the all-in-one image with `CORRELIC_GRAPH=off`, the Kubernetes base overlay).
A configured but unreachable Neo4j logs one warning and the planes run without it.

Exactly these features require the graph:

| Feature | Without Neo4j |
|---------|---------------|
| **`ai.data_exfiltration`** — read-then-exfiltrate correlation over the last 15 min (`GetRecentEventsBySession` / `GetProcessAncestors` / `GetRecentEventsMultiPID`) | Does not fire: the look-back returns no events |
| **`ai.excessive_writes`** — file-write burst scoring over the last 30 s (`GetRecentEvents`) | Does not fire: the look-back returns no events |
| **Graph timeline** — `/neo4j/timeline`, `/neo4j/process-tree`, `/neo4j/attack-path`, `/processes/tree`, `/processes/activity`, `/processes/summary`, `/neo4j/investigation/*` | Routes are not registered (404); the UI hides the graph views |
| Tier 1 process-tree writer, Tier 2 batched correlation, AI label propagation, graph-backed incident context | Disabled |

`ai.discovery` is a partial case: its active-scanner signal (nmap, masscan, …)
fires without the graph; its "3+ distinct discovery commands in 60 s" burst
reads the same look-back window, so on PostgreSQL alone it only ever sees the
current command and does not reach the threshold.

Everything else works on PostgreSQL alone: ingestion and sampling, the other
11 detection rules and all 11 chain patterns (AI attribution comes from the
agent's own session tags and the attribution cache, see
`detection.AttributionQuerier`), baselines, exceptions, incidents, block rules,
notifications, the dashboard (including the live activity feed and the Agent
Activity page, which `/agents/activity` serves from the events table), the AI
explain/chat endpoints and the MCP server. `GET /health` reports
`detection_graph: enabled|disabled` so an operator can see which mode a plane
runs in.

## Architecture

```
Event ingested via POST /ingest/events
  |
  v
Validation + Sampling
  |
  v
Store in PostgreSQL (telemetry_events + events)
  |
  v
AI Attribution (track AI agent sessions)
  |
  v
Tier 1: ProcessTreeWriter (real-time)
  |-- UpsertProcessAndLink() -> Neo4j immediate write
  |-- Creates PROCESS_PARENT edges in real-time
  '-- PropagateAILabels() -> Labels AI descendants
  |
  v
Detection Engine evaluates event (uses graph for context)
  |
  v
Tier 2: EventBuffer -> Worker -> CorrelationWindow
  |-- Buffers events per host
  |-- Flushes on: age >= 5min OR count >= 1000 OR idle >= 30s
  |-- BuildGraph() -> Creates temporal, activity, file, network edges
  '-- Neo4j batch write
  |
  v
Neo4j Graph (process tree + activity edges + AI labels)
  |
  v
Graph API endpoints (attack chain, process tree, session activity)
```

## Key Files

| File | Purpose |
|------|---------|
| `internal/correlation/buffer.go` | Thread-safe non-blocking event queue (10k capacity) |
| `internal/correlation/worker.go` | Consumes buffer, routes to per-host windows, periodic flush |
| `internal/correlation/window_manager.go` | CorrelationWindow: accumulates events, flushes to Neo4j |
| `internal/correlation/window.go` | Builder: on-demand correlation around anchor event |
| `internal/correlation/graph.go` | BuildGraph(): deterministic in-memory graph with typed edges |
| `internal/correlation/order.go` | OrderEvents(): stable timestamp sort |
| `internal/correlation/context.go` | CorrelatedContext: anchor + window + events + graph |
| `internal/correlation/process_tree_writer.go` | Tier 1: real-time process tree to Neo4j |
| `internal/storage/neo4j/graph_store.go` | Neo4j CRUD: events, edges, AI labeling, process linking |
| `internal/storage/neo4j/persister.go` | GraphPersister: Tier 2 batch persistence + AI propagation |
| `internal/storage/neo4j/client.go` | Neo4j driver wrapper (read/write/session) |
| `internal/storage/neo4j/queries.go` | Graph query methods (attack chain, process tree, lateral movement) |
| `internal/storage/neo4j/handler.go` | HTTP handlers for graph API endpoints |
| `internal/ai/attribution/service.go` | AI session tracking and event attribution |
| `internal/ai/attribution/postgres_store.go` | DB store for AI patterns + sessions |
| `internal/detection/graph_querier.go` | Detection-facing Neo4j queries (IsAIProcess, GetRecentEvents) |
| `internal/ingest/live_ingest.go` | Ingestion pipeline: sampling -> attribution -> Tier 1 -> detection -> Tier 2 |

## Two-Tier Correlation

### Tier 1: Real-Time Process Tree (ProcessTreeWriter)

Handles `process_exec` events immediately:
1. `UpsertProcessAndLink(ctx, evt)` creates event node in Neo4j
2. Finds parent by `(host_id, actor_pid == ppid, type == process_exec)` with timestamp ordering
3. Creates `PROCESS_PARENT` edge immediately
4. Calls `PropagateAILabels()` to label AI descendants

**Why Tier 1 exists**: Process tree must be correct before detection rules query it. Batching would introduce race conditions where a child is queried before its parent edge exists.

### Tier 2: Batched Activity Correlation (Worker + EventBuffer)

Handles all event types via buffered windows:
1. `EventBuffer.Push()` enqueues event (non-blocking, drops if full)
2. Worker routes events to per-host `CorrelationWindow`
3. Windows flush on: age >= 5min, count >= 1000, or idle >= 30s
4. `BuildGraph()` creates typed edges (temporal, network, file, lifecycle)
5. `GraphPersister.PersistGraph()` writes batch to Neo4j

## EventBuffer

```go
type EventBuffer struct {
    events  chan *event.Event   // 10,000 capacity
    done    chan struct{}       // Close signal
    closed  atomic.Bool        // Thread-safe close flag
    dropped atomic.Int64       // Drop counter
}
```

- `Push()`: Non-blocking. Returns error if full (increments drop counter). Has `case <-b.done:` to prevent panic on concurrent close.
- `Close()`: Uses CompareAndSwap to close once. Closes `done` channel first (signals consumers), then `events` channel.
- Drop policy: Events dropped when buffer full. Prevents eBPF reader from blocking.

## CorrelationWindow

```go
type CorrelationWindow struct {
    hostID      string
    events      []*event.Event  // Pre-allocated 1000 capacity
    startTime   time.Time
    lastEventAt time.Time
    maxAge      time.Duration   // 5 minutes (default)
    mu          sync.RWMutex
}
```

- `ShouldFlush()`: True when age >= maxAge OR count >= 1000
- `IsIdle()`: True when no events for idleThreshold (30s)
- `BuildAndPersist()`: Orders events -> BuildGraph() -> PersistGraph()

## Worker

```go
type Worker struct {
    buffer         *EventBuffer
    graphPersister GraphPersister
    windowSize     time.Duration   // 5 min
    flushInterval  time.Duration   // 30 sec
    windows        map[string]*CorrelationWindow  // host_id -> window
}
```

Runs 2 goroutines:
1. **Event processor**: Reads from buffer, routes to per-host windows, auto-flushes full windows
2. **Periodic flusher**: Every 30s, flushes idle windows

Shutdown: `flushAll()` persists all remaining windows when buffer closes.

## EventGraph (In-Memory)

```go
type EventGraph struct {
    Nodes map[string]event.Event
    Edges []EventEdge
}

type EventEdge struct {
    From, To, Type string
}
```

`BuildGraph()` creates deterministic edges:

| Edge Type | Logic |
|-----------|-------|
| `temporal` | Consecutive events in timestamp order |
| `process_parent` | Event with PPID -> first event with matching PID |
| `process_net_connect` | net_connect -> its process_exec (by PID) |
| `process_net_listen` | net_listen -> its process_exec |
| `process_net_accept` | net_accept -> its process_exec |
| `process_net_msg` | net_msg -> its process_exec |
| `process_net_tls` | net_tls -> its process_exec |
| `process_file_open` | file_open -> its process_exec |
| `process_file_write` | file_write -> its process_exec |
| `process_file_unlink` | file_unlink -> its process_exec |
| `process_lifecycle_exit` | process_exec -> process_exit (same PID) |
| `process_container_start` | container_start -> its process_exec |

**Unpaired exit handling**: process_exit without matching process_exec is filtered from nodes.

## Neo4j Schema

### Constraints & Indexes (InitializeSchema)
- UNIQUE constraint: `Event.id`
- Indexes: `timestamp`, `type`, `host_id`, `(actor_pid, host_id)`, `(session_id, host_id)`, `(ai_session_id, host_id)`, `(type, timestamp)`, `ai_type`

### Relationship Types (edgeTypeToNeo4j mapping)
- `temporal` -> `TEMPORAL`
- `process_parent` -> `PROCESS_PARENT`
- `process_lifecycle_exit` -> `LIFECYCLE`
- `process_net_*` -> `NET_CONNECT`, `NET_LISTEN`, `NET_ACCEPT`, `NET_MSG`, `NET_TLS`
- `process_file_*` -> `FILE_OPEN`, `FILE_WRITE`, `FILE_UNLINK`
- `ai_spawned` -> `AI_SPAWNED`

### Node Properties
Every `:Event` node has: `id`, `timestamp`, `host_id`, `source`, `type`, `actor_pid`, `actor_ppid`, `actor_exe_path`, `actor_user`, `actor_comm`, `actor_role`, `actor_cmdline` (JSON array), `session_id`, `target_file_path`, `target_ip`, `target_port`, `target_protocol`, `target_domain`

AI agent nodes additionally have: `:AIAgent` label, `ai_type`, `ai_root` (set on propagated descendants)

## AI Attribution

### Service (`internal/ai/attribution/service.go`)

Tracks which processes belong to AI agent sessions:

```go
type Service struct {
    store        Store
    sessionCache map[string]*AIAgentSession  // key: "orgID:agentID:pid"
}
```

**Attribution flow** (called on every `process_exec`):
1. Check if process comm matches known AI pattern -> create new session
2. Check if parent PID is in a cached session -> mark as child
3. Cache result for grandchildren lookup

**Cache key**: `orgID + ":" + agentID + ":" + strconv.FormatInt(pid, 10)`

### AI Label Propagation (`PropagateAILabels`)

After process tree is built:
```cypher
MATCH (ai:Event:AIAgent {host_id: $host_id, type: 'process_exec'})
WHERE ai.ai_root IS NULL
MATCH path = (ai)-[:PROCESS_PARENT*1..20]->(child:Event {type: 'process_exec'})
WHERE NOT child:AIAgent
SET child:AIAgent, child.ai_type = ai.ai_type, child.ai_root = ai.id
```

### IsAIProcess (Detection Query)

Two-stage lookup for detection rules:
1. **Direct**: Check if PID has `:AIAgent` label (fast path)
2. **Ancestor walk**: If direct fails, walk up PROCESS_PARENT*1..10 to find labeled ancestor (handles propagation race)

## Graph API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /api/v1/graph/attack-chain?event_id=&pid=&host_id=` | BFS from event, max depth 10 |
| `GET /api/v1/graph/process-tree?pid=&host_id=` | 5 levels up, 10 levels down |
| `GET /api/v1/graph/related-events?target_path=&target_ip=` | Events by file or IP |
| `GET /api/v1/graph/lateral-movement?host_id=&since=` | Processes with net + children |
| `GET /api/v1/graph/session-activity?session_id=&host_id=` | All events in session |
| `GET /api/v1/graph/container-activity?container_id=` | All events in container |

## GraphQuerier (Detection Interface)

| Method | Purpose | Limit |
|--------|---------|-------|
| `GetRecentEvents(hostID, pid, since, types)` | Events for single PID in window | 100 |
| `GetRecentEventsMultiPID(hostID, pids, since, types)` | Events for PID list | 500 |
| `GetRecentEventsBySession(hostID, sessionID, since, types)` | Session-scoped events | 500 |
| `GetProcessAncestors(hostID, pid, maxDepth)` | Walk PROCESS_PARENT chain | depth param |
| `IsAIProcess(hostID, pid)` | Check AI label (direct + ancestor walk) | 1 |

All query methods return: `id, type, timestamp, comm, exe_path, cmdline, target_path, target_ip, target_port`.

## Event Flow (Agent -> Backend -> Neo4j)

### Agent Side
```
eBPF kernel -> Ring Buffer -> Collector (parses binary struct)
  -> Runner (enriches: timestamp, host_id, session_id, event ID)
  -> BufferedDispatcher (rate limit, dedupe, 50k buffer)
  -> HTTPSink (batches 10 events or 500ms timeout)
  -> POST /api/v1/ingest/events
```

### Backend Side (IngestCanonicalEvents)
```
For each event:
  1. Validate (schema=1, ID, HostID, PID)
  2. Sample (if sampler configured)
  3. Store to PostgreSQL (telemetry_events + events)
  4. AI Attribution (track sessions for process_exec)
  5. Tier 1: ProcessTreeWriter.IngestProcess() -> Neo4j immediate
  6. Detection: engine.Evaluate() -> baselines -> exceptions -> cooldown -> findings -> chains
  7. Baseline: learn clean event patterns
  8. Tier 2: eventBuffer.Push() -> Worker -> CorrelationWindow -> Neo4j batch
```

## Actor Field Semantics

| Field | Set By | Source | Meaning |
|-------|--------|--------|---------|
| `Comm` | All handlers | `bpf_get_current_comm` | 16-byte kernel process name (e.g., "python3") |
| `ExePath` | exec_handler ONLY | `/proc/PID/exe` readlink | Full binary path (e.g., "/usr/bin/python3") |
| `Cmdline` | exec_handler ONLY | `/proc/PID/cmdline` | Full argument list as string array |
| `SessionID` | All handlers | `detectSessionID()` | Login session for cross-process correlation |

**Design rule**: Only `process_exec` events have reliable `ExePath` and `Cmdline`. All other event types set `Comm` only.

## Configuration Defaults

| Parameter | Value | Location |
|-----------|-------|----------|
| EventBuffer capacity | 10,000 | cmd/api/main.go |
| Window max age | 5 minutes | cmd/api/main.go |
| Worker flush interval | 30 seconds | cmd/api/main.go |
| Window flush threshold | 1,000 events | window_manager.go |
| AI propagation depth | 20 edges | graph_store.go |
| IsAIProcess ancestor walk | 10 edges | graph_querier.go |
| Graph query default depth | 10 | handler.go |
| Process tree query | 5 up, 10 down | queries.go |
| Agent dispatch buffer | 50,000 | dispatcher.go |
| Agent HTTP batch size | 10 events | http_sink.go |
| Agent HTTP batch timeout | 500ms | http_sink.go |

## Interfaces

```go
// Tier 2 batched persistence
type GraphPersister interface {
    PersistGraph(ctx, events []event.Event, graph *EventGraph) error
    PropagateAILabels(ctx, hostID string) (int, error)
}

// Tier 1 real-time persistence
type ProcessTreePersister interface {
    UpsertProcessAndLink(ctx, evt *event.Event) error
    PropagateAILabels(ctx, hostID string) (int, error)
}

// AI attribution storage
type Store interface {
    GetPatterns() ([]AIAgentPattern, error)
    GetPattern(comm string) (string, error)
    UpsertSession(session *AIAgentSession) error
    FindSessionByPID(orgID, agentID string, pid int64) (*AIAgentSession, error)
    IncrementEventCount(sessionID int64) error
    CountDistinctAgents(orgID string, since time.Time) (int, error)
    ListActiveSessions(orgID string, since time.Time, limit int) ([]AIAgentSession, error)
}

// Detection graph queries
type GraphQuerier interface {
    GetRecentEvents(ctx, hostID string, pid int, since time.Time, types []string) ([]event.Event, error)
    GetRecentEventsMultiPID(ctx, hostID string, pids []int, since time.Time, types []string) ([]event.Event, error)
    GetRecentEventsBySession(ctx, hostID, sessionID string, since time.Time, types []string) ([]event.Event, error)
    GetProcessAncestors(ctx, hostID string, pid, maxDepth int) ([]event.Event, error)
    IsAIProcess(ctx, hostID string, pid int) (bool, string, error)
}
```

## Resilience & Edge Cases

- **Neo4j optional**: If unavailable, Tier 1 + Tier 2 disabled gracefully. The look-back queries return empty results, so `ai.data_exfiltration` and `ai.excessive_writes` never fire and `ai.discovery` loses its burst signal (see "What needs the graph" above); every other rule is unaffected.
- **Non-blocking persistence**: Buffer drops when full; ProcessTreeWriter errors logged but don't fail ingestion; GraphPersister errors in Builder don't fail correlation.
- **PID reuse**: First occurrence per PID wins for parent lookup. No time limit on parent search (supports long-running daemons).
- **Unpaired exits**: process_exit without matching process_exec filtered from graph nodes.
- **AI propagation race**: IsAIProcess has ancestor walk fallback for children queried before label propagates.
- **Buffer close race**: Push() has `case <-b.done:` to prevent send-on-closed-channel panic.
- **Cmdline storage**: Stored as JSON array in Neo4j. Read back with json.Unmarshal + fallback for legacy space-joined data.
- **LinkOrphans**: Dead code (no longer called). Tier 1 handles all process linking in real-time.

## Bugs Fixed (Audit Q1 2026)

| # | Severity | Bug | File |
|---|----------|-----|------|
| 1 | CRITICAL | cacheKey `string(rune(pid))` -> Unicode, not decimal | attribution/service.go |
| 2 | HIGH | EventBuffer.Push() TOCTOU panic (send on closed channel) | correlation/buffer.go |
| 3 | HIGH | Exit handler missing Comm field | agent/exit_handler.go |
| 4 | HIGH | ExePath=Comm in 8 handlers (semantic corruption) | agent: 6 runners + msg_handler + accept_handler |
| 5 | MEDIUM | LinkOrphans MERGE on null parent (defensive, dead code) | neo4j/graph_store.go |
| 6 | MEDIUM | IsAIProcess: no ancestor walk fallback | detection/graph_querier.go |
| 7 | MEDIUM | Cmdline stored as joined string, read as single-element array | graph_store.go + graph_querier.go |
| 8 | LOW | GetProcessAncestors missing cmdline in RETURN | detection/graph_querier.go |
