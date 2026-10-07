# Incident Engine (Phase 4)

The incident engine groups related detection findings into incidents — the primary investigation unit. Each incident is a correlated package of findings with temporal timeline, process ancestry, MITRE mapping, and event graph context. This is the last processing stage before the AI layer (Phase 5), so incidents produce structured, AI-consumable context packages.

## Architecture

```
Detection Engine produces Finding
  |
  v
FindingStore.Insert() -> PostgreSQL (findings table)
  |
  v
IncidentCorrelator.Ingest(ctx, orgID, finding)
  |
  ├── Chain finding? (detection_id starts with "chain.")
  │     |
  │     v
  │   Extract chain_steps from Context["chain_steps"]
  │     |
  │     v
  │   Create new Incident with ALL step findings + chain finding
  │     |
  │     v
  │   IncidentStore.Upsert() -> PostgreSQL (incidents table)
  │     |
  │     v
  │   FindingStore.SetIncidentID() for each finding
  │
  └── Standalone finding?
        |
        v
      Extract session_id from Context["session_id"]
        |
        v
      IncidentStore.FindMergeCandidate(hostID, sessionID, 30min)
        |
        ├── Candidate found? -> mergeInto() -> Update existing incident
        │     |-- Append finding to finding_ids
        │     |-- Recalculate severity (highest-wins + chain amplification)
        │     |-- Union MITRE techniques
        │     |-- Extend ended_at
        │     |-- Reopen auto_resolved if new finding is non-low
        │     '-- FindingStore.SetIncidentID()
        │
        └── No candidate? -> createSeed() -> New single-finding incident
              |-- Low severity? -> status = "auto_resolved"
              |-- Otherwise -> status = "open"
              '-- FindingStore.SetIncidentID()
  |
  v
Incident in PostgreSQL (incidents table)
  |
  v
API: GET /api/v1/incidents/{id}
  |
  v
ContextAssembler.Assemble(ctx, orgID, incidentID)
  |
  ├── 1. Load Incident from IncidentStore.GetByID()
  ├── 2. Load all Findings from FindingStore.GetByID() for each finding_id
  ├── 3. Collect PIDs from finding contexts
  ├── 4. Query Neo4j: QueryAttackChain() by event ID or PID
  ├── 5. Query Neo4j: GetProcessTree() from first PID
  ├── 6. Build timeline: merge findings + graph events, sort chronologically
  └── 7. Return IncidentDetail (AI-consumable package)
```

## Key Files

| File | Purpose |
|------|---------|
| `internal/incident/types.go` | Core types: Incident, IncidentDetail, TimelineEntry, ProcessNode, EventGraph |
| `internal/incident/store.go` | PostgreSQL CRUD: Upsert, GetByID, List, CountByStatus, UpdateStatus, FindMergeCandidate, Update, GetFindingIDs |
| `internal/incident/correlator.go` | Finding→incident clustering: chain vs standalone, merge logic, severity recalculation |
| `internal/incident/assembler.go` | On-demand IncidentDetail assembly from PostgreSQL + Neo4j |
| `internal/api/incidents_handler.go` | HTTP handlers: list, detail, status update with cascade, timeline |
| `internal/api/dashboard.go` | Dashboard handler with incident counts (IncidentSummaryStats) |
| `internal/storage/finding_store.go` | Modified: added incident_id field + SetIncidentID() method |
| `internal/ingest/live_ingest.go` | Modified: incidentCorrelator param + integration after chain correlation |
| `internal/api/live_ingest.go` | Modified: incidentCorrelator field on LiveIngestHandler |
| `cmd/api/main.go` | Wiring: incidentStore, incidentCorrelator, contextAssembler, routes |
| `cmd/telemetry/main.go` | Wiring: incidentStore, incidentCorrelator (parity with API plane) |
| `migrations/055_incidents.sql` | Incidents table schema + indexes |
| `migrations/056_findings_incident_id.sql` | findings.incident_id column + index |

## Data Model

### Incident (PostgreSQL)

```go
type Incident struct {
    ID              string         // Format: "inc:{sha256(host:finding)[:8]}:{unix_ts}"
    OrgID           string         // Multi-tenant isolation
    HostID          string         // Host where events occurred
    Severity        string         // critical | high | medium | low
    Confidence      float64        // Weighted average of findings' confidence
    Title           string         // Inherited from highest-severity finding
    Summary         string         // Description
    MITRETechniques []string       // Union of all findings' MITRE techniques
    FindingIDs      []string       // Ordered by timestamp
    ChainFindingID  string         // Set if seeded by a chain finding
    StartedAt       time.Time      // First finding timestamp
    EndedAt         time.Time      // Last finding timestamp
    ContextSummary  map[string]any // Pre-computed: finding_count, detection_ids, ai_types, session_ids, pids
    Status          string         // open | investigating | resolved | dismissed | auto_resolved
    Resolution      *string        // User-provided reason
    ResolvedBy      *string        // Actor who resolved
    ResolvedAt      *time.Time     // When resolved
    CreatedAt       time.Time
    UpdatedAt       time.Time
}
```

### IncidentDetail (API Response — AI-consumable)

```go
type IncidentDetail struct {
    Incident                         // All PostgreSQL fields
    Findings    []FindingSummary     // Resolved findings with context
    Timeline    []TimelineEntry      // Chronological: findings + events merged
    ProcessTree *ProcessNode         // Tree from Neo4j (nil if unavailable)
    EventGraph  *EventGraph          // Nodes + Edges from Neo4j (nil if unavailable)
}
```

### TimelineEntry

```go
type TimelineEntry struct {
    Timestamp  time.Time      // When this happened
    Type       string         // "finding" | "event" | "chain"
    EventType  string         // e.g. "process_exec", "file_open" (events only)
    Title      string         // Human-readable label
    Detail     string         // Extended description
    Severity   string         // For findings: critical/high/medium/low
    EventID    string         // Neo4j event ID (events only)
    FindingID  string         // Finding ID (findings only)
    PID        int            // Process ID
    Properties map[string]any // Extra properties
}
```

### Supporting Types

```go
type FindingSummary struct {
    ID, DetectionID, Severity, Title, Summary, Status string
    Confidence float64
    Context    map[string]any
    Timestamp  time.Time
}

type ProcessNode struct {
    PID, PPID  int
    Comm       string
    ExePath    string
    User       string
    AIType     string          // Set if this is an AI agent process
    StartedAt  *time.Time
    FindingIDs []string        // Findings associated with this PID
    Children   []*ProcessNode  // Child processes
}

type EventGraph struct {
    Nodes []EventNode
    Edges []EventEdge
}

type IncidentCounts struct {
    Total, Open, Investigating, Resolved, Dismissed, AutoResolved int
}

type ListOptions struct {
    Status, Severity, HostID string
    Since                    time.Time
    Limit, Offset            int
}
```

## Database Schema

### incidents table (migration 055)

```sql
CREATE TABLE incidents (
    id              TEXT PRIMARY KEY,      -- "inc:{hash}:{unix_ts}"
    org_id          TEXT NOT NULL DEFAULT '',
    host_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,          -- critical|high|medium|low
    confidence      FLOAT NOT NULL DEFAULT 0,
    title           TEXT NOT NULL,
    summary         TEXT,
    mitre_techniques TEXT[],               -- Union of all findings' techniques
    finding_ids     TEXT[] NOT NULL,        -- Ordered by timestamp
    chain_finding_id TEXT,                 -- Set if seeded by chain finding
    started_at      TIMESTAMPTZ NOT NULL,
    ended_at        TIMESTAMPTZ NOT NULL,
    context_summary JSONB,                 -- Pre-computed for list views
    status          TEXT NOT NULL DEFAULT 'open',
    resolution      TEXT,
    resolved_by     TEXT,
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);
```

**Indexes**: `(org_id)`, `(org_id, status)`, `(host_id)`, `(severity)`, `(created_at DESC)`

### findings.incident_id (migration 056)

```sql
ALTER TABLE findings ADD COLUMN incident_id TEXT;
CREATE INDEX idx_findings_incident ON findings(incident_id);
```

### context_summary JSONB structure

```json
{
    "finding_count": 3,
    "detection_ids": ["ai.credential_access", "ai.data_exfiltration"],
    "ai_types": ["claude-code"],
    "session_ids": ["ses_abc123"],
    "pid_count": 2,
    "pids": [1234, 5678]
}
```

## IncidentCorrelator

Runs synchronously in the ingestion pipeline after chain correlation and finding storage. Nil-safe: if correlator is nil, all methods return early.

```go
type IncidentCorrelator struct {
    store        *IncidentStore
    findingStore *storage.FindingStore
    mergeWindow  time.Duration  // 30 minutes
}
```

### Clustering Logic

**Chain findings** (`detection_id` starts with `"chain."`):
1. Extract constituent step finding IDs from `Context["chain_steps"]`
2. Collect all IDs: step findings + the chain finding itself
3. Extract MITRE techniques from chain context
4. Compute time bounds: `chain_window_secs` back from chain timestamp
5. Generate deterministic ID: `inc:{sha256(host:finding)[:8]}:{unix_ts}`
6. Create incident with status `"open"`
7. `IncidentStore.Upsert()` to PostgreSQL
8. `FindingStore.SetIncidentID()` for each constituent finding

**Standalone findings**:
1. Extract `session_id` from `Context["session_id"]`
2. `FindMergeCandidate(orgID, hostID, sessionID, 30min)`:
   - Looks for open/investigating incidents on same host + session within window
   - Session match first, falls back to host-only match
3. If candidate found → `mergeInto()`:
   - Append finding to `finding_ids`
   - Extend `ended_at` to finding timestamp
   - Recalculate severity and confidence
   - Union MITRE techniques
   - Update title if new finding has higher/equal severity
   - Reopen `auto_resolved` incidents if new finding is non-low
   - `IncidentStore.Update()` + `FindingStore.SetIncidentID()`
4. If no candidate → `createSeed()`:
   - Create single-finding incident
   - Low severity → `status = "auto_resolved"`, otherwise `"open"`
   - `IncidentStore.Upsert()` + `FindingStore.SetIncidentID()`

### Severity Calculation

```go
func recalculateSeverity(inc *Incident, newFinding detection.Finding) (string, float64) {
    // Highest-finding-wins
    maxRank = max(SeverityRank[inc.Severity], SeverityRank[newFinding.Severity])

    // Chain amplification: promote by one level if chain present
    if inc.ChainFindingID != "" && maxRank < 4 {
        maxRank++
    }

    // Weighted average confidence
    n = len(inc.FindingIDs)
    confidence = (inc.Confidence*(n-1) + newFinding.Confidence) / n

    return SeverityFromRank(maxRank), confidence
}
```

**SeverityRank**: `critical=4, high=3, medium=2, low=1`

### Incident ID Generation

```go
func generateIncidentID(hostID, seedFindingID string, ts time.Time) string {
    h := sha256.Sum256([]byte(hostID + ":" + seedFindingID))
    return fmt.Sprintf("inc:%x:%d", h[:8], ts.Unix())
}
```

Deterministic: same host + finding + timestamp = same ID. Enables idempotent upserts.

### Merge Candidate Query

```sql
-- Primary: match host + session within 30min window
SELECT ... FROM incidents
WHERE org_id = $1 AND host_id = $2
  AND status IN ('open', 'investigating')
  AND ended_at >= $3  -- cutoff = now - 30min
  AND context_summary->>'session_ids' LIKE '%' || $4 || '%'
ORDER BY ended_at DESC LIMIT 1

-- Fallback: host-only match (no session filter)
SELECT ... FROM incidents
WHERE org_id = $1 AND host_id = $2
  AND status IN ('open', 'investigating')
  AND ended_at >= $3
ORDER BY ended_at DESC LIMIT 1
```

## ContextAssembler

Builds full `IncidentDetail` on-demand for the detail API endpoint. Combines PostgreSQL data (incident + findings) with Neo4j graph data (events, process tree, edges).

```go
type ContextAssembler struct {
    incidentStore *IncidentStore
    findingStore  *storage.FindingStore
    graphStore    *neo4j.GraphStore  // nil = Neo4j unavailable
}
```

### Assembly Steps

1. **Load incident** from `IncidentStore.GetByID()`
2. **Load findings** from `FindingStore.GetByID()` for each `finding_id`
3. **Collect PIDs** from finding contexts (`Context["pid"]`)
4. **Build finding timeline**: Each finding → `TimelineEntry` (type=`"finding"` or `"chain"`)
5. **Query Neo4j** (if available):
   - `QueryAttackChain()` by anchor event ID or first PID, with time window = incident duration + 20min padding
   - Converts graph events to `TimelineEntry` (type=`"event"`)
   - Builds `EventGraph` (nodes + edges, finding nodes highlighted)
6. **Build process tree**: `GetProcessTree()` from first PID, links children to parents, highlights PIDs with findings
7. **Merge + sort** finding timeline + event timeline chronologically

### Graceful Degradation

- **Neo4j unavailable**: `ProcessTree`, `EventGraph` are nil. Timeline contains only findings (no events). All PostgreSQL data (incident metadata, findings) still available.
- **Missing findings**: Logged as warnings, skipped. Partial assembly succeeds.
- **Graph query failures**: Logged as warnings. Assembly continues with available data.

### Event Labels

```go
func eventLabel(evt neo4j.EventNode) string {
    "process_exec" -> "exec /usr/bin/python3 (PID 1234)"
    "process_exit" -> "exit PID 1234"
    "file_open"    -> "open /etc/shadow"
    "net_connect"  -> "connect 10.0.0.1:443"
    "net_dns"      -> "DNS api.openai.com"
    default        -> evt.Type
}
```

## IncidentStore

PostgreSQL CRUD following the established `FindingStore` pattern.

### Methods

| Method | Purpose | Org-scoped |
|--------|---------|-----------|
| `Upsert(ctx, inc)` | INSERT ON CONFLICT UPDATE (idempotent) | Yes (by org_id in data) |
| `GetByID(ctx, orgID, id)` | Single incident | Yes |
| `List(ctx, orgID, opts)` | Filtered list (status, severity, host_id, since, limit, offset) | Yes |
| `CountByStatus(ctx, orgID, since)` | Aggregated counts by status | Yes |
| `UpdateStatus(ctx, orgID, id, status, resolution, resolvedBy)` | Status transition | Yes, returns ErrIncidentNotFound on 0 rows |
| `FindMergeCandidate(ctx, orgID, hostID, sessionID, window)` | Finds open incident on same host+session | Yes |
| `Update(ctx, inc)` | Update mutable fields (severity, findings, ended_at, context) | Yes |
| `GetFindingIDs(ctx, orgID, id)` | Get finding_ids for cascade resolution | Yes |

### Upsert ON CONFLICT behavior

Updates on conflict: `severity`, `confidence`, `title`, `summary`, `mitre_techniques`, `finding_ids`, `ended_at`, `context_summary`, `status`, `updated_at`. Does NOT update: `id`, `org_id`, `host_id`, `chain_finding_id`, `started_at`, `created_at`, `resolution`, `resolved_by`, `resolved_at`.

## Incident Lifecycle

### 5 Status States

```
                        ┌──────────────────────┐
                        │                      │
  ┌──────┐         ┌────▼─────┐         ┌──────┴───┐
  │ open │────────>│investing │────────>│ resolved │
  └──┬───┘         └────┬─────┘         └──────────┘
     │                  │
     │                  │               ┌───────────┐
     └──────────────────┴──────────────>│ dismissed │
                                        └───────────┘

  ┌───────────────┐        ┌──────┐
  │ auto_resolved │<──────>│ open │  (reopen on non-low finding)
  └───────────────┘        └──────┘
```

- **open**: Default for new incidents (severity > low)
- **investigating**: User has started reviewing
- **resolved**: Investigation complete, threat mitigated
- **dismissed**: False positive or irrelevant
- **auto_resolved**: Low-severity single-finding incidents; auto-created, can reopen

### Cascade Resolution

When an incident is resolved or dismissed via `PATCH /api/v1/incidents/{id}`:

1. `IncidentStore.UpdateStatus()` updates the incident
2. `IncidentStore.GetFindingIDs()` retrieves all constituent finding IDs
3. For each finding: `FindingStore.UpdateStatus()`:
   - Incident `resolved` → Finding `allowed`
   - Incident `dismissed` → Finding `dismissed`
4. Errors logged as warnings (partial cascade succeeds)

**One-directional**: Resolving individual findings does NOT auto-resolve the parent incident. Incidents are the primary investigation unit.

## API Endpoints

### Incidents Handler

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| `GET` | `/api/v1/incidents` | `ListIncidents` | Filtered list with counts |
| `GET` | `/api/v1/incidents/{id}` | `GetIncident` | Full detail (calls assembler) |
| `PATCH` | `/api/v1/incidents/{id}` | `UpdateIncidentStatus` | Status transition with cascade |
| `GET` | `/api/v1/incidents/{id}/timeline` | `GetIncidentTimeline` | Timeline only (lighter) |

### List Response

```json
{
    "incidents": [...],
    "count": 5,
    "counts": {
        "total": 12,
        "open": 3,
        "investigating": 2,
        "resolved": 4,
        "dismissed": 1,
        "auto_resolved": 2
    }
}
```

**Default filters**: `since = 7 days ago`, `limit = 1000`

### Detail Response

```json
{
    "incident": {
        "id": "inc:a1b2c3d4e5f6g7h8:1709123456",
        "severity": "critical",
        "title": "Multi-step credential theft + data exfiltration",
        "mitre_techniques": ["T1552", "T1041"],
        "finding_ids": ["f1", "f2", "f3"],
        "chain_finding_id": "f3",
        "started_at": "...",
        "ended_at": "...",
        "status": "open",
        "findings": [
            { "id": "f1", "detection_id": "ai.credential_access", "severity": "high", ... },
            { "id": "f2", "detection_id": "ai.data_exfiltration", "severity": "high", ... },
            { "id": "f3", "detection_id": "chain.credential_exfil", "severity": "critical", ... }
        ],
        "timeline": [
            { "timestamp": "...", "type": "finding", "title": "SSH key read", "severity": "high" },
            { "timestamp": "...", "type": "event", "event_type": "file_open", "title": "open /home/user/.ssh/id_rsa" },
            { "timestamp": "...", "type": "event", "event_type": "net_connect", "title": "connect 10.0.0.1:443" },
            { "timestamp": "...", "type": "finding", "title": "Data exfiltration", "severity": "high" },
            { "timestamp": "...", "type": "chain", "title": "Credential theft chain", "severity": "critical" }
        ],
        "process_tree": {
            "pid": 100, "comm": "bash", "children": [
                { "pid": 200, "comm": "claude-code", "ai_type": "claude-code", "finding_ids": ["f1", "f2"] }
            ]
        },
        "event_graph": {
            "nodes": [...],
            "edges": [...]
        }
    }
}
```

### Status Update Request

```json
{
    "status": "resolved",
    "resolution": "Known safe operation — AI agent reading own config"
}
```

Valid statuses: `open`, `investigating`, `resolved`, `dismissed`

### Dashboard Stats

Added `IncidentSummaryStats` to `DashboardStats`:

```json
{
    "incidents": {
        "total": 12,
        "open": 5,
        "critical_open": 1
    }
}
```

## Pipeline Integration

### Ingestion Flow (IngestCanonicalEvents)

```
For each event:
  1. Validate + Sample + Store to PostgreSQL
  2. AI Attribution
  3. Tier 1: ProcessTreeWriter -> Neo4j
  4. Detection: engine.Evaluate() -> baselines -> exceptions -> cooldown
  5. Store findings -> FindingStore.Insert()
  6. Chain correlation: chainCorrelator.Check() -> chain findings stored
  7. ──> NEW: Incident correlation:
  │       for _, f := range emittedFindings {
  │           incidentCorrelator.Ingest(ctx, orgID, f)
  │       }
  │       for _, cf := range allChainFindings {
  │           incidentCorrelator.Ingest(ctx, orgID, cf)
  │       }
  8. Behavioral baseline learning
  9. Tier 2: eventBuffer.Push() -> Neo4j batch
```

### Wiring (cmd/api/main.go)

```go
incidentStore := incident.NewIncidentStore(db)
incidentCorrelator := incident.NewIncidentCorrelator(incidentStore, findingStore)

// Neo4j for context assembly (optional)
var graphStoreForIncidents *neo4j.GraphStore
if graphPersister != nil {
    incNeo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
    graphStoreForIncidents = neo4j.NewGraphStore(incNeo4jClient)
}
contextAssembler := incident.NewContextAssembler(incidentStore, findingStore, graphStoreForIncidents)

// Pass to ingest handler
NewLiveIngestHandler(..., incidentCorrelator)

// Register API routes
incidentsHandler := api.NewIncidentsHandler(contextAssembler, incidentStore, findingStore)
mux.Handle("/api/v1/incidents", wrapAuthed(...))
mux.Handle("/api/v1/incidents/", wrapAuthed(...))

// Dashboard handler now includes incidentStore
api.NewDashboardHandler(..., incidentStore, db)
```

Both `cmd/api/main.go` and `cmd/telemetry/main.go` wire `incidentCorrelator` into the ingestion pipeline (parity — learned from Phase 3 H1 bug).

## Frontend Integration

### API Client (`correlic-ui/lib/api-client.ts`)

Types: `Incident`, `IncidentDetail`, `TimelineEntry`, `FindingSummary`, `IncidentProcessNode`, `EventGraph`, `EventGraphNode`, `EventGraphEdge`, `IncidentCounts`, `IncidentListResponse`, `IncidentSummaryStats`

Functions: `getIncidents(params)`, `getIncident(id)`, `getIncidentTimeline(id)`, `updateIncidentStatus(id, status, resolution?)`

`Finding` type extended with `incident_id?: string`

`DashboardStats` extended with `incidents: IncidentSummaryStats`

### Pages

| Route | File | Description |
|-------|------|-------------|
| `/incidents` | `app/(dashboard)/incidents/page.tsx` | Incident list with status filters, severity badges, MITRE techniques, chain indicators, confirmation dialogs |
| `/incidents/[id]` | `app/(dashboard)/incidents/[id]/page.tsx` | Incident detail: header, interactive SVG timeline (zoom/pan), findings panel, process tree, event graph summary |

### Navigation

`layout.tsx` navItems: `Incidents` added between `Alerts` and `Baselines` (icon: `ShieldAlert`)

### Cross-links

- **Alerts page**: Each finding in expanded detail view shows "View Incident" link if `incident_id` is set
- **Dashboard page**: Incidents section shows Open Incidents, Critical Open, Total Incidents metrics

### Interactive Timeline (SVG)

Built with pure React + SVG (no D3 dependency):
- **Zoom**: Mouse wheel scales X axis (0.5x to 10x)
- **Pan**: Click + drag translates horizontally
- **3 lanes**: Chain (top), Finding (middle), Event (bottom)
- **Color-coded**: Critical=red, High=orange, Medium=yellow, Events=gray
- **Hover tooltips**: Show entry title on mouseover
- **Connected**: Lines between consecutive entries
- **Glow effect**: Finding/chain nodes have outer glow ring

## Configuration Defaults

| Parameter | Value | Location |
|-----------|-------|----------|
| Merge window | 30 minutes | correlator.go |
| Default list limit | 1000 incidents | incidents_handler.go |
| Max list limit | 5000 | incidents_handler.go |
| Default since | 7 days | incidents_handler.go |
| Attack chain max depth | 15 | assembler.go |
| Attack chain time padding | 20 minutes (10 each side) | assembler.go |
| Low-severity auto-resolve | severity rank <= 1 (low) | correlator.go |
| Chain amplification | +1 severity level, cap at 4 (critical) | correlator.go |
| Incident ID format | `inc:{sha256[:8]}:{unix_ts}` | correlator.go |

## Resilience & Edge Cases

- **Nil-safe correlator**: `IncidentCorrelator.Ingest()` returns `("", nil)` if receiver is nil. Follows established codebase pattern.
- **Neo4j optional**: Assembly succeeds with PostgreSQL data alone. Timeline/ProcessTree/EventGraph are nil. No errors surfaced to user.
- **Partial finding load**: Missing findings logged as warnings, skipped. Assembly continues.
- **Graph query failure**: Logged, assembly continues with available data.
- **Merge candidate miss**: Falls back from session+host to host-only match. If still no candidate, creates new seed.
- **Cascade partial failure**: Individual finding status updates that fail are logged but don't abort the cascade.
- **Org isolation**: Every query (List, GetByID, UpdateStatus, FindMergeCandidate) filters by `org_id`. No cross-tenant data leaks.
- **Deterministic IDs**: Same host + finding + timestamp = same incident ID. Upsert is idempotent.
- **Auto-resolve reopen**: `auto_resolved` incidents reopen to `open` when a non-low finding merges in.
- **PID type handling**: Context `pid` field handled as both `float64` (from JSON unmarshal) and `int` (from Go).
- **context_summary JSON**: Marshal errors fallback to `{}`. Unmarshal errors logged as warnings.
