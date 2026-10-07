# Query & Timeline Services

Structured query services for exploring canonical events, process trees, and timeline data. Two backends: PostgreSQL for event queries, Neo4j for graph-powered timeline and investigation.

## Architecture

```
API Handlers
  ├── /query/*           → Service (PostgreSQL canonical events)
  ├── /neo4j/*           → TimelineService (Neo4j graph queries)
  ├── /processes/*       → TimelineService (process tree + activity)
  ├── /agents/activity   → TimelineService (human-readable feed)
  ├── /timeline          → Builder (on-demand correlation around anchor)
  └── /process/lifecycles → EventStore (process lifecycle events)
```

## PostgreSQL Query Service

Deterministic structured queries over canonical events. No heuristics.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/query/containers` | Container start events in time range |
| GET | `/query/ports` | Port binding events (net_listen) |
| GET | `/query/connections` | Outbound network connections |
| GET | `/query/inbound` | Inbound accepted connections |
| GET | `/query/processes` | Process execution events |
| GET | `/process/lifecycles` | Process start + exit pairs |

### Common Query Parameters
- `host_id` — filter by host
- `since` / `until` — time range (RFC3339)
- Results capped at `MaxResults` (configurable); `truncated: true` when more exist

## Neo4j Timeline Service

Graph-powered queries for process trees, attack paths, and session-scoped activity. Only available when Neo4j is connected.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/neo4j/timeline` | Event timeline with graph relationships |
| GET | `/neo4j/process-tree` | Process tree (5 ancestors up, 10 descendants down) |
| GET | `/neo4j/attack-path` | BFS attack path from event/PID (max depth 10) |
| GET | `/processes/tree` | Interactive process timeline for UI |
| GET | `/processes/activity` | Process activity stream |
| GET | `/processes/summary` | Process network summary |
| GET | `/agents/activity` | Human-readable action feed (agent activity stream) |

## Neo4j Investigation Service

Deep investigation queries for incident analysis. Only available when Neo4j is connected.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/neo4j/investigation/*` | Investigation sub-queries (session, context, relationships) |

## Correlation Builder

On-demand correlation around a specific anchor event (used by `/timeline` endpoint). Builds temporal context from PostgreSQL canonical events and optionally enriches with Neo4j graph data.

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/timeline` | Build correlated timeline around anchor event |

## Dashboard Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/dashboard/stats` | Aggregated metrics (incidents, findings, trends, agent counts) |
| GET | `/dashboard/trends` | Time-series trend data |

## Key Files

| File | Purpose |
|------|---------|
| `internal/query/service.go` | PostgreSQL query service (containers, ports, connections, inbound, processes) |
| `internal/query/timeline_service.go` | Neo4j-powered timeline queries |
| `internal/query/investigation_service.go` | Neo4j investigation queries |
| `internal/correlation/window.go` | Builder: on-demand correlation around anchor event |
| `internal/api/query_handlers.go` | HTTP handlers for /query/* endpoints |
| `internal/api/timeline.go` | `/timeline` handler (PostgreSQL + optional Neo4j) |
| `internal/api/timeline_neo4j.go` | Neo4j timeline + attack path handlers |
| `internal/api/process_timeline.go` | `/processes/*` interactive handlers |
| `internal/api/process_lifecycle.go` | `/process/lifecycles` handler |
| `internal/api/dashboard.go` | Dashboard stats + trends handlers |

## Conditional Availability

Neo4j-powered endpoints are only registered when Neo4j is connected:
```go
if timelineService != nil {
    mux.Handle("/neo4j/timeline", ...)
    mux.Handle("/processes/tree", ...)
    // ...
}
if investigationService != nil {
    mux.Handle("/neo4j/investigation/", ...)
}
```

Query service endpoints (`/query/*`) are always available as they use PostgreSQL.
