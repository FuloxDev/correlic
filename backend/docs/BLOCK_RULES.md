# Block Rules & Enforcement

Block rules allow org admins to define patterns that trigger automatic process termination on monitored hosts. Rules are managed via the backend API, synced to agents over HTTPS with ETag-based polling, and enforced in the agent's hot path. Every block action is recorded as a block event for audit and statistics.

## Architecture

```
Dashboard UI (CRUD)
  |
  v
Backend API (/api/v1/block-rules)
  ├── PostgreSQL: block_rules table (source of truth)
  └── BlockRuleStore: in-memory cache, refreshed every 30s
  |
  v
Agent polling endpoint (/api/v1/agent/block-rules)
  ├── Returns only enabled rules for the org
  ├── ETag (SHA256 version hash) for 304 Not Modified
  └── Response: { version, rules[] }
  |
  v
Agent RuleSync (configurable interval, default 30s)
  ├── Polls backend with If-None-Match header
  ├── On change: atomically replaces all rules in Enforcer
  ├── Saves to local cache (~/.correlic/block_rules_cache.json)
  └── On boot: loads from local cache first (offline support)
  |
  v
Agent Enforcer (hot path, <1us target)
  ├── ShouldBlock(signalType, candidate) → bool, *BlockRule
  ├── Kill(pid, killTree) → success, error
  └── Protected PIDs list (agent self, AI roots) — never killed
  |
  v
Block event reported back to backend
  └── POST /api/v1/agent/block-events (batch)
```

## Rule Schema

Each block rule has the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `id` | `SERIAL` | Auto-incrementing primary key |
| `org_id` | `TEXT` | Organization scope (multi-tenant isolation) |
| `signal_type` | `TEXT` | One of: `process_exec`, `net_connect`, `file_open` |
| `pattern` | `TEXT` | Match pattern (interpretation depends on signal_type) |
| `description` | `TEXT` | Human-readable description |
| `enabled` | `BOOLEAN` | Whether the rule is active (default `true`) |
| `kill_tree` | `BOOLEAN` | Kill entire process tree vs single process (default `false`) |
| `source` | `TEXT` | `user` or `system` (system rules cannot be deleted via API) |
| `created_by` | `TEXT` | Actor ID who created the rule |
| `created_at` | `TIMESTAMPTZ` | Creation timestamp |
| `updated_at` | `TIMESTAMPTZ` | Last modification timestamp |

Unique constraint: `(org_id, signal_type, pattern)` -- upserting an existing combination updates description, kill_tree, and created_by.

## Pattern Matching by Signal Type

### `process_exec`
Matches the **executable basename** (case-insensitive). The agent also tries stripping the `.exe` extension for flexibility.

- Pattern: `mimikatz.exe` matches `C:\Tools\mimikatz.exe`, `mimikatz.EXE`, etc.
- Pattern: `mimikatz` also matches `mimikatz.exe` (agent strips `.exe` before second lookup)

### `net_connect`
Matches outbound connections by **IP:port** exactly, or **IP-only** (any port).

- Pattern: `10.0.0.5:4444` matches only that exact IP and port
- Pattern: `10.0.0.5` matches any port on that IP
- Comparison is case-insensitive (relevant for IPv6)

### `file_open`
Matches file paths using **`filepath.Match` glob** syntax.

- Pattern: `/etc/shadow` matches that exact path
- Pattern: `/tmp/*.sh` matches any `.sh` file in `/tmp/`
- Agent-side matching is case-insensitive and normalizes path separators to forward slashes
- Agent also supports directory prefix matching for `/**` suffix patterns

## kill_tree Flag

When `kill_tree` is `false` (default), only the matched process PID is terminated.

When `kill_tree` is `true`, the enforcer calls `KillProcessTree(pid)` which terminates the entire process tree rooted at the matched PID. This is useful for blocking AI agent spawns where killing only the child would allow the parent to respawn it.

The enforcer maintains a **protected PIDs** set that is never killed regardless of kill_tree. This always includes the agent's own PID and can include additional PIDs registered via `AddProtectedPID()` (e.g., AI process roots that should be monitored but not killed).

## Agent Sync

The `RuleSync` component manages rule synchronization between the backend and agent:

1. **Boot**: loads rules from local cache file (`~/.correlic/block_rules_cache.json`) for offline resilience
2. **Initial fetch**: immediately polls the backend for current rules
3. **Polling loop**: fetches rules on a configurable interval (default 30s)
4. **ETag optimization**: sends `If-None-Match` header with the last known version hash; backend returns `304 Not Modified` if unchanged
5. **Atomic update**: on change, calls `Enforcer.UpdateRules()` which atomically replaces all rule maps under a write lock
6. **Cache persistence**: saves fetched rules + version + timestamp to local JSON file

The backend `BlockRuleStore` also maintains its own 30s refresh loop from PostgreSQL into an in-memory cache, so API reads are served from memory.

### Version Hash

Both backend and agent compute a SHA256 hash over all enabled rules (sorted by ID) to detect changes. The hash includes: `id`, `signal_type`, `pattern`, `description` (backend) / `kill_tree` (both), ensuring any rule modification triggers a resync.

## Block Event Logging

Every enforcement action (successful or failed kill) is recorded as a `BlockEvent` and reported back to the backend in batch via `POST /api/v1/agent/block-events`.

### Block Event Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | `TEXT` | ULID (unique, time-sortable) |
| `org_id` | `TEXT` | Organization scope |
| `host_id` | `TEXT` | Host where the block occurred |
| `agent_id` | `TEXT` | Reporting agent ID |
| `rule_id` | `INTEGER` | Foreign key to `block_rules.id` |
| `signal_type` | `TEXT` | Signal type that triggered the rule |
| `pid` | `INTEGER` | Process ID that was killed |
| `exe_path` | `TEXT` | Full executable path of the killed process |
| `cmdline` | `TEXT` | Command line of the killed process |
| `target` | `TEXT` | Destination IP:port (net_connect) or file path (file_open) |
| `ai_type` | `TEXT` | AI process type if applicable |
| `success` | `BOOLEAN` | Whether the kill succeeded |
| `error_msg` | `TEXT` | Error message if kill failed |
| `latency_us` | `INTEGER` | Microseconds from event detection to kill completion |
| `blocked_at` | `TIMESTAMPTZ` | When the block occurred |

### Block Event Stats

The stats endpoint returns aggregated metrics:

```json
{
  "total_blocked": 42,
  "success_count": 40,
  "failed_count": 2,
  "unique_rules": 5,
  "by_rule": {
    "1": 20,
    "3": 15,
    "7": 7
  }
}
```

## API Endpoints

### Dashboard / Admin Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/block-rules` | List all block rules for the org. Optional `?signal_type=` filter |
| `POST` | `/api/v1/block-rules` | Create a block rule. Body: `{ signal_type, pattern, description, kill_tree }` |
| `PUT` | `/api/v1/block-rules/{id}` | Update a block rule. Body: `{ enabled, description, kill_tree }` (partial) |
| `DELETE` | `/api/v1/block-rules/{id}` | Delete a block rule. Rejects deletion of `source=system` rules |
| `GET` | `/api/v1/block-events` | List block events. Params: `?host_id=`, `?since=` (RFC3339), `?limit=` (default 100) |
| `GET` | `/api/v1/block-events/stats` | Aggregated block stats. Param: `?since=` (RFC3339, default 24h) |

### Agent Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/agent/block-rules` | Get enabled rules for the org. Supports `If-None-Match` for 304 |
| `POST` | `/api/v1/agent/block-events` | Report block events in batch. Body: `{ events: [...] }` |

## Key Files

| File | Purpose |
|------|---------|
| `correlic-backend/internal/storage/block_rule_store.go` | `BlockRuleStore`: in-memory cached store with 30s refresh, CRUD, pattern matching, version hash |
| `correlic-backend/internal/storage/block_event_store.go` | `BlockEventStore`: insert (single/batch), list, stats, count-by-rule |
| `correlic-backend/internal/api/block_rules_handler.go` | `BlockRulesHandler`: dashboard CRUD endpoints (list, create, update, delete) |
| `correlic-backend/internal/api/block_events_handler.go` | `BlockEventsHandler`: event list, stats, and agent batch reporting |
| `correlic-backend/internal/api/agent_block_rules.go` | `AgentBlockRulesHandler`: agent polling endpoint with ETag support |
| `correlic-backend/migrations/083_block_rules_and_events.sql` | Database migration creating both tables + indexes |
| `Correlic-agent/internal/enforcer/enforcer.go` | `Enforcer`: hot-path rule matching, process killing, protected PID management |
| `Correlic-agent/internal/enforcer/sync.go` | `RuleSync`: polling loop, ETag-based sync, local cache for offline boot |

## Database Schema

```sql
CREATE TABLE block_rules (
    id          SERIAL PRIMARY KEY,
    org_id      TEXT NOT NULL,
    signal_type TEXT NOT NULL,          -- 'process_exec' | 'net_connect' | 'file_open'
    pattern     TEXT NOT NULL,          -- exe name, IP:port, file path glob
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    kill_tree   BOOLEAN NOT NULL DEFAULT FALSE,
    source      TEXT NOT NULL DEFAULT 'user',  -- 'user' | 'system'
    created_by  TEXT NOT NULL DEFAULT 'user',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, signal_type, pattern)
);

CREATE INDEX idx_block_rules_org ON block_rules (org_id);
CREATE INDEX idx_block_rules_org_enabled ON block_rules (org_id) WHERE enabled = TRUE;

CREATE TABLE block_events (
    id          TEXT PRIMARY KEY,       -- ULID
    org_id      TEXT NOT NULL,
    host_id     TEXT NOT NULL,
    agent_id    TEXT NOT NULL DEFAULT '',
    rule_id     INTEGER NOT NULL REFERENCES block_rules(id) ON DELETE SET NULL,
    signal_type TEXT NOT NULL,
    pid         INTEGER NOT NULL,
    exe_path    TEXT NOT NULL DEFAULT '',
    cmdline     TEXT NOT NULL DEFAULT '',
    target      TEXT NOT NULL DEFAULT '',   -- dst IP:port for net, file path for file
    ai_type     TEXT NOT NULL DEFAULT '',
    success     BOOLEAN NOT NULL,
    error_msg   TEXT NOT NULL DEFAULT '',
    latency_us  INTEGER NOT NULL DEFAULT 0, -- microseconds from event to kill
    blocked_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_block_events_org ON block_events (org_id, blocked_at DESC);
CREATE INDEX idx_block_events_host ON block_events (host_id, blocked_at DESC);
CREATE INDEX idx_block_events_rule ON block_events (rule_id);
```
