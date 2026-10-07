# Behavioural Engine (Phase 3)

The behavioural engine passively learns what "normal" looks like for AI agents and automatically suppresses detection findings that match established patterns. It combines detection-gated auto-observation, a never-baseline safety list, in-memory cached matching, user-confirmed feedback loops, and safe domain allowlisting. All operations are org-scoped for multi-tenant isolation.

## Architecture

```
Event ingested → Detection Engine evaluates
  |
  v
Findings produced?
  |
  ├── YES → Findings go through suppression pipeline:
  │         1. BaselineCollector.MatchesBaseline(orgID, finding)
  │            ├── Match found → suppress (don't store)
  │            └── No match → continue to exception/cooldown/store
  │         2. When user clicks "Allow Always" on finding:
  │            └── FindingsHandler.ResolveFinding(status="allowed")
  │                └── BaselineCollector.LearnFromFinding()
  │                    └── Upsert with source='user_confirmed'
  │
  └── NO → Candidate for baseline learning:
            1. ShouldBaseline(evt, findings=[])
               ├── IsNeverBaselineEvent(evt)?
               │   ├── YES → skip (never auto-baseline)
               │   └── NO → proceed
               └── BaselineCollector.Observe(orgID, evt)
                   └── Extract pattern → upsert to PostgreSQL
```

## Key Files

| File | Purpose |
|------|---------|
| `internal/detection/baseline.go` | `BaselineCollector`: core engine — observe, match, learn, delete, upsert, cache reload |
| `internal/detection/never_baseline.go` | `IsNeverBaselineEvent()`: files, binaries, ports, domains that must never be auto-baselined |
| `internal/storage/finding_store.go` | Finding status updates that trigger baseline learning ("allowed" → LearnFromFinding) |
| `internal/api/findings_handler.go` | `ResolveFinding()`: user feedback loop — "Allow Always" triggers baseline learning |
| `internal/api/baselines_handler.go` | `BaselinesHandler`: list baselines, delete baselines, list safe domains |
| `migrations/053_baselines_org_id.sql` | Added org_id to behavioral_baselines + new unique constraint |
| `migrations/054_baselines_org_id_not_null.sql` | org_id NOT NULL DEFAULT '', backfill NULLs |

## Data Model

### BaselineEntry (in-memory cache)

```go
type baselineEntry struct {
    ID         int
    OrgID      string
    HostID     string
    AIType     string
    SignalType string    // "file_pattern", "binary", "network_dest", "dns_domain"
    Pattern    string    // "~/.ssh/**", "curl", "10.0.0.0/24:443", "api.openai.com"
    Source     string    // "observed" or "user_confirmed"
    HitCount   int
    LastSeen   time.Time
}
```

### Cache Structure

```go
type BaselineCollector struct {
    db   *sql.DB
    mu   sync.RWMutex
    byOrg map[string]map[string]baselineEntry  // orgID → cacheKey → entry
    done chan struct{}
}
```

Cache key: `signalType + "\x00" + pattern + "\x00" + hostID + "\x00" + aiType` — O(1) lookup.

## Database Schema

```sql
CREATE TABLE behavioral_baselines (
    id SERIAL PRIMARY KEY,
    org_id TEXT NOT NULL DEFAULT '',
    host_id TEXT NOT NULL,
    ai_type TEXT NOT NULL DEFAULT '',
    signal_type TEXT NOT NULL,     -- "file_pattern", "binary", "network_dest", "dns_domain"
    pattern TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'observed',  -- "observed" | "user_confirmed"
    hit_count INTEGER DEFAULT 1,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    UNIQUE (org_id, host_id, ai_type, signal_type, pattern)
);
```

The unique constraint enables `ON CONFLICT` upsert behavior.

## BaselineCollector Methods

| Method | Purpose |
|--------|---------|
| `NewBaselineCollector(db)` | Create collector, initial load, start 30s background refresh |
| `Stop()` | Signal background goroutine to exit |
| `Observe(orgID, evt)` | Extract pattern from clean event → upsert with source='observed' |
| `MatchesBaseline(orgID, finding)` | O(1) in-memory check against cached baselines |
| `LearnFromFinding(orgID, hostID, findingContext)` | Upsert with source='user_confirmed' |
| `DeleteBaseline(ctx, orgID, id)` | Remove baseline by ID (org-scoped) → reload cache |

## Pattern Extraction (Observe)

When an event triggers zero detection findings AND is not on the never-baseline list, patterns are extracted:

| Event Type | Signal Type | Pattern | Example |
|------------|-------------|---------|---------|
| `file_open` / `file_write` | `file_pattern` | `filepath.Dir(path) + "/**"` | `/home/user/.aws/**` |
| `process_exec` | `binary` | `filepath.Base(exePath)` or `comm` | `curl` |
| `net_connect` | `network_dest` | `bgp_prefix:port` or `cidr/24:port` | `104.18.0.0/24:443` |
| `net_dns` | `dns_domain` | domain | `api.openai.com` |

Network destinations use BGP prefix from Cymru DNS enrichment when available, falling back to /24 CIDR.

## Baseline Matching (MatchesBaseline)

When a finding is produced, checked before storage:

1. Extract `signal_type` and `pattern` from `finding.Context`
2. Extract `ai_type` from `finding.Context`
3. Build cache key: `signalType\x00pattern\x00hostID\x00aiType`
4. Look up in `bc.byOrg[orgID]` (O(1) map lookup)
5. TTL check:
   - `source == "user_confirmed"` → never expires
   - `source == "observed"` → expires after 30 days (`observedBaselineTTL`)
6. If match → return `(true, "signalType:pattern")`

## Never-Baseline List

Events matching inherently sensitive resources are excluded from auto-observation even when they trigger zero findings. Tier 1 only.

### Files (isNeverBaselineFile)

Three typed lists (fixed from broken `filepath.Match` fallback):

1. **Suffixes**: `.pem`, `_rsa`, `_ecdsa`, `_ed25519`, `.key`, `.p12`, `.pfx`
2. **Directory containment** (strings.Contains): `/.ssh/`, `/.azure/`, `/.config/gcloud/`, `/.kube/cache/`, `/etc/sudoers.d/`
3. **Exact basenames**: `shadow`, `passwd`, `sudoers`, `.gitconfig`

### Binaries (isNeverBaselineBinary)

```
nc, ncat, socat, nmap, base64, xxd,
useradd, usermod, passwd, visudo, chpasswd,
chmod, chown, setcap
```

### Network Ports (isNeverBaselineNetConnect)

C2 / exploit tool ports:
```
4444 (Metasploit), 5555 (RAT), 1337, 6666/6667 (IRC C2),
8888 (malware C2), 9001/9050/9150 (Tor), 31337 (Back Orifice)
```

### DNS Domains (isNeverBaselineDNS)

Suffix matching:
```
.onion, .i2p, pastebin.com, paste.ee,
ghostbin.com, transfer.sh, file.io
```

## User Feedback Loop

When a user marks a finding as "allowed" via PATCH `/api/v1/findings/{id}`:

1. `FindingsHandler.ResolveFinding()` updates finding status → "allowed"
2. If status == "allowed" AND `baselineCollector != nil`:
   - Load finding via `FindingStore.GetByID(orgID, findingID)`
   - Call `BaselineCollector.LearnFromFinding(orgID, hostID, finding.Context)`
   - Extracts `signal_type` and `pattern` from finding context
   - Upserts to `behavioral_baselines` with `source='user_confirmed'`
3. Future identical findings are automatically suppressed

### Source Preservation

The upsert SQL uses a CASE expression to prevent downgrading:
```sql
ON CONFLICT (org_id, host_id, ai_type, signal_type, pattern)
DO UPDATE SET hit_count = behavioral_baselines.hit_count + 1,
              last_seen = $7,
              source = CASE WHEN behavioral_baselines.source = 'user_confirmed'
                       THEN 'user_confirmed' ELSE EXCLUDED.source END
```

A user-confirmed baseline is never downgraded to 'observed' by passive observation.

## Safe Domain Allowlist

Pre-populated via migration 051 with 12 AI/cloud provider domains:

```
openai.com, anthropic.com, googleapis.com, azure.com,
huggingface.co, cohere.com, together.ai, replicate.com,
mistral.ai, groq.com, github.com, raw.githubusercontent.com
```

Used by `ai.unauthorized_exec` (curl/wget URL checks) and `ai.unexpected_network` (network destination checks) to suppress findings for known-safe destinations.

API: GET `/api/v1/baselines/safe-domains` — returns all safe domains.

## API Endpoints

### Baselines

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| GET | `/api/v1/baselines` | ListBaselines | Filtered list (host_id, signal_type, ai_type, limit) |
| DELETE | `/api/v1/baselines/{id}` | DeleteBaseline | Remove baseline (org-scoped) |
| GET | `/api/v1/baselines/safe-domains` | ListSafeDomains | All safe domain entries |

### Finding Resolution (triggers learning)

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| PATCH | `/api/v1/findings/{id}` | ResolveFinding | Status="allowed" → LearnFromFinding |

## Rule Signal Types Required for Baseline Matching

Each detection rule must set `signal_type` and `pattern` in `finding.Context` for baseline matching to work:

| Rule | signal_type | pattern |
|------|-------------|---------|
| `ai.credential_access` | `file_pattern` | `{dir}/**` |
| `ai.unauthorized_exec` | `binary` | `{exe_basename}` |
| `ai.excessive_writes` | `file_write_burst` | `pid:NNN:reason` |
| `ai.data_exfiltration` | `network_dest` | `bgp:port` |
| `ai.unexpected_network` | `network_dest` | `bgp:port` |
| `ai.suspicious_dns` | `dns_domain` | `domain` |

Without these context fields, `MatchesBaseline()` returns `(false, "")` and the finding is not suppressible.

## Pipeline Position

In `internal/ingest/live_ingest.go`, baseline operations occur at two points:

**Point 1 — Suppression (after detection, before storage):**
```go
for _, f := range findings {
    if baselineCollector != nil {
        if matched, pattern := baselineCollector.MatchesBaseline(orgID, f); matched {
            continue // suppress
        }
    }
    // ... exception check, cooldown, store
}
```

**Point 2 — Observation (after all finding processing):**
```go
if baselineCollector != nil && detection.ShouldBaseline(evt, findings) {
    baselineCollector.Observe(orgID, evt)
}
```

## Wiring

Both `cmd/api/main.go` and `cmd/telemetry/main.go`:
```go
baselineCollector := detection.NewBaselineCollector(db)
defer baselineCollector.Stop()

// Pass to findings handler for user feedback loop
findingsHandler := api.NewFindingsHandler(findingStore, baselineCollector)

// Pass to baselines handler for API
baselinesHandler := api.NewBaselinesHandler(db, baselineCollector)

// Pass to IngestCanonicalEvents for observe + suppress
```

## Database Migrations

| Migration | Purpose |
|-----------|---------|
| 051 | Default safe domains (12 entries) |
| 053 | `behavioral_baselines.org_id` + new unique constraint |
| 054 | `org_id NOT NULL DEFAULT ''`, backfill NULLs, remove all `OR org_id IS NULL` from queries |

## Configuration

| Parameter | Value | Notes |
|-----------|-------|-------|
| Cache refresh interval | 30 seconds | Background goroutine |
| Observed baseline TTL | 30 days | After last_seen; user_confirmed never expires |
| Cache key separator | `\x00` (null byte) | Avoids collisions |

## Resilience & Edge Cases

- **Nil-safe receiver**: All public methods (`MatchesBaseline`, `Observe`, `LearnFromFinding`, `DeleteBaseline`) check `if bc == nil { return }`. Prevents panics when collector is not initialized.
- **Background goroutine lifecycle**: `done chan struct{}` + `Stop()` method + select-based loop. `defer bc.Stop()` in both main.go files.
- **Cross-tenant isolation**: Migration 054 enforces `org_id NOT NULL DEFAULT ''`. Unique constraint `(org_id, host_id, ai_type, signal_type, pattern)` ensures tenant separation. All queries filter by `org_id = $X` (no NULL fallback after migration 054).
- **Source preservation**: ON CONFLICT never downgrades `user_confirmed` to `observed`.
- **isNeverBaselineFile rewritten**: Replaced broken `filepath.Match` fallback with 3 typed lists (suffixes, dir containment, exact basenames). `*/.azure/*` no longer matches all files.
- **ai.excessive_writes baseline fix**: Now sets `signal_type="file_write_burst"` + `pattern="pid:NNN:reason"` in Context. "Allow Always" and baseline suppression work for this rule.
- **Cache reload on mutation**: `DeleteBaseline()` and `upsert()` both call `bc.reload()` after DB write to keep cache fresh.
- **Graceful scan errors**: If a row fails to scan during `reload()`, it's skipped (continue) rather than failing the entire reload.
- **FindingsHandler GetByID org-scoped**: Prevents cross-tenant data leak via "Allow Always" flow (fixed in Phase 3 C1 audit).

## Frontend Integration

### Baselines Page (`/alerts` → Baselines tab)

- Source badges: "Confirmed" (green) vs "Learned" (blue)
- Remove button with confirmation dialog (`ConfirmDialog` component)
- "Allow Always" button on finding cards → triggers learning

### UI Components

- `ConfirmDialog` component: `correlic-ui/components/ui/confirm-dialog.tsx` — Radix UI Dialog
- Destructive actions (baseline delete, bulk allow) require confirmation
- `Promise.allSettled` for bulk operations — partial failures logged, only succeeded IDs update UI state
