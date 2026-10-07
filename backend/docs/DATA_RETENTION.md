# Data Retention & Cleanup

Background worker that periodically deletes old data from PostgreSQL to manage storage costs and query performance.

## Architecture

```
StartRetentionCleanup(ctx, db, cfg)
  |
  v
30s startup delay → first cleanup run
  |
  v
Ticker loop (default 1h interval)
  |
  v
runCleanup(): DELETE FROM {table} WHERE {ts_column} < cutoff
  ├── telemetry_events (received_at < 1 day)    — largest table, aggressive retention
  ├── events (ts < 30 days)                      — canonical events
  ├── findings (created_at < 90 days)            — detection findings
  ├── incidents (created_at < 365 days)          — incidents
  └── behavioral_baselines (last_seen < 90 days) — stale baselines
```

## Configuration

| Env Variable | Default | Description |
|-------------|---------|-------------|
| `RETENTION_EVENTS_DAYS` | 30 | Canonical events retention (days) |
| `RETENTION_FINDINGS_DAYS` | 90 | Findings retention (days) |
| `RETENTION_INCIDENTS_DAYS` | 365 | Incidents retention (days) |
| `RETENTION_CLEANUP_INTERVAL` | `1h` | Cleanup sweep interval (Go duration) |

**Note:** `telemetry_events` is hardcoded to 1-day retention regardless of env vars — this is the raw ingestion table and is the largest by far. Readers only need recent data.

Behavioral baselines use the same retention as findings (`RETENTION_FINDINGS_DAYS`).

## Key Files

| File | Purpose |
|------|---------|
| `internal/maintenance/retention.go` | `RetentionConfig`, `LoadRetentionConfig()`, `StartRetentionCleanup()`, `runCleanup()` |

## Wiring

Started in `cmd/api/main.go`:
```go
retentionCfg := maintenance.LoadRetentionConfig()
maintenance.StartRetentionCleanup(ctx, db, retentionCfg)
```

Respects context cancellation for graceful shutdown.

## Behavior

- First cleanup runs after a 30-second startup delay (avoids hitting the DB during initialization)
- Subsequent runs on the configured interval (default 1 hour)
- Each table cleaned independently — one failure doesn't block others
- Logs deleted row counts (only when > 0)
- Logs errors but continues to next table
