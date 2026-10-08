package maintenance

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"time"
)

// retentionAdvisoryLockKey is the pg_try_advisory_lock key shared by every plane
// (api + telemetry) so only one process runs cleanup at a time against a database.
const retentionAdvisoryLockKey int64 = 0x636f7272656c6963 // "correlic"

// retentionBatchSize bounds each DELETE so long-running deletes never hold locks
// on hot tables for seconds at a time.
const retentionBatchSize = 5000

// RetentionConfig controls how long data is kept before cleanup.
type RetentionConfig struct {
	EventRetentionDays     int
	FindingRetentionDays   int
	IncidentRetentionDays  int
	TelemetryRetentionDays int
	// PruneSessions deletes expired login sessions (RETENTION_SESSIONS, default true).
	PruneSessions   bool
	CleanupInterval time.Duration
}

// LoadRetentionConfig reads retention settings from environment variables,
// falling back to sensible defaults:
//
//	RETENTION_EVENTS_DAYS       (30)
//	RETENTION_FINDINGS_DAYS     (30)
//	RETENTION_INCIDENTS_DAYS    (30)
//	RETENTION_TELEMETRY_DAYS    (30)
//	RETENTION_SESSIONS          (true; "false"/"0" disables expired-session pruning)
//	RETENTION_CLEANUP_INTERVAL  (1h, Go duration)
func LoadRetentionConfig() RetentionConfig {
	cfg := RetentionConfig{
		EventRetentionDays:     30,
		FindingRetentionDays:   30,
		IncidentRetentionDays:  30,
		TelemetryRetentionDays: 30,
		PruneSessions:          true,
		CleanupInterval:        1 * time.Hour,
	}
	days := func(name string, dst *int) {
		if v := os.Getenv(name); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				*dst = n
			} else {
				log.Printf("retention: ignoring invalid %s=%q (want positive integer days)", name, v)
			}
		}
	}
	days("RETENTION_EVENTS_DAYS", &cfg.EventRetentionDays)
	days("RETENTION_FINDINGS_DAYS", &cfg.FindingRetentionDays)
	days("RETENTION_INCIDENTS_DAYS", &cfg.IncidentRetentionDays)
	days("RETENTION_TELEMETRY_DAYS", &cfg.TelemetryRetentionDays)
	if v := os.Getenv("RETENTION_SESSIONS"); v != "" {
		switch v {
		case "0", "false", "FALSE", "no", "off":
			cfg.PruneSessions = false
		default:
			cfg.PruneSessions = true
		}
	}
	if v := os.Getenv("RETENTION_CLEANUP_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.CleanupInterval = d
		}
	}
	return cfg
}

// StartRetentionCleanup runs periodic deletion of old data in the background.
// It respects context cancellation for graceful shutdown. It is safe to start in
// every plane: runs are serialized across processes with a PostgreSQL advisory lock.
func StartRetentionCleanup(ctx context.Context, db *sql.DB, cfg RetentionConfig) {
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()

		// Run once at startup after a short delay.
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
			RunCleanup(ctx, db, cfg)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				RunCleanup(ctx, db, cfg)
			}
		}
	}()
	log.Printf("retention cleanup started: events=%dd, findings=%dd, incidents=%dd, telemetry=%dd, sessions=%v, interval=%s",
		cfg.EventRetentionDays, cfg.FindingRetentionDays, cfg.IncidentRetentionDays,
		cfg.TelemetryRetentionDays, cfg.PruneSessions, cfg.CleanupInterval)
}

// retentionTarget describes one table to prune.
type retentionTarget struct {
	name     string
	tsColumn string
	cutoff   time.Time
	extra    string // additional predicate, e.g. " AND source <> 'user_confirmed'"
}

// RunCleanup performs one cleanup pass. It returns immediately (without deleting
// anything) if another process holds the retention advisory lock.
func RunCleanup(ctx context.Context, db *sql.DB, cfg RetentionConfig) {
	// Hold a dedicated connection: advisory locks are per-session, so the lock and
	// the unlock must travel over the same connection.
	conn, err := db.Conn(ctx)
	if err != nil {
		log.Printf("retention cleanup: acquire connection: %v", err)
		return
	}
	defer conn.Close()

	var locked bool
	if err := conn.QueryRowContext(ctx, `SELECT pg_try_advisory_lock($1)`, retentionAdvisoryLockKey).Scan(&locked); err != nil {
		log.Printf("retention cleanup: advisory lock: %v", err)
		return
	}
	if !locked {
		log.Printf("retention cleanup: skipped (another process holds the retention lock)")
		return
	}
	defer func() {
		// Use a fresh context so the unlock still runs during shutdown.
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.ExecContext(unlockCtx, `SELECT pg_advisory_unlock($1)`, retentionAdvisoryLockKey); err != nil {
			log.Printf("retention cleanup: advisory unlock: %v", err)
		}
	}()

	now := time.Now()
	targets := []retentionTarget{
		{"telemetry_events", "received_at", now.AddDate(0, 0, -cfg.TelemetryRetentionDays), ""},
		{"events", "ts", now.AddDate(0, 0, -cfg.EventRetentionDays), ""},
		{"findings", "created_at", now.AddDate(0, 0, -cfg.FindingRetentionDays), ""},
		{"incidents", "created_at", now.AddDate(0, 0, -cfg.IncidentRetentionDays), ""},
		// Auto-observed baselines age out; ones a user confirmed are permanent.
		{"behavioral_baselines", "last_seen", now.AddDate(0, 0, -cfg.FindingRetentionDays), " AND source <> 'user_confirmed'"},
	}
	if cfg.PruneSessions {
		targets = append(targets, retentionTarget{"sessions", "expires_at", now, ""})
	}

	for _, t := range targets {
		if ctx.Err() != nil {
			return
		}
		deleted, err := deleteInBatches(ctx, conn, t)
		if err != nil {
			log.Printf("retention cleanup %s: %v", t.name, err)
			continue
		}
		if deleted > 0 {
			log.Printf("retention cleanup %s: deleted %d rows with %s < %s", t.name, deleted, t.tsColumn, t.cutoff.Format(time.RFC3339))
		}
	}
}

// deleteInBatches deletes matching rows retentionBatchSize at a time using ctid
// subselects, looping until a batch comes back short.
func deleteInBatches(ctx context.Context, conn *sql.Conn, t retentionTarget) (int64, error) {
	query := "DELETE FROM " + t.name + " WHERE ctid IN (" +
		"SELECT ctid FROM " + t.name + " WHERE " + t.tsColumn + " < $1" + t.extra +
		" LIMIT " + strconv.Itoa(retentionBatchSize) + ")"

	var total int64
	for {
		if ctx.Err() != nil {
			return total, ctx.Err()
		}
		res, err := conn.ExecContext(ctx, query, t.cutoff)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < retentionBatchSize {
			return total, nil
		}
	}
}
