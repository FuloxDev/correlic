package maintenance

import (
	"context"
	"database/sql"
	"log"
	"os"
	"strconv"
	"time"
)

// RetentionConfig controls how long data is kept before cleanup.
type RetentionConfig struct {
	EventRetentionDays  int
	FindingRetentionDays int
	IncidentRetentionDays int
	CleanupInterval     time.Duration
}

// LoadRetentionConfig reads retention settings from environment variables,
// falling back to sensible defaults.
func LoadRetentionConfig() RetentionConfig {
	cfg := RetentionConfig{
		EventRetentionDays:   30,
		FindingRetentionDays: 90,
		IncidentRetentionDays: 365,
		CleanupInterval:      1 * time.Hour,
	}
	if v := os.Getenv("RETENTION_EVENTS_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.EventRetentionDays = n
		}
	}
	if v := os.Getenv("RETENTION_FINDINGS_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.FindingRetentionDays = n
		}
	}
	if v := os.Getenv("RETENTION_INCIDENTS_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.IncidentRetentionDays = n
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
// It respects context cancellation for graceful shutdown.
func StartRetentionCleanup(ctx context.Context, db *sql.DB, cfg RetentionConfig) {
	go func() {
		ticker := time.NewTicker(cfg.CleanupInterval)
		defer ticker.Stop()

		// Run once at startup after a short delay.
		select {
		case <-ctx.Done():
			return
		case <-time.After(30 * time.Second):
			runCleanup(ctx, db, cfg)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCleanup(ctx, db, cfg)
			}
		}
	}()
	log.Printf("retention cleanup started: events=%dd, findings=%dd, incidents=%dd, interval=%s",
		cfg.EventRetentionDays, cfg.FindingRetentionDays, cfg.IncidentRetentionDays, cfg.CleanupInterval)
}

func runCleanup(ctx context.Context, db *sql.DB, cfg RetentionConfig) {
	tables := []struct {
		name      string
		tsColumn  string
		retention int
	}{
		{"telemetry_events", "received_at", 1}, // 1-day retention — largest table, readers only need recent data
		{"events", "ts", cfg.EventRetentionDays},
		{"findings", "created_at", cfg.FindingRetentionDays},
		{"incidents", "created_at", cfg.IncidentRetentionDays},
		{"behavioral_baselines", "last_seen", cfg.FindingRetentionDays},
	}

	for _, t := range tables {
		cutoff := time.Now().AddDate(0, 0, -t.retention)
		res, err := db.ExecContext(ctx,
			"DELETE FROM "+t.name+" WHERE "+t.tsColumn+" < $1", cutoff)
		if err != nil {
			log.Printf("retention cleanup %s: %v", t.name, err)
			continue
		}
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("retention cleanup %s: deleted %d rows older than %s", t.name, n, cutoff.Format(time.DateOnly))
		}
	}
}
