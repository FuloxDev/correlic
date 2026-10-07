package intelligence

import (
	"context"
	"database/sql"
	"log"
	"time"
)

// Worker runs background jobs for the AI intelligence system:
// - Every 1 min: create a context window snapshot (Layer 2)
// - Every 1 hr:  rebuild system profile (Layer 1) + rollup 1m→1h
// - Every 24 hr: rollup 1h→24h + cleanup old windows
// - Every 7 days: rollup 24h→weekly
type Worker struct {
	db             *sql.DB
	store          *Store
	profileBuilder *ProfileBuilder
	contextBuilder *ContextBuilder
	rollup         *Rollup
	done           chan struct{}
}

// NewWorker creates the intelligence background worker.
func NewWorker(db *sql.DB) *Worker {
	store := NewStore(db)
	return &Worker{
		db:             db,
		store:          store,
		profileBuilder: NewProfileBuilder(db, store),
		contextBuilder: NewContextBuilder(db, store),
		rollup:         NewRollup(store),
		done:           make(chan struct{}),
	}
}

// Start runs the intelligence worker loop. Call in a goroutine.
func (w *Worker) Start() {
	log.Println("AI intelligence worker started (1-min snapshots, hourly profiles, hierarchical rollups)")

	minuteTicker := time.NewTicker(1 * time.Minute)
	hourTicker := time.NewTicker(1 * time.Hour)
	dayTicker := time.NewTicker(24 * time.Hour)

	defer minuteTicker.Stop()
	defer hourTicker.Stop()
	defer dayTicker.Stop()

	// Initial snapshot on startup (after 10s delay to let events flow in)
	select {
	case <-w.done:
		return
	case <-time.After(10 * time.Second):
	}
	w.buildMinuteSnapshot()

	for {
		select {
		case <-w.done:
			return

		case <-minuteTicker.C:
			w.buildMinuteSnapshot()

		case <-hourTicker.C:
			w.hourlyJobs()

		case <-dayTicker.C:
			w.dailyJobs()
		}
	}
}

// Stop signals the worker to exit.
func (w *Worker) Stop() {
	select {
	case <-w.done:
	default:
		close(w.done)
	}
}

// Store returns the intelligence store for use by other components.
func (w *Worker) Store() *Store {
	return w.store
}

func (w *Worker) buildMinuteSnapshot() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Snapshot the PREVIOUS minute (just completed)
	now := time.Now().Truncate(time.Minute)
	windowStart := now.Add(-1 * time.Minute)

	// Get all active hosts from recent events
	hosts := w.getActiveHosts(ctx, windowStart)
	for _, h := range hosts {
		if err := w.contextBuilder.BuildMinuteSnapshot(ctx, h.orgID, h.hostID, windowStart); err != nil {
			log.Printf("WARN: intelligence 1-min snapshot failed for %s: %v", h.hostID, err)
		}
	}
}

func (w *Worker) hourlyJobs() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	now := time.Now().Truncate(time.Hour)
	hourStart := now.Add(-1 * time.Hour)

	hosts := w.getActiveHosts(ctx, hourStart)
	for _, h := range hosts {
		// Rollup: 1-min → 1-hr
		if err := w.rollup.RollupMinuteToHourly(ctx, h.orgID, h.hostID, hourStart); err != nil {
			log.Printf("WARN: intelligence 1h rollup failed for %s: %v", h.hostID, err)
		}

		// Rebuild system profile
		if err := w.profileBuilder.Build(ctx, h.orgID, h.hostID); err != nil {
			log.Printf("WARN: intelligence profile build failed for %s: %v", h.hostID, err)
		}
	}

	// Cleanup stale 1-min windows
	w.rollup.Cleanup(ctx)

	log.Printf("AI intelligence hourly jobs complete (hosts=%d)", len(hosts))
}

func (w *Worker) dailyJobs() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	now := time.Now().Truncate(24 * time.Hour)
	dayStart := now.Add(-24 * time.Hour)

	hosts := w.getActiveHosts(ctx, dayStart)
	for _, h := range hosts {
		// Rollup: 1-hr → 24-hr
		if err := w.rollup.RollupHourlyToDaily(ctx, h.orgID, h.hostID, dayStart); err != nil {
			log.Printf("WARN: intelligence 24h rollup failed for %s: %v", h.hostID, err)
		}

		// Check if it's Sunday (weekly rollup)
		if now.Weekday() == time.Sunday {
			weekStart := dayStart.Add(-6 * 24 * time.Hour)
			if err := w.rollup.RollupDailyToWeekly(ctx, h.orgID, h.hostID, weekStart); err != nil {
				log.Printf("WARN: intelligence weekly rollup failed for %s: %v", h.hostID, err)
			}
		}
	}

	log.Printf("AI intelligence daily jobs complete (hosts=%d)", len(hosts))
}

type hostEntry struct {
	orgID  string
	hostID string
}

func (w *Worker) getActiveHosts(ctx context.Context, since time.Time) []hostEntry {
	// Step 1: get unique host_ids from canonical events table
	rows, err := w.db.QueryContext(ctx, `
		SELECT DISTINCT host_id
		FROM events
		WHERE ts >= $1 AND host_id IS NOT NULL AND host_id != ''
		LIMIT 100
	`, since)
	if err != nil {
		log.Printf("WARN: intelligence getActiveHosts: %v", err)
		return nil
	}
	defer rows.Close()

	var hostIDs []string
	for rows.Next() {
		var hid string
		if err := rows.Scan(&hid); err == nil {
			hostIDs = append(hostIDs, hid)
		}
	}
	if len(hostIDs) == 0 {
		return nil
	}

	// Step 2: map each host to its org. The live-ingest path writes
	// telemetry_events with agent_id = host_id, so that table carries the
	// per-host org. Fall back to the first org for hosts without a match.
	orgByHost := make(map[string]string, len(hostIDs))
	if orgRows, err := w.db.QueryContext(ctx, `
		SELECT DISTINCT agent_id, org_id::text
		FROM telemetry_events
		WHERE received_at >= $1 AND agent_id = ANY($2)
	`, since, hostIDs); err == nil {
		for orgRows.Next() {
			var hid, oid string
			if err := orgRows.Scan(&hid, &oid); err == nil {
				orgByHost[hid] = oid
			}
		}
		orgRows.Close()
	}
	var fallbackOrg string
	_ = w.db.QueryRowContext(ctx, `SELECT id::text FROM organizations ORDER BY created_at ASC LIMIT 1`).Scan(&fallbackOrg)

	var hosts []hostEntry
	for _, hid := range hostIDs {
		oid := orgByHost[hid]
		if oid == "" {
			oid = fallbackOrg
		}
		if oid == "" {
			continue
		}
		hosts = append(hosts, hostEntry{orgID: oid, hostID: hid})
	}
	return hosts
}
