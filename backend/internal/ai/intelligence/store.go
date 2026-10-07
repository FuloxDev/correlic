package intelligence

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type Store struct {
	db *sql.DB
}

func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// --- Layer 1: System Profile ---

func (s *Store) UpsertProfile(ctx context.Context, orgID, hostID string, profile SystemProfile) error {
	data, err := json.Marshal(profile)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ai_system_profiles (org_id, host_id, profile, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (org_id, host_id)
		DO UPDATE SET profile = $3, updated_at = NOW()
	`, orgID, hostID, data)
	return err
}

func (s *Store) GetProfile(ctx context.Context, orgID, hostID string) (*SystemProfile, error) {
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT profile FROM ai_system_profiles WHERE org_id = $1 AND host_id = $2`,
		orgID, hostID).Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p SystemProfile
	return &p, json.Unmarshal(data, &p)
}

// --- Layer 2: Context Windows ---

func (s *Store) InsertContextWindow(ctx context.Context, orgID, hostID, granularity string, windowStart, windowEnd time.Time, summary ContextSummary) error {
	data, err := json.Marshal(summary)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ai_context_windows (org_id, host_id, granularity, window_start, window_end, summary)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, orgID, hostID, granularity, windowStart, windowEnd, data)
	return err
}

func (s *Store) GetContextWindows(ctx context.Context, orgID, hostID, granularity string, since time.Time, limit int) ([]ContextWindow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, window_start, window_end, summary, created_at
		FROM ai_context_windows
		WHERE org_id = $1 AND host_id = $2 AND granularity = $3 AND window_start >= $4
		ORDER BY window_start DESC
		LIMIT $5
	`, orgID, hostID, granularity, since, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var windows []ContextWindow
	for rows.Next() {
		var w ContextWindow
		var data []byte
		if err := rows.Scan(&w.ID, &w.WindowStart, &w.WindowEnd, &data, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Granularity = granularity
		json.Unmarshal(data, &w.Summary)
		windows = append(windows, w)
	}
	return windows, rows.Err()
}

// GetLatestWindow returns the most recent context window for a given granularity.
func (s *Store) GetLatestWindow(ctx context.Context, orgID, hostID, granularity string) (*ContextWindow, error) {
	var w ContextWindow
	var data []byte
	err := s.db.QueryRowContext(ctx, `
		SELECT id, window_start, window_end, summary, created_at
		FROM ai_context_windows
		WHERE org_id = $1 AND host_id = $2 AND granularity = $3
		ORDER BY window_start DESC LIMIT 1
	`, orgID, hostID, granularity).Scan(&w.ID, &w.WindowStart, &w.WindowEnd, &data, &w.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	w.Granularity = granularity
	json.Unmarshal(data, &w.Summary)
	return &w, nil
}

// CleanupWindows deletes context windows older than the retention period for a granularity.
func (s *Store) CleanupWindows(ctx context.Context, granularity string, olderThan time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `
		DELETE FROM ai_context_windows WHERE granularity = $1 AND created_at < $2
	`, granularity, olderThan)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// GetWindowsForRollup returns all context windows in a time range for a given granularity.
func (s *Store) GetWindowsForRollup(ctx context.Context, orgID, hostID, granularity string, from, to time.Time) ([]ContextWindow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, window_start, window_end, summary, created_at
		FROM ai_context_windows
		WHERE org_id = $1 AND host_id = $2 AND granularity = $3
		  AND window_start >= $4 AND window_start < $5
		ORDER BY window_start ASC
	`, orgID, hostID, granularity, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var windows []ContextWindow
	for rows.Next() {
		var w ContextWindow
		var data []byte
		if err := rows.Scan(&w.ID, &w.WindowStart, &w.WindowEnd, &data, &w.CreatedAt); err != nil {
			return nil, err
		}
		w.Granularity = granularity
		json.Unmarshal(data, &w.Summary)
		windows = append(windows, w)
	}
	return windows, rows.Err()
}

// --- Layer 3: Learned Patterns ---

func (s *Store) UpsertPattern(ctx context.Context, orgID string, pattern LearnedPattern) error {
	data, err := json.Marshal(pattern.Evidence)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO ai_learned_patterns (org_id, pattern_key, verdict, confidence, evidence, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (org_id, pattern_key)
		DO UPDATE SET verdict = $3, confidence = $4, evidence = $5, last_seen = $7
	`, orgID, pattern.PatternKey, pattern.Verdict, pattern.Confidence, data, pattern.FirstSeen, pattern.LastSeen)
	return err
}

func (s *Store) GetPattern(ctx context.Context, orgID, patternKey string) (*LearnedPattern, error) {
	var p LearnedPattern
	var data []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT id, pattern_key, verdict, confidence, evidence, first_seen, last_seen
		 FROM ai_learned_patterns WHERE org_id = $1 AND pattern_key = $2`,
		orgID, patternKey).Scan(&p.ID, &p.PatternKey, &p.Verdict, &p.Confidence, &data, &p.FirstSeen, &p.LastSeen)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(data, &p.Evidence)
	return &p, nil
}

func (s *Store) ListPatterns(ctx context.Context, orgID string) ([]LearnedPattern, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, pattern_key, verdict, confidence, evidence, first_seen, last_seen
		 FROM ai_learned_patterns WHERE org_id = $1 ORDER BY confidence DESC, last_seen DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var patterns []LearnedPattern
	for rows.Next() {
		var p LearnedPattern
		var data []byte
		if err := rows.Scan(&p.ID, &p.PatternKey, &p.Verdict, &p.Confidence, &data, &p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		json.Unmarshal(data, &p.Evidence)
		patterns = append(patterns, p)
	}
	return patterns, rows.Err()
}

// GetFalsePositiveRates returns the false positive rate per detection rule.
func (s *Store) GetFalsePositiveRates(ctx context.Context, orgID string, since time.Time) (map[string]float64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT detection_id,
		       COUNT(*) FILTER (WHERE status IN ('dismissed', 'allowed', 'auto_resolved')) as fp,
		       COUNT(*) as total
		FROM findings
		WHERE org_id = $1 AND created_at > $2
		GROUP BY detection_id
		HAVING COUNT(*) >= 5
	`, orgID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	rates := make(map[string]float64)
	for rows.Next() {
		var detID string
		var fp, total int64
		if err := rows.Scan(&detID, &fp, &total); err != nil {
			return nil, err
		}
		if total > 0 {
			rates[detID] = float64(fp) / float64(total)
		}
	}
	return rates, rows.Err()
}

// --- On-Demand Micro-Context ---

// GetOnDemandContext builds a fresh context summary from raw events for a host
// over the given time window. Unlike context windows (built by background worker),
// this runs on-demand when the AI needs immediate context — e.g., when a user
// clicks "Analyze" within seconds of an incident being created.
//
// This ensures the AI always has temporal context regardless of whether the
// 1-min ticker has run yet.
func (s *Store) GetOnDemandContext(ctx context.Context, hostID string, since time.Time) (*ContextSummary, error) {
	summary := &ContextSummary{}

	rows, err := s.db.QueryContext(ctx, `
		SELECT type, COUNT(*) FROM events
		WHERE host_id = $1 AND ts >= $2
		GROUP BY type
	`, hostID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var evType string
		var cnt int
		if err := rows.Scan(&evType, &cnt); err != nil {
			continue
		}
		switch evType {
		case "process_exec":
			summary.ProcessExecCount = cnt
		case "file_open":
			summary.FileOpenCount = cnt
		case "net_connect":
			summary.NetConnectCount = cnt
		case "net_dns":
			summary.DNSQueryCount = cnt
		}
	}

	// Get unique binaries
	binRows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT actor->>'comm' FROM events
		WHERE host_id = $1 AND ts >= $2 AND type = 'process_exec' AND actor->>'comm' IS NOT NULL
		LIMIT 50
	`, hostID, since)
	if err == nil {
		defer binRows.Close()
		for binRows.Next() {
			var comm string
			if binRows.Scan(&comm) == nil && comm != "" {
				summary.UniqueBinaries = append(summary.UniqueBinaries, comm)
			}
		}
	}

	// Get findings count
	_ = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COUNT(*) FILTER (WHERE suppressed = true)
		FROM findings WHERE host_id = $1 AND created_at >= $2
	`, hostID, since).Scan(&summary.FindingsGenerated, &summary.FindingsSuppressed)

	// Classify activity pattern
	summary.ActivityPattern = classifyActivity(summary)

	return summary, nil
}

// classifyActivity determines what the user/system was doing based on event patterns.
func classifyActivity(s *ContextSummary) string {
	devTools := map[string]bool{
		"bash": true, "git": true, "go": true, "node": true, "npm": true,
		"python": true, "pip": true, "cargo": true, "rustc": true,
		"javac": true, "gradle": true, "maven": true, "dotnet": true,
		"psql": true, "mysql": true, "code": true, "claude": true, "cursor": true,
	}
	devToolCount := 0
	for _, b := range s.UniqueBinaries {
		if devTools[b] {
			devToolCount++
		}
	}

	switch {
	case s.ProcessExecCount > 20 && devToolCount >= 3:
		return "active_development"
	case s.ProcessExecCount > 50:
		return "build_or_ci"
	case s.ProcessExecCount > 5 && devToolCount >= 2:
		return "active_development"
	case s.ProcessExecCount == 0 && s.NetConnectCount > 0:
		return "idle_with_background_network"
	case s.ProcessExecCount == 0 && s.FileOpenCount == 0 && s.NetConnectCount == 0:
		return "idle"
	default:
		return "light_activity"
	}
}
