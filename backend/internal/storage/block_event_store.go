package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// BlockEvent records an individual block action taken by an agent.
type BlockEvent struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	HostID     string    `json:"host_id"`
	AgentID    string    `json:"agent_id"`
	RuleID     int       `json:"rule_id"`
	SignalType string    `json:"signal_type"`
	PID        int       `json:"pid"`
	ExePath    string    `json:"exe_path"`
	Cmdline    string    `json:"cmdline"`
	Target     string    `json:"target"`
	AIType     string    `json:"ai_type"`
	Success    bool      `json:"success"`
	ErrorMsg   string    `json:"error_msg"`
	LatencyUS  int       `json:"latency_us"`
	BlockedAt  time.Time `json:"blocked_at"`
}

// BlockEventStats provides aggregated block event statistics.
type BlockEventStats struct {
	TotalBlocked int64 `json:"total_blocked"`
	SuccessCount int64 `json:"success_count"`
	FailedCount  int64 `json:"failed_count"`
	UniqueRules  int64 `json:"unique_rules"`
}

// BlockEventStore manages the block_events audit trail.
type BlockEventStore struct {
	db *sql.DB
}

func NewBlockEventStore(db *sql.DB) *BlockEventStore {
	return &BlockEventStore{db: db}
}

// Insert records a single block event.
func (s *BlockEventStore) Insert(ctx context.Context, event BlockEvent) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO block_events (id, org_id, host_id, agent_id, rule_id, signal_type, pid, exe_path, cmdline, target, ai_type, success, error_msg, latency_us, blocked_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		event.ID, event.OrgID, event.HostID, event.AgentID, event.RuleID,
		event.SignalType, event.PID, event.ExePath, event.Cmdline, event.Target,
		event.AIType, event.Success, event.ErrorMsg, event.LatencyUS, event.BlockedAt)
	if err != nil {
		return fmt.Errorf("insert block_event: %w", err)
	}
	return nil
}

// InsertBatch records multiple block events in a single transaction.
func (s *BlockEventStore) InsertBatch(ctx context.Context, events []BlockEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO block_events (id, org_id, host_id, agent_id, rule_id, signal_type, pid, exe_path, cmdline, target, ai_type, success, error_msg, latency_us, blocked_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`)
	if err != nil {
		return fmt.Errorf("prepare: %w", err)
	}
	defer stmt.Close()

	for _, e := range events {
		if _, err := stmt.ExecContext(ctx, e.ID, e.OrgID, e.HostID, e.AgentID, e.RuleID,
			e.SignalType, e.PID, e.ExePath, e.Cmdline, e.Target,
			e.AIType, e.Success, e.ErrorMsg, e.LatencyUS, e.BlockedAt); err != nil {
			return fmt.Errorf("insert block_event %s: %w", e.ID, err)
		}
	}
	return tx.Commit()
}

// List returns block events for an org, optionally filtered by host_id.
// If hostID is empty, all events for the org are returned.
func (s *BlockEventStore) List(ctx context.Context, orgID string, hostID string, since time.Time, limit int) ([]BlockEvent, error) {
	if limit <= 0 {
		limit = 100
	}

	var rows *sql.Rows
	var err error
	if hostID != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, org_id, host_id, agent_id, rule_id, signal_type, pid, exe_path, cmdline, target, ai_type, success, error_msg, latency_us, blocked_at
			 FROM block_events
			 WHERE org_id = $1 AND host_id = $2 AND blocked_at >= $3
			 ORDER BY blocked_at DESC
			 LIMIT $4`,
			orgID, hostID, since, limit)
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, org_id, host_id, agent_id, rule_id, signal_type, pid, exe_path, cmdline, target, ai_type, success, error_msg, latency_us, blocked_at
			 FROM block_events
			 WHERE org_id = $1 AND blocked_at >= $2
			 ORDER BY blocked_at DESC
			 LIMIT $3`,
			orgID, since, limit)
	}
	if err != nil {
		return nil, fmt.Errorf("list block_events: %w", err)
	}
	defer rows.Close()

	var out []BlockEvent
	for rows.Next() {
		var e BlockEvent
		if err := rows.Scan(&e.ID, &e.OrgID, &e.HostID, &e.AgentID, &e.RuleID,
			&e.SignalType, &e.PID, &e.ExePath, &e.Cmdline, &e.Target,
			&e.AIType, &e.Success, &e.ErrorMsg, &e.LatencyUS, &e.BlockedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Stats returns aggregated block event statistics for the given org since the specified time.
func (s *BlockEventStore) Stats(ctx context.Context, orgID string, since time.Time) (BlockEventStats, error) {
	var stats BlockEventStats
	err := s.db.QueryRowContext(ctx,
		`SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE success = true),
			COUNT(*) FILTER (WHERE success = false),
			COUNT(DISTINCT rule_id)
		 FROM block_events
		 WHERE org_id = $1 AND blocked_at >= $2`,
		orgID, since).Scan(&stats.TotalBlocked, &stats.SuccessCount, &stats.FailedCount, &stats.UniqueRules)
	if err != nil {
		return stats, fmt.Errorf("block_event stats: %w", err)
	}
	return stats, nil
}

// CountByRule returns a map of rule_id → block count for the given org since the specified time.
func (s *BlockEventStore) CountByRule(ctx context.Context, orgID string, since time.Time) (map[int]int64, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT rule_id, COUNT(*)
		 FROM block_events
		 WHERE org_id = $1 AND blocked_at >= $2
		 GROUP BY rule_id`,
		orgID, since)
	if err != nil {
		return nil, fmt.Errorf("count_by_rule: %w", err)
	}
	defer rows.Close()

	out := make(map[int]int64)
	for rows.Next() {
		var ruleID int
		var count int64
		if err := rows.Scan(&ruleID, &count); err != nil {
			return nil, err
		}
		out[ruleID] = count
	}
	return out, rows.Err()
}
