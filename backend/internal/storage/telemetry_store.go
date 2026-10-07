package storage

import (
	"time"

	"github.com/correlic/correlic-backend/internal/model"
)

// TelemetryListFilter describes optional filters for listing telemetry events.
type TelemetryListFilter struct {
	AgentID   string
	EventType string
	Since     time.Time
	Until     time.Time
	PID       int64

	Limit  int
	Offset int
}

// TelemetryStore is the storage boundary for telemetry events.
type TelemetryStore interface {
	InsertEvents(orgID string, events []model.TelemetryEvent) error
	ListRecent(orgID string, agentID string, limit int) ([]model.TelemetryEvent, error)
	ListRange(orgID string, agentID string, eventType string, from, to time.Time, limit int) ([]model.TelemetryEvent, error)
	ListByIDs(orgID string, agentID string, ids []string, limit int) ([]model.TelemetryEvent, error)
	// ListAll returns recent events for an org (all agents, optionally filtered)
	ListAll(orgID string, eventType string, limit int, offset int) ([]model.TelemetryEvent, error)
	// ListFiltered returns recent events for an org with optional filters.
	ListFiltered(orgID string, f TelemetryListFilter) ([]model.TelemetryEvent, error)
	// CountFiltered returns the number of events matching the filter (ignores Limit/Offset).
	CountFiltered(orgID string, f TelemetryListFilter) (int, error)
	// CountToday returns count of events since midnight for an org
	CountToday(orgID string) (int, error)
	// CountByEventType returns event counts grouped by event_type since a given time.
	// Returns (map[event_type]count, total, error). Replaces multiple CountFiltered calls.
	CountByEventType(orgID string, since time.Time) (map[string]int, int, error)
}
