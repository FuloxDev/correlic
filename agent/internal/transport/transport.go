package transport

import (
	"context"

	"github.com/correlic/correlic-agent/internal/model"
)

// Transport defines the interface for sending heartbeats to the backend.
type Transport interface {

	// SendHeartbeat sends a heartbeat to the backend.
	SendHeartbeat(ctx context.Context, hb model.Heartbeat) error

	// SendTelemetryBatch sends a batch of telemetry events to the backend.
	SendTelemetryBatch(ctx context.Context, batch model.TelemetryBatch) error

	// ListApprovals fetches approvals from the telemetry plane (v0).
	// status may be: pending|approved|rejected (empty means all).
	ListApprovals(ctx context.Context, status string, agentID string, limit int) ([]model.Approval, error)

	// DecideApproval sends an approval decision to the telemetry plane (v0).
	// status must be: approved|rejected.
	DecideApproval(ctx context.Context, approvalID string, status string, reason string) error

	// CheckApproval performs a preflight approval gate check.
	CheckApproval(ctx context.Context, agentID string, kind string, subject map[string]any) (*model.ApprovalCheckResponse, error)
}
