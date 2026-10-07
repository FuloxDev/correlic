package query

import (
	"context"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/storage/eventstore"
)

// GetEventType returns the event type for the given id (e.g. process_exec, net_listen).
// Returns empty string if the event is not found or on error.
func (s *Service) GetEventType(ctx context.Context, id string) (string, error) {
	evt, err := s.Store.GetByID(ctx, id)
	if err != nil || evt == nil {
		return "", err
	}
	return evt.Type, nil
}

// Service runs structured queries over canonical events. No heuristics; deterministic results.
type Service struct {
	Store eventstore.EventStore
}

// NewService returns a query service that uses the given event store.
func NewService(store eventstore.EventStore) *Service {
	return &Service{Store: store}
}

// ListContainerStarts returns container_start events in the time range for the host. Truncated is true if more existed.
func (s *Service) ListContainerStarts(ctx context.Context, hostID string, since, until time.Time) ([]ContainerStartRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	var out []ContainerStartRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "container_start" {
			continue
		}
		row := ContainerStartRow{
			ID: e.ID, HostID: e.HostID, Timestamp: e.Timestamp,
		}
		if e.Target != nil {
			row.ContainerID = e.Target.ContainerID
			row.ContainerImg = e.Target.ContainerImg
		}
		if e.Process != nil {
			row.ProcessPID = e.Process.PID
		}
		out = append(out, row)
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

// ListOpenPorts returns net_listen events in the time range for the host. Truncated is true if more existed.
func (s *Service) ListOpenPorts(ctx context.Context, hostID string, since, until time.Time) ([]OpenPortRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	var out []OpenPortRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "net_listen" {
			continue
		}
		row := OpenPortRow{
			ID: e.ID, HostID: e.HostID, Timestamp: e.Timestamp,
		}
		if e.Target != nil {
			row.Port = e.Target.Port
			row.Protocol = e.Target.Protocol
		}
		if e.Process != nil {
			row.ProcessPID = e.Process.PID
			row.ExePath = SanitizeExePathForResponse(e.Process.ExePath)
		}
		out = append(out, row)
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

// ListExternalConnections returns net_connect events in the time range for the host. Truncated is true if more existed.
func (s *Service) ListExternalConnections(ctx context.Context, hostID string, since, until time.Time) ([]ExternalConnectionRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	var out []ExternalConnectionRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "net_connect" {
			continue
		}
		row := ExternalConnectionRow{
			ID: e.ID, HostID: e.HostID, Timestamp: e.Timestamp,
		}
		if e.Target != nil {
			row.IP = e.Target.IP
			row.Port = e.Target.Port
			row.Protocol = e.Target.Protocol
		}
		if e.Process != nil {
			row.ProcessPID = e.Process.PID
			row.ExePath = SanitizeExePathForResponse(e.Process.ExePath)
		}
		out = append(out, row)
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

// ListInboundConnections returns net_accept events in the time range for the host (who connected to this host).
func (s *Service) ListInboundConnections(ctx context.Context, hostID string, since, until time.Time) ([]InboundConnectionRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	var out []InboundConnectionRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "net_accept" {
			continue
		}
		row := InboundConnectionRow{
			ID: e.ID, HostID: e.HostID, Timestamp: e.Timestamp,
		}
		if e.Target != nil {
			row.IP = e.Target.IP
			row.Port = e.Target.Port
			row.Protocol = e.Target.Protocol
		}
		if e.Process != nil {
			row.ProcessPID = e.Process.PID
			row.ExePath = SanitizeExePathForResponse(e.Process.ExePath)
		}
		out = append(out, row)
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

// ListProcessExits returns process_exit events in the time range for the host. Truncated is true if more existed.
func (s *Service) ListProcessExits(ctx context.Context, hostID string, since, until time.Time) ([]ProcessExitRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	var out []ProcessExitRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "process_exit" || e.Process == nil {
			continue
		}
		row := ProcessExitRow{
			ID:        e.ID,
			HostID:    e.HostID,
			Timestamp: e.Timestamp,
			PID:       e.Process.PID,
			PPID:      e.Process.PPID,
			ExitCode:  contextInt(e.Context, "exit_code"),
		}
		out = append(out, row)
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

// ListProcessesByExecutable returns process_exec events whose ExePath contains the pattern (substring match). Truncated is true if more existed.
// Populates ExecClass from event Context when present (exec normalization).
func (s *Service) ListProcessesByExecutable(ctx context.Context, hostID string, since, until time.Time, pattern string) ([]ProcessByExecutableRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	pattern = strings.TrimSpace(pattern)
	var out []ProcessByExecutableRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "process_exec" || e.Process == nil {
			continue
		}
		if pattern != "" && !strings.Contains(e.Process.ExePath, pattern) {
			continue
		}
		row := ProcessByExecutableRow{
			ID:        e.ID,
			HostID:    e.HostID,
			Timestamp: e.Timestamp,
			PID:       e.Process.PID,
			PPID:      e.Process.PPID,
			ExePath:   SanitizeExePathForResponse(e.Process.ExePath),
		}
		if e.Context != nil {
			row.ExecClass = contextString(e.Context, "exec_class")
		}
		out = append(out, row)
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

// ListExecs returns all process_exec events in the time range (for lifecycle materializer).
func (s *Service) ListExecs(ctx context.Context, hostID string, since, until time.Time) ([]ExecRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	var out []ExecRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "process_exec" || e.Process == nil {
			continue
		}
		out = append(out, ExecRow{
			ID:        e.ID,
			HostID:    e.HostID,
			Timestamp: e.Timestamp,
			PID:       e.Process.PID,
			PPID:      e.Process.PPID,
			ExePath:   SanitizeExePathForResponse(e.Process.ExePath),
		})
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

// ListPrimaryExecs returns process_exec events with exec_class == "primary" in the time range.
// Used by AI and detections for high-value exec signal.
// Implementation is intentionally naive: in-memory filter after GetRange, depends on context["exec_class"].
// Do not optimize (partial index, materialized view) until this is hot-path (Phase 15+).
func (s *Service) ListPrimaryExecs(ctx context.Context, hostID string, since, until time.Time) ([]ExecRow, bool, error) {
	events, err := s.Store.GetRange(ctx, hostID, since, until)
	if err != nil {
		return nil, false, err
	}
	var out []ExecRow
	for _, e := range events {
		if e.Timestamp.After(until) {
			continue
		}
		if e.Type != "process_exec" || e.Process == nil {
			continue
		}
		if contextString(e.Context, "exec_class") != "primary" {
			continue
		}
		out = append(out, ExecRow{
			ID:        e.ID,
			HostID:    e.HostID,
			Timestamp: e.Timestamp,
			PID:       e.Process.PID,
			PPID:      e.Process.PPID,
			ExePath:   SanitizeExePathForResponse(e.Process.ExePath),
		})
		if len(out) >= MaxResults {
			return out, true, nil
		}
	}
	return out, false, nil
}

func contextString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func contextInt(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	v, ok := m[key]
	if !ok {
		return 0
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return 0
	}
}
