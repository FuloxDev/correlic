//go:build windows

// Package logging provides Windows Event Log integration for the Correlic agent.
package logging

import (
	"context"
	"log/slog"

	"golang.org/x/sys/windows/svc/eventlog"
)

const eventLogSource = "CorrelicAgent"

// EventLogHandler is a slog.Handler that writes to the Windows Event Log.
// Used in service mode to ensure agent logs are visible in Event Viewer.
type EventLogHandler struct {
	elog  *eventlog.Log
	inner slog.Handler // Fallback handler (e.g., stderr)
	level slog.Level
}

// NewEventLogHandler creates a new Windows Event Log handler.
// Falls back to the inner handler if the Event Log cannot be opened.
func NewEventLogHandler(inner slog.Handler, level slog.Level) (*EventLogHandler, error) {
	// Ensure the event source is registered.
	// Ignore error if already exists.
	_ = eventlog.InstallAsEventCreate(eventLogSource, eventlog.Info|eventlog.Warning|eventlog.Error)

	elog, err := eventlog.Open(eventLogSource)
	if err != nil {
		return nil, err
	}

	return &EventLogHandler{
		elog:  elog,
		inner: inner,
		level: level,
	}, nil
}

// Enabled reports whether the handler is enabled for the given level.
func (h *EventLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level
}

// Handle writes the log record to both the Windows Event Log and the inner handler.
func (h *EventLogHandler) Handle(ctx context.Context, r slog.Record) error {
	msg := r.Message

	// Write to Windows Event Log based on severity.
	switch {
	case r.Level >= slog.LevelError:
		_ = h.elog.Error(1, msg)
	case r.Level >= slog.LevelWarn:
		_ = h.elog.Warning(2, msg)
	default:
		_ = h.elog.Info(3, msg)
	}

	// Also write to the inner handler (e.g., stderr for debugging).
	if h.inner != nil {
		return h.inner.Handle(ctx, r)
	}
	return nil
}

// WithAttrs returns a new handler with the given attributes.
func (h *EventLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	inner := h.inner
	if inner != nil {
		inner = inner.WithAttrs(attrs)
	}
	return &EventLogHandler{
		elog:  h.elog,
		inner: inner,
		level: h.level,
	}
}

// WithGroup returns a new handler with the given group.
func (h *EventLogHandler) WithGroup(name string) slog.Handler {
	inner := h.inner
	if inner != nil {
		inner = inner.WithGroup(name)
	}
	return &EventLogHandler{
		elog:  h.elog,
		inner: inner,
		level: h.level,
	}
}

// Close releases the Event Log handle.
func (h *EventLogHandler) Close() error {
	if h.elog != nil {
		return h.elog.Close()
	}
	return nil
}
