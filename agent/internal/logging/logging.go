// Package logging configures the process-wide slog logger.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// Level is the dynamic level shared by every handler the agent installs.
// Changing it (SetLevel) takes effect on all platforms, including the
// Windows service file handler.
var Level = new(slog.LevelVar)

// ParseLevel converts a config log_level string to a slog.Level. Unknown
// values map to Info.
func ParseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// SetLevel updates the shared level from a config log_level string.
func SetLevel(level string) {
	Level.Set(ParseLevel(level))
}

// Init installs a text handler writing to w (stderr when nil) at the given
// level, sets it as the default logger and returns it.
func Init(level string, w io.Writer) *slog.Logger {
	if w == nil {
		w = os.Stderr
	}
	SetLevel(level)
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: Level})
	logger := slog.New(handler)
	slog.SetDefault(logger)
	return logger
}
