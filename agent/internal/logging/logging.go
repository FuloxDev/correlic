package logging

import (
	"log/slog"
	"os"
)

/*
Init initializes the logging system with the specified log level.
*/
func Init(level string) {
	var logLevel slog.Level

	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// create a new JSON handler for logging
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})

	// set the default logger to use the new handler
	slog.SetDefault(slog.New(handler))
}
