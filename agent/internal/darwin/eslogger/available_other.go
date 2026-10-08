//go:build !darwin

package eslogger

import "log/slog"

// Available always fails off macOS; the parser and collector are still
// compiled here so their tests run on Linux.
func Available(*slog.Logger) error { return ErrUnsupportedOS }
