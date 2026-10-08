package hook

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// LogFileName is the diagnostics log under ~/.correlic.
const LogFileName = "hook.log"

// logMaxBytes rotates hook.log to hook.log.1 once it grows past this size, so
// the file never grows without bound on a busy machine.
const logMaxBytes = 1 << 20

// OpenLogger returns a logger writing to dir/hook.log (rotated at 1 MiB) and,
// when debug is true, to stderr as well. stdout is never used: it is the
// hook protocol channel. If the file cannot be opened the logger writes to
// stderr only in debug mode, else discards.
func OpenLogger(dir string, debug bool) (*slog.Logger, func()) {
	var writers []io.Writer
	closeFn := func() {}

	if dir != "" {
		path := filepath.Join(dir, LogFileName)
		if err := os.MkdirAll(dir, 0o700); err == nil {
			rotateIfLarge(path)
			if f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600); err == nil {
				writers = append(writers, f)
				closeFn = func() { _ = f.Close() }
			}
		}
	}
	level := slog.LevelInfo
	if debug {
		writers = append(writers, os.Stderr)
		level = slog.LevelDebug
	}
	if len(writers) == 0 {
		return slog.New(slog.NewTextHandler(io.Discard, nil)), closeFn
	}
	h := slog.NewTextHandler(io.MultiWriter(writers...), &slog.HandlerOptions{Level: level})
	return slog.New(h).With("pid", os.Getpid()), closeFn
}

func rotateIfLarge(path string) {
	st, err := os.Stat(path)
	if err != nil || st.Size() < logMaxBytes {
		return
	}
	_ = os.Remove(path + ".1")
	_ = os.Rename(path, path+".1")
}
