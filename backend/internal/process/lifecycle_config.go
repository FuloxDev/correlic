package process

import (
	"os"
	"strconv"
	"time"
)

// LifecycleConfig holds configurable thresholds for lifecycle classification.
type LifecycleConfig struct {
	ShortLivedThreshold time.Duration
	DaemonMinRuntime    time.Duration
}

// DefaultLifecycleConfig returns default thresholds (500ms short-lived, 30s daemon minimum).
func DefaultLifecycleConfig() LifecycleConfig {
	return LifecycleConfig{
		ShortLivedThreshold: 500 * time.Millisecond,
		DaemonMinRuntime:    30 * time.Second,
	}
}

// LifecycleConfigFromEnv returns config from env with defaults. EXEC_SHORT_LIVED_MS and EXEC_DAEMON_MIN_MS.
func LifecycleConfigFromEnv() LifecycleConfig {
	cfg := DefaultLifecycleConfig()
	if v := os.Getenv("EXEC_SHORT_LIVED_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil {
			cfg.ShortLivedThreshold = time.Duration(ms) * time.Millisecond
		}
	}
	if v := os.Getenv("EXEC_DAEMON_MIN_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil {
			cfg.DaemonMinRuntime = time.Duration(ms) * time.Millisecond
		}
	}
	return cfg
}

// ExitMaxFutureFromEnv returns the max allowed future offset for process_exit timestamps (Phase 18B).
// Env: EXIT_MAX_FUTURE_MS (default 300000 = 5 minutes). Tune per environment for containers/suspend/resume.
func ExitMaxFutureFromEnv() time.Duration {
	const defaultMs = 300000 // 5 minutes
	if v := os.Getenv("EXIT_MAX_FUTURE_MS"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms >= 0 {
			return time.Duration(ms) * time.Millisecond
		}
	}
	return defaultMs * time.Millisecond
}

// ExitYearBoundsFromEnv returns the allowed year range for process_exit timestamps (clock skew / embedded / replay).
// Env: EXIT_YEAR_MIN (default 2000), EXIT_YEAR_MAX (default 2100). Invalid or min <= 1970 or max < min → 2000, 2100.
func ExitYearBoundsFromEnv() (min, max int) {
	min = envIntDefault("EXIT_YEAR_MIN", 2000)
	max = envIntDefault("EXIT_YEAR_MAX", 2100)
	if min <= 1970 || max < min {
		return 2000, 2100
	}
	return min, max
}

func envIntDefault(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
