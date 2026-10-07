//go:build linux

package ebpf

import (
	"context"
	"log/slog"
	"strings"

	"github.com/correlic/correlic-agent/internal/collect"
)

// UnlinkRunner wraps the UnlinkCollector to implement the collect.Collector interface.
type UnlinkRunner struct {
	collector *UnlinkCollector
	emit      collect.EventSink
	logger    *slog.Logger
}

// NewUnlinkRunner creates a new file deletion monitoring runner.
func NewUnlinkRunner(emit collect.EventSink, logger *slog.Logger) (*UnlinkRunner, error) {
	if logger == nil {
		logger = slog.Default()
	}

	collector, err := NewUnlinkCollector(logger)
	if err != nil {
		return nil, err
	}

	return &UnlinkRunner{
		collector: collector,
		emit:      emit,
		logger:    logger,
	}, nil
}

// Start implements the collect.Collector interface.
func (r *UnlinkRunner) Start(ctx context.Context) {
	// Start the underlying collector
	go r.collector.Start(ctx)

	r.logger.Info("eBPF unlink runner started, forwarding file deletion events")

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("eBPF unlink runner stopping")
			r.collector.Close()
			return
		case event := <-r.collector.Events():
			// Categorize the deletion
			category, risk := categorizeUnlink(event.Path, event.Comm)

			// Skip low-interest deletions (tmp files, cache, etc.)
			if category == "noise" {
				continue
			}

			// Convert UnlinkEvent to telemetry format
			payload := map[string]any{
				"pid":      event.PID,
				"ppid":     event.PPID,
				"uid":      event.UID,
				"path":     event.Path,
				"comm":     event.Comm,
				"pcomm":    event.ParentComm,
				"category": category,
				"risk":     risk,
				"source":   "ebpf",
			}

			ok := r.emit("file_delete", payload)
			if !ok {
				r.logger.Debug("file delete event dropped by sink")
			}
		}
	}
}

// Close releases eBPF resources.
func (r *UnlinkRunner) Close() error {
	if r.collector != nil {
		return r.collector.Close()
	}
	return nil
}

// categorizeUnlink returns a category and risk level for the deletion.
func categorizeUnlink(path, comm string) (category, risk string) {
	// Artifact cleanup - shell history
	if strings.Contains(path, ".bash_history") ||
		strings.Contains(path, ".zsh_history") ||
		strings.Contains(path, ".sh_history") {
		return "history_cleanup", "critical"
	}

	// Git object deletion
	if strings.Contains(path, ".git/objects") ||
		strings.Contains(path, ".git/logs") ||
		strings.Contains(path, ".git/refs") {
		return "git_cleanup", "high"
	}

	// Credential file deletion
	if strings.Contains(path, ".ssh/") ||
		strings.Contains(path, ".aws/") ||
		strings.Contains(path, ".kube/") ||
		strings.Contains(path, ".gnupg/") {
		return "credential_cleanup", "critical"
	}

	// Log file deletion
	if strings.HasSuffix(path, ".log") ||
		strings.Contains(path, "/var/log/") ||
		strings.Contains(path, "/logs/") {
		return "log_cleanup", "high"
	}

	// Source code deletion
	if strings.HasSuffix(path, ".go") ||
		strings.HasSuffix(path, ".py") ||
		strings.HasSuffix(path, ".js") ||
		strings.HasSuffix(path, ".ts") ||
		strings.HasSuffix(path, ".rs") ||
		strings.HasSuffix(path, ".java") {
		return "source_delete", "medium"
	}

	// Config file deletion
	if strings.HasSuffix(path, ".yaml") ||
		strings.HasSuffix(path, ".yml") ||
		strings.HasSuffix(path, ".json") ||
		strings.HasSuffix(path, ".toml") ||
		strings.HasSuffix(path, ".env") ||
		strings.Contains(path, ".config/") {
		return "config_delete", "medium"
	}

	// Docker/container artifact deletion
	if strings.Contains(path, "docker") ||
		strings.Contains(path, "container") {
		return "container_cleanup", "medium"
	}

	// AI agent specific deletions (patterns for Cursor, Claude, etc.)
	aiProcesses := map[string]bool{
		"cursor": true, "claude": true, "copilot": true,
		"codeium": true, "tabnine": true,
	}
	if aiProcesses[strings.ToLower(comm)] {
		return "ai_agent_delete", "high"
	}

	// Noise - temp files, cache, etc.
	if strings.HasPrefix(path, "/tmp/") ||
		strings.Contains(path, "/cache/") ||
		strings.Contains(path, "/.cache/") ||
		strings.HasSuffix(path, ".tmp") ||
		strings.HasSuffix(path, ".swp") ||
		strings.HasSuffix(path, "~") ||
		strings.Contains(path, "__pycache__") ||
		strings.Contains(path, "node_modules/.cache") {
		return "noise", "none"
	}

	// Default - track but low priority
	return "other", "low"
}
