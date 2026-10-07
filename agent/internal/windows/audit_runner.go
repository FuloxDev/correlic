//go:build windows

package windows

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/lineage"
)

// Access mask constants for file/registry access distinction
const (
	accessReadData    = 0x1
	accessWriteData   = 0x2
	accessAppendData  = 0x4
	accessDelete      = 0x10000
	accessWriteDAC    = 0x40000
	accessWriteOwner  = 0x80000
)

// AuditRunner converts Windows Security Audit events (from AuditSubscriber)
// into canonical Correlic events and dispatches them to the backend.
//
// Events handled:
//   - 4657 (Registry Value Modified) → "registry_write" events
//   - 4656 (Handle Request) → enriches file_open with access_type
//   - 4672 (Special Privileges) → "privilege_use" events
//   - 4698 (Scheduled Task Created) → "schtask_create" events
//   - 4688/4689 are handled by CmdlineCache, not dispatched separately
type AuditRunner struct {
	subscriber *AuditSubscriber
	dispatcher dispatch.Dispatcher
	logger     *slog.Logger
	hostID     string
}

// NewAuditRunner creates a runner for audit events.
func NewAuditRunner(subscriber *AuditSubscriber, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *AuditRunner {
	return &AuditRunner{
		subscriber: subscriber,
		dispatcher: disp,
		logger:     logger.With("component", "audit_runner"),
		hostID:     hostID,
	}
}

// Start processes audit events from the subscriber.
func (r *AuditRunner) Start(ctx context.Context) {
	r.logger.Info("audit runner started (registry, privilege, scheduled task events)")

	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-r.subscriber.Events():
			if !ok {
				return
			}

			// Only process events from AI processes (or their children)
			if evt.PID > 0 && !tracker.IsAI(evt.PID) {
				continue
			}

			switch evt.EventID {
			case 4657:
				r.handleRegistryWrite(evt)
			case 4656:
				r.handleObjectAccess(evt)
			case 4672:
				r.handlePrivilegeUse(evt)
			case 4698:
				r.handleScheduledTask(evt)
			// 4688/4689 handled by CmdlineCache — not dispatched here
			}
		}
	}
}

func (r *AuditRunner) handleRegistryWrite(evt AuditEvent) {
	if evt.RegKey == "" {
		return
	}

	// Normalize registry key path
	regPath := strings.ReplaceAll(evt.RegKey, "\\REGISTRY\\MACHINE\\", "HKLM\\")
	regPath = strings.ReplaceAll(regPath, "\\REGISTRY\\USER\\", "HKU\\")

	canonEvt := event.Event{
		SchemaVersion: 1,
		Type:          "registry_write",
		Timestamp:     evt.Timestamp,
		HostID:        r.hostID,
		Source:        "event_log_security",
		Actor: &event.Actor{
			PID:     int(evt.PID),
			ExePath: normalizePath(evt.ExePath),
			Comm:    strings.ToLower(filepath.Base(evt.ExePath)),
		},
		Target: &event.Target{
			FilePath: regPath, // Treat registry path like file path for compatibility
		},
		Context: map[string]any{
			"event_id":   4657,
			"reg_key":    regPath,
			"reg_value":  evt.RegValue,
			"old_value":  evt.RegOldVal,
			"new_value":  evt.RegNewVal,
			"operation":  "SetValue",
		},
	}

	if aiSess := lineage.GetLineageTracker().GetSessionID(evt.PID); aiSess != "" {
		canonEvt.Context["ai_session_id"] = aiSess
	}
	if aiType := lineage.GetLineageTracker().GetAIType(evt.PID); aiType != "" {
		canonEvt.Context["ai_type"] = aiType
	}

	canonEvt.ID = event.GenerateID(r.hostID, evt.Timestamp.UnixNano(),
		canonEvt.Source, canonEvt.Type, canonEvt.Actor.PID, regPath)

	r.dispatcher.Enqueue(canonEvt)

	r.logger.Debug("registry write event dispatched",
		"pid", evt.PID, "key", regPath, "value", evt.RegValue)
}

func (r *AuditRunner) handleObjectAccess(evt AuditEvent) {
	if evt.ObjectPath == "" || evt.ObjectType != "File" {
		return // Only interested in file object access
	}

	accessType := "read"
	if evt.AccessMask&(accessWriteData|accessAppendData|accessDelete|accessWriteDAC|accessWriteOwner) != 0 {
		accessType = "write"
	}

	canonEvt := event.Event{
		SchemaVersion: 1,
		Type:          "file_access",
		Timestamp:     evt.Timestamp,
		HostID:        r.hostID,
		Source:        "event_log_security",
		Actor: &event.Actor{
			PID:     int(evt.PID),
			ExePath: normalizePath(evt.ExePath),
			Comm:    strings.ToLower(filepath.Base(evt.ExePath)),
		},
		Target: &event.Target{
			FilePath: normalizePath(evt.ObjectPath),
		},
		Context: map[string]any{
			"event_id":    4656,
			"access_type": accessType,
			"access_mask": evt.AccessMask,
			"file_exists": true, // 4656 only fires for existing objects
		},
	}

	if aiSess := lineage.GetLineageTracker().GetSessionID(evt.PID); aiSess != "" {
		canonEvt.Context["ai_session_id"] = aiSess
	}
	if aiType := lineage.GetLineageTracker().GetAIType(evt.PID); aiType != "" {
		canonEvt.Context["ai_type"] = aiType
	}

	canonEvt.ID = event.GenerateID(r.hostID, evt.Timestamp.UnixNano(),
		canonEvt.Source, canonEvt.Type, canonEvt.Actor.PID, evt.ObjectPath)

	r.dispatcher.Enqueue(canonEvt)
}

func (r *AuditRunner) handlePrivilegeUse(evt AuditEvent) {
	if len(evt.Privileges) == 0 {
		return
	}

	// Filter out common non-sensitive privileges
	var sensitive []string
	for _, p := range evt.Privileges {
		p = strings.TrimSpace(p)
		switch p {
		case "SeDebugPrivilege",
			"SeTakeOwnershipPrivilege",
			"SeLoadDriverPrivilege",
			"SeImpersonatePrivilege",
			"SeAssignPrimaryTokenPrivilege",
			"SeTcbPrivilege",
			"SeBackupPrivilege",
			"SeRestorePrivilege",
			"SeCreateTokenPrivilege":
			sensitive = append(sensitive, p)
		}
	}
	if len(sensitive) == 0 {
		return // Only non-sensitive privileges — skip
	}

	canonEvt := event.Event{
		SchemaVersion: 1,
		Type:          "privilege_use",
		Timestamp:     evt.Timestamp,
		HostID:        r.hostID,
		Source:        "event_log_security",
		Actor: &event.Actor{
			PID:  int(evt.PID),
			User: evt.User,
		},
		Context: map[string]any{
			"event_id":   4672,
			"privileges": sensitive,
		},
	}

	if aiSess := lineage.GetLineageTracker().GetSessionID(evt.PID); aiSess != "" {
		canonEvt.Context["ai_session_id"] = aiSess
	}

	canonEvt.ID = event.GenerateID(r.hostID, evt.Timestamp.UnixNano(),
		canonEvt.Source, canonEvt.Type, canonEvt.Actor.PID, strings.Join(sensitive, ","))

	r.dispatcher.Enqueue(canonEvt)

	r.logger.Info("sensitive privilege use detected",
		"pid", evt.PID, "user", evt.User, "privileges", sensitive)
}

func (r *AuditRunner) handleScheduledTask(evt AuditEvent) {
	if evt.TaskName == "" {
		return
	}

	canonEvt := event.Event{
		SchemaVersion: 1,
		Type:          "schtask_create",
		Timestamp:     evt.Timestamp,
		HostID:        r.hostID,
		Source:        "event_log_security",
		Actor: &event.Actor{
			User: evt.User,
		},
		Context: map[string]any{
			"event_id":  4698,
			"task_name": evt.TaskName,
			"task_xml":  evt.TaskXML,
		},
	}

	canonEvt.ID = event.GenerateID(r.hostID, evt.Timestamp.UnixNano(),
		canonEvt.Source, canonEvt.Type, 0, evt.TaskName)

	r.dispatcher.Enqueue(canonEvt)

	r.logger.Info("scheduled task created",
		"task", evt.TaskName, "user", evt.User)
}

// normalizePath converts Windows paths to forward-slash format.
func normalizePath(p string) string {
	return filepath.ToSlash(p)
}
