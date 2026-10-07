//go:build windows

package windows

import (
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-agent/internal/classify"
	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/exechandler"
	"github.com/correlic/correlic-agent/internal/lineage"
	"github.com/correlic/correlic-agent/internal/procinfo"
)

// ExecRunner consumes ProcCollector events and emits canonical process_exec / process_exit events.
type ExecRunner struct {
	collector    *ProcCollector
	emit         collect.EventSink
	logger       *slog.Logger
	hostID       string
	dispatcher   dispatch.Dispatcher
	handler      *exechandler.ExecHandler
	dropCount    uint64
	enforcer     *enforcer.Enforcer
	cmdlineCache *CmdlineCache
}

// SetCmdlineCache sets the cache for merging Event 4688 cmdlines into ETW events.
func (r *ExecRunner) SetCmdlineCache(c *CmdlineCache) {
	r.cmdlineCache = c
}

// SetEnforcer attaches the soft-block enforcer to the exec runner.
func (r *ExecRunner) SetEnforcer(e *enforcer.Enforcer) {
	r.enforcer = e
}

// NewExecRunner creates an ETW-based process exec runner.
func NewExecRunner(emit collect.EventSink, logger *slog.Logger, hostID string, disp dispatch.Dispatcher) *ExecRunner {
	if logger == nil {
		logger = slog.Default()
	}
	if hostID == "" {
		hostID = "localhost"
	}
	return &ExecRunner{
		collector:  NewProcCollector(),
		emit:       emit,
		logger:     logger,
		hostID:     hostID,
		dispatcher: disp,
		handler: &exechandler.ExecHandler{
			HostID:     hostID,
			Dispatcher: disp,
		},
	}
}

// Collector returns the underlying ProcCollector so it can be registered with the ETW session.
func (r *ExecRunner) Collector() *ProcCollector {
	return r.collector
}

// Start processes proc events until ctx is cancelled.
func (r *ExecRunner) Start(ctx context.Context) {
	r.logger.Info("windows exec runner started (ETW Kernel-Process)")
	tracker := lineage.GetLineageTracker()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("windows exec runner stopping")
			return
		case ev, ok := <-r.collector.Events():
			if !ok {
				return
			}
			switch ev.Type {
			case ProcStart:
				r.handleStart(ev, tracker)
			case ProcStop:
				r.handleStop(ev, tracker)
			}
		}
	}
}

func (r *ExecRunner) handleStart(ev ProcEvent, tracker *lineage.LineageTracker) {
	defer func() {
		if rec := recover(); rec != nil {
			r.logger.Error("exec handleStart panic recovered", "error", rec, "pid", ev.PID)
		}
	}()

	// Command line capture priority:
	// 1. Event 4688 cache (100% reliable — kernel writes cmdline at creation)
	// 2. ETW callback capture (from ProcCollector, may have garbled data)
	// 3. PEB read fallback (for processes started before audit subscriber)
	var cmdlineArgs []string
	var cmdSource string

	// Check ETW callback cmdline validity — garbled PEB reads produce
	// non-ASCII garbage like "腴曲", "푍稾". If the cmdline contains
	// characters outside the printable ASCII+extended range, discard it.
	etwCmdlineValid := len(ev.Cmdline) > 0 && isValidCmdline(ev.Cmdline)

	if r.cmdlineCache != nil {
		// Try Event 4688 cache first (100% reliable — kernel writes it)
		// Wait up to 50ms for 4688 to arrive if ETW cmdline is invalid
		waitTime := 50 * time.Millisecond
		if etwCmdlineValid {
			waitTime = 5 * time.Millisecond // Short wait if we have a fallback
		}
		if cmd, _, ok := r.cmdlineCache.GetWithWait(ev.PID, waitTime); ok && cmd != "" {
			cmdlineArgs = splitCmdline(cmd)
			cmdSource = "event_4688"
		}
	}
	if len(cmdlineArgs) == 0 && etwCmdlineValid {
		cmdlineArgs = ev.Cmdline
		cmdSource = "etw_callback"
	}
	if len(cmdlineArgs) == 0 {
		cmdlineArgs = procinfo.ReadProcCmdline(ev.PID)
		if len(cmdlineArgs) > 0 {
			cmdSource = "peb_read"
		}
	}
	if len(cmdlineArgs) == 0 {
		r.logger.Debug("[DIAG] cmdline capture failed (all sources)", "pid", ev.PID, "image", ev.ImagePath)
	} else {
		r.logger.Debug("[DIAG] cmdline captured", "pid", ev.PID, "source", cmdSource, "args", len(cmdlineArgs))
	}

	// Redact credentials from cmdline before dispatch.
	// PGPASSWORD=secret → PGPASSWORD=***, --token=abc → --token=***
	if len(cmdlineArgs) > 0 {
		cmdlineArgs = redactCmdline(cmdlineArgs)
	}

	// PPID and ImagePath fallbacks.
	if ev.PPID == 0 {
		ev.PPID = lookupPPID(ev.PID)
	}
	if ev.ImagePath == "" {
		ev.ImagePath = queryImagePath(ev.PID)
	}

	comm := filepath.Base(ev.ImagePath)
	comm = strings.TrimSuffix(strings.ToLower(comm), ".exe")

	isAI := tracker.IsAI(ev.PID)
	if !isAI {
		isAI = tracker.RegisterProcess(ev.PID, ev.PPID, comm)
		if !isAI {
			r.dropCount++
			if r.dropCount <= 20 || r.dropCount%100 == 0 {
				r.logger.Info("[DIAG] exec dropped",
					"pid", ev.PID, "ppid", ev.PPID, "comm", comm,
					"exe", ev.ImagePath,
					"drop_count", r.dropCount)
			}
			return
		}
	}

	// Soft-block check — kill process if it matches a block rule
	wasBlocked := false
	if r.enforcer != nil && r.enforcer.IsEnabled() && !r.enforcer.IsProtected(ev.PID) {
		exeForMatch := filepath.ToSlash(ev.ImagePath)
		if exeForMatch == "" {
			exeForMatch = comm
		}
		if blocked, rule := r.enforcer.ShouldBlock("process_exec", exeForMatch); blocked {
			start := time.Now()
			success, killErr := r.enforcer.Kill(ev.PID, rule.KillTree)
			latency := time.Since(start)
			// Mark as blocked when rule MATCHED, regardless of kill success.
			// Fast processes (reg.exe) exit before we can kill them — the block
			// intent is still valid and the finding should show as "blocked".
			wasBlocked = true
			r.logger.Warn("BLOCKED process",
				"pid", ev.PID, "exe", exeForMatch, "comm", comm,
				"rule_id", rule.ID, "success", success, "latency", latency)
			if r.emit != nil {
				r.emit("block_event", map[string]any{
					"rule_id":     rule.ID,
					"signal_type": "process_exec",
					"pid":         int(ev.PID),
					"exe_path":    exeForMatch,
					"cmdline":     strings.Join(cmdlineArgs, " "),
					"success":     success,
					"error_msg":   errStr(killErr),
					"latency_us":  latency.Microseconds(),
				})
			}
		}
	}

	sessionID := procinfo.DetectSessionID(ev.PID)
	role := classify.CheckRole(comm)
	exePath := ntPathToDOS(normalisePath(ev.ImagePath))

	payload := map[string]any{
		"pid":     int(ev.PID),
		"ppid":    int(ev.PPID),
		"comm":    comm,
		"exe":     exePath,
		"cmdline": cmdlineArgs,
		"role":    role,
		"source":  "etw_kernel_process",
		"is_ai":   true,
	}
	if r.emit != nil {
		r.emit("process_exec", payload)
	}

	if r.dispatcher != nil {
		raw := exechandler.RawExecEvent{
			PID:         ev.PID,
			PPID:        ev.PPID,
			Comm:        comm,
			Exe:         exePath,
			Args:        cmdlineArgs,
			SessionID:   sessionID,
			Role:        role,
			AISessionID: tracker.GetSessionID(ev.PID),
			Blocked:     wasBlocked,
		}
		r.handler.Handle(raw)
	}
}

func (r *ExecRunner) handleStop(ev ProcEvent, tracker *lineage.LineageTracker) {
	if !tracker.IsAI(ev.PID) {
		return
	}

	if r.dispatcher != nil {
		ts := time.Now()
		exitEvt := event.Event{
			SchemaVersion: 1,
			Type:          "process_exit",
			Timestamp:     ts,
			HostID:        r.hostID,
			Source:        "etw_kernel_process",
			Actor: &event.Actor{
				PID:       int(ev.PID),
				SessionID: strconv.FormatUint(uint64(procinfo.DetectSessionID(ev.PID)), 10),
			},
		}
		exitEvt.ID = event.GenerateID(
			r.hostID, ts.UnixNano(),
			exitEvt.Source, exitEvt.Type,
			exitEvt.Actor.PID, "",
		)
		r.dispatcher.Enqueue(exitEvt)
	}

	tracker.UnregisterProcess(ev.PID)
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

// isValidCmdline checks if the cmdline args contain valid text (not garbled PEB data).
// Garbled PEB reads produce strings with CJK/Korean characters that are clearly not
// real command-line arguments.
func isValidCmdline(args []string) bool {
	for _, arg := range args {
		for _, r := range arg {
			// Control chars (except tab/newline) or characters above Latin Extended
			// that aren't in common Windows paths indicate garbled data
			if r > 0x024F && r < 0xFFFD {
				// CJK, Korean, Arabic, etc. — not valid in Windows command lines
				return false
			}
			if r < 0x20 && r != '\t' && r != '\n' && r != '\r' {
				return false
			}
		}
	}
	return true
}

// splitCmdline splits a Windows command line string into arguments.
// Handles quoted arguments with spaces (e.g., "C:\Program Files\foo.exe" -bar).
func splitCmdline(cmdline string) []string {
	var args []string
	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return nil
	}

	var current strings.Builder
	inQuote := false
	for i := 0; i < len(cmdline); i++ {
		c := cmdline[i]
		switch {
		case c == '"':
			inQuote = !inQuote
		case c == ' ' && !inQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteByte(c)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}
	return args
}

// redactCmdline masks sensitive values in command line arguments.
// Preserves command structure and flag names — only the secret values are replaced.
//
// Examples:
//   PGPASSWORD=correlic psql → PGPASSWORD=*** psql
//   --password=secret       → --password=***
//   --token=abc123          → --token=***
//   -H "Authorization: Bearer sk-xxx" → -H "Authorization: Bearer ***"
func redactCmdline(args []string) []string {
	redacted := make([]string, len(args))
	copy(redacted, args)

	for i, arg := range redacted {
		// Pattern 1: KEY=VALUE env var assignments (first tokens before the binary)
		// e.g., PGPASSWORD=correlic, AWS_SECRET_ACCESS_KEY=abc123
		if idx := strings.Index(arg, "="); idx > 0 && !strings.HasPrefix(arg, "-") {
			key := arg[:idx]
			if isSensitiveKey(key) {
				redacted[i] = key + "=***"
				continue
			}
		}

		// Pattern 2: --flag=VALUE long flags
		// e.g., --password=secret, --token=abc, --api-key=sk-123
		if strings.HasPrefix(arg, "--") {
			if idx := strings.Index(arg, "="); idx > 0 {
				flag := arg[2:idx]
				if isSensitiveKey(flag) {
					redacted[i] = arg[:idx+1] + "***"
					continue
				}
			}
		}

		// Pattern 3: "Authorization: Bearer xxx" or "Authorization: Basic xxx"
		lower := strings.ToLower(arg)
		if strings.Contains(lower, "authorization:") {
			if idx := strings.Index(lower, "bearer "); idx >= 0 {
				redacted[i] = arg[:idx+7] + "***"
			} else if idx := strings.Index(lower, "basic "); idx >= 0 {
				redacted[i] = arg[:idx+6] + "***"
			}
		}
	}
	return redacted
}

// redactCmdlineStr redacts a single command line string (not split into args).
func redactCmdlineStr(cmdline string) string {
	args := splitCmdline(cmdline)
	redacted := redactCmdline(args)
	return strings.Join(redacted, " ")
}

// isSensitiveKey checks if a key/flag name likely contains a credential.
func isSensitiveKey(key string) bool {
	lower := strings.ToLower(key)
	for _, s := range []string{
		"password", "passwd", "secret", "token",
		"credential", "auth", "apikey", "api_key",
		"api-key", "access_key", "access-key",
	} {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
