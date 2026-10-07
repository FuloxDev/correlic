//go:build linux

// Package ebpf provides port tracking with open/close lifecycle management.
package ebpf

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
)

// PortState represents the current state of an open port.
type PortState struct {
	Port       uint16    `json:"port"`
	BindAddr   string    `json:"bind_addr"`
	Family     string    `json:"family"`
	PID        uint32    `json:"pid"`
	Comm       string    `json:"comm"`
	ParentComm string    `json:"pcomm"`
	UID        uint32    `json:"uid"`
	OpenedAt   time.Time `json:"opened_at"`
	Risk       string    `json:"risk"`
	IsExposed  bool      `json:"is_exposed"`
}

// PortTracker maintains state of open ports and emits lifecycle events.
type PortTracker struct {
	bindCollector *BindCollector
	emit          collect.EventSink
	logger        *slog.Logger

	// State management
	mu       sync.RWMutex
	ports    map[portKey]*PortState // Currently open ports
	pidPorts map[uint32][]portKey   // Ports by PID for cleanup on exit
}

// portKey uniquely identifies a port binding
type portKey struct {
	Port   uint16
	Addr   string
	Family uint16
}

// NewPortTracker creates a new port tracker with state management.
func NewPortTracker(emit collect.EventSink, logger *slog.Logger) (*PortTracker, error) {
	if logger == nil {
		logger = slog.Default()
	}

	collector, err := NewBindCollector(logger)
	if err != nil {
		return nil, err
	}

	return &PortTracker{
		bindCollector: collector,
		emit:          emit,
		logger:        logger,
		ports:         make(map[portKey]*PortState),
		pidPorts:      make(map[uint32][]portKey),
	}, nil
}

// Start begins tracking ports and emitting events.
func (t *PortTracker) Start(ctx context.Context) {
	// Start the underlying collector
	go t.bindCollector.Start(ctx)

	// Start periodic summary emissions
	go t.emitPeriodicSummary(ctx)

	// Start process exit watcher (to detect port closures)
	go t.watchProcessExits(ctx)

	t.logger.Info("port tracker started")

	// Baseline snapshot: if the agent starts after services have already bound ports,
	// eBPF won't see those historical bind() calls. Emit a one-time best-effort summary
	// using `ss` so the UI has useful "Active Ports" immediately.
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(1 * time.Second):
		}
		t.emitBaselineSummaryOnce()
	}()

	for {
		select {
		case <-ctx.Done():
			t.logger.Info("port tracker stopping")
			t.bindCollector.Close()
			return
		case event := <-t.bindCollector.Events():
			t.handleBindEvent(event)
		}
	}
}

var ssUsersRegex = regexp.MustCompile(`\(\s*"([^"]+)"\s*,\s*pid=(\d+)`)

func (t *PortTracker) emitBaselineSummaryOnce() {
	if t == nil {
		return
	}
	if _, err := exec.LookPath("ss"); err != nil {
		t.logger.Warn("ports baseline skipped (ss not found)", "error", err)
		return
	}

	// -H: no header, -l: listening, -n: numeric, -t/-u: tcp/udp, -p: show process
	out, err := exec.Command("ss", "-Hlnptu").CombinedOutput()
	if err != nil {
		t.logger.Warn("ports baseline failed (ss exec)", "error", err, "output", string(out))
		return
	}

	lines := strings.Split(string(out), "\n")
	ports := make([]map[string]any, 0, 64)

	now := time.Now()
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		// Typical ss format: Netid State Recv-Q Send-Q Local:Port Peer:Port Process
		if len(fields) < 5 {
			continue
		}

		// Best-effort local address is usually at index 3 or 4 depending on ss version.
		// We'll scan for the first token that looks like it contains a port.
		local := ""
		for i := 0; i < len(fields); i++ {
			if strings.HasPrefix(fields[i], "users:") {
				continue
			}
			if strings.Contains(fields[i], "]:") || strings.Count(fields[i], ":") >= 1 {
				local = fields[i]
				if i >= 3 {
					break
				}
			}
		}
		if local == "" {
			continue
		}

		addr, port, fam, ok := parseSSLocal(local)
		if !ok || port == 0 {
			continue
		}

		comm, pid := parseSSProcess(line)

		isWildcard := addr == "0.0.0.0" || addr == "::"
		// Keep this as "expected": UI normalizes into low/medium based on exposure.
		risk := "expected"

		ports = append(ports, map[string]any{
			"port":       port,
			"bind_addr":  addr,
			"family":     fam,
			"comm":       comm,
			"pcomm":      "",
			"pid":        pid,
			"uid":        0,
			"opened_at":  now.Unix(),
			"uptime_sec": 0,
			"risk":       risk,
			"is_exposed": isWildcard,
		})
	}

	if len(ports) == 0 {
		t.logger.Debug("ports baseline: no listeners found")
		return
	}

	// Emit compat net_bind events so existing UI/stats still show ports even when
	// binds happened before the agent started.
	for _, p := range ports {
		t.emit("net_bind", map[string]any{
			"pid":        p["pid"],
			"ppid":       0,
			"uid":        p["uid"],
			"bind_addr":  p["bind_addr"],
			"bind_port":  p["port"],
			"family":     p["family"],
			"comm":       p["comm"],
			"pcomm":      p["pcomm"],
			"source":     "baseline",
			"is_exposed": p["is_exposed"],
			"risk":       p["risk"],
		})
	}

	t.emit("port_lifecycle", map[string]any{
		"event":      "summary",
		"open_count": len(ports),
		"ports":      ports,
		"source":     "baseline",
	})
}

func parseSSProcess(line string) (comm string, pid uint32) {
	m := ssUsersRegex.FindStringSubmatch(line)
	if len(m) != 3 {
		return "", 0
	}
	comm = m[1]
	n, err := strconv.ParseUint(m[2], 10, 32)
	if err != nil {
		return comm, 0
	}
	return comm, uint32(n)
}

func parseSSLocal(local string) (addr string, port uint16, family string, ok bool) {
	// Examples:
	// - 0.0.0.0:51234
	// - 127.0.0.1:3000
	// - [::]:8080
	// - [::1]:5353
	// - *:80
	local = strings.TrimSpace(local)
	local = strings.TrimRight(local, ",")

	if strings.HasPrefix(local, "[") {
		// [addr]:port
		end := strings.LastIndex(local, "]:")
		if end <= 0 || end+2 >= len(local) {
			return "", 0, "", false
		}
		a := local[1:end]
		p := local[end+2:]
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || n > 65535 {
			return "", 0, "", false
		}
		if a == "" || a == "*" {
			a = "::"
		}
		return a, uint16(n), "ipv6", true
	}

	// addr:port (IPv4 or wildcard "*:port")
	i := strings.LastIndex(local, ":")
	if i <= 0 || i+1 >= len(local) {
		return "", 0, "", false
	}
	a := local[:i]
	p := local[i+1:]
	n, err := strconv.Atoi(p)
	if err != nil || n < 0 || n > 65535 {
		return "", 0, "", false
	}
	if a == "" || a == "*" {
		a = "0.0.0.0"
	}
	return a, uint16(n), "ipv4", true
}

// handleBindEvent processes a bind event and updates state.
func (t *PortTracker) handleBindEvent(event BindEvent) {
	// Ignore port 0 ("kernel picks ephemeral") — it's not a meaningful listener for users.
	if event.Port == 0 {
		return
	}

	key := portKey{
		Port:   event.Port,
		Addr:   event.BindAddr(),
		Family: event.Family,
	}

	state := &PortState{
		Port:       event.Port,
		BindAddr:   event.BindAddr(),
		Family:     familyToString(event.Family),
		PID:        event.PID,
		Comm:       event.Comm,
		ParentComm: event.ParentComm,
		UID:        event.UID,
		OpenedAt:   time.Now(),
		Risk:       categorizeBind(event),
		// Keep this conservative; UI does finer-grained exposure/scope tags.
		IsExposed: event.IsWildcard(),
	}

	t.mu.Lock()
	// Check if this is a rebind (port was already tracked)
	if existing, ok := t.ports[key]; ok {
		// Port was rebound - emit close for old, open for new
		t.mu.Unlock()
		t.emitPortClosed(existing, "rebind", event.Comm)
		t.mu.Lock()
	}

	t.ports[key] = state
	t.pidPorts[event.PID] = append(t.pidPorts[event.PID], key)
	t.mu.Unlock()

	// Also emit raw bind telemetry for consumers that still rely on net_bind.
	t.emit("net_bind", map[string]any{
		"pid":        event.PID,
		"ppid":       event.PPID,
		"uid":        event.UID,
		"bind_addr":  event.BindAddr(),
		"bind_port":  event.Port,
		"family":     familyToString(event.Family),
		"comm":       event.Comm,
		"pcomm":      event.ParentComm,
		"source":     "ebpf",
		"is_exposed": event.IsWildcard(),
		"risk":       state.Risk,
	})

	// Emit port opened event
	t.emitPortOpened(state)
}

// emitPortOpened sends a port_open event.
func (t *PortTracker) emitPortOpened(state *PortState) {
	payload := map[string]any{
		"event":      "opened",
		"port":       state.Port,
		"bind_addr":  state.BindAddr,
		"family":     state.Family,
		"pid":        state.PID,
		"comm":       state.Comm,
		"pcomm":      state.ParentComm,
		"uid":        state.UID,
		"opened_at":  state.OpenedAt.Unix(),
		"risk":       state.Risk,
		"is_exposed": state.IsExposed,
		"source":     "ebpf",
	}

	t.emit("port_lifecycle", payload)
	t.logger.Debug("port opened", "port", state.Port, "addr", state.BindAddr, "comm", state.Comm)
}

// emitPortClosed sends a port_close event.
func (t *PortTracker) emitPortClosed(state *PortState, reason, closedBy string) {
	duration := time.Since(state.OpenedAt)

	payload := map[string]any{
		"event":        "closed",
		"port":         state.Port,
		"bind_addr":    state.BindAddr,
		"family":       state.Family,
		"pid":          state.PID,
		"comm":         state.Comm,
		"pcomm":        state.ParentComm,
		"opened_at":    state.OpenedAt.Unix(),
		"closed_at":    time.Now().Unix(),
		"duration_sec": int(duration.Seconds()),
		"reason":       reason, // "process_exit", "rebind", "manual"
		"closed_by":    closedBy,
		"risk":         state.Risk,
		"source":       "ebpf",
	}

	t.emit("port_lifecycle", payload)
	t.logger.Debug("port closed", "port", state.Port, "reason", reason, "duration", duration)
}

// emitPeriodicSummary sends a summary of all open ports every interval.
func (t *PortTracker) emitPeriodicSummary(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.mu.RLock()
			if len(t.ports) == 0 {
				t.mu.RUnlock()
				continue
			}

			ports := make([]map[string]any, 0, len(t.ports))
			for _, state := range t.ports {
				ports = append(ports, map[string]any{
					"port":       state.Port,
					"bind_addr":  state.BindAddr,
					"family":     state.Family,
					"comm":       state.Comm,
					"pcomm":      state.ParentComm,
					"pid":        state.PID,
					"uid":        state.UID,
					"opened_at":  state.OpenedAt.Unix(),
					"uptime_sec": int(time.Since(state.OpenedAt).Seconds()),
					"risk":       state.Risk,
					"is_exposed": state.IsExposed,
				})
			}
			t.mu.RUnlock()

			payload := map[string]any{
				"event":      "summary",
				"open_count": len(ports),
				"ports":      ports,
				"source":     "ebpf",
			}

			t.emit("port_lifecycle", payload)
		}
	}
}

// watchProcessExits monitors for process exits to detect port closures.
// This is a simplified approach - checks if tracked PIDs are still alive.
func (t *PortTracker) watchProcessExits(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.checkDeadProcesses()
		}
	}
}

// checkDeadProcesses removes ports from processes that no longer exist.
func (t *PortTracker) checkDeadProcesses() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for pid, keys := range t.pidPorts {
		if !processExists(pid) {
			// Process is dead, close all its ports
			for _, key := range keys {
				if state, ok := t.ports[key]; ok {
					// Emit close event (unlock temporarily)
					t.mu.Unlock()
					t.emitPortClosed(state, "process_exit", state.Comm)
					t.mu.Lock()
					delete(t.ports, key)
				}
			}
			delete(t.pidPorts, pid)
		}
	}
}

// processExists checks if a process with the given PID exists.
func processExists(pid uint32) bool {
	// Check /proc/<pid>/stat exists
	path := "/proc/" + itoa(pid) + "/stat"
	_, err := os.Stat(path)
	return err == nil
}

// GetOpenPorts returns a snapshot of currently open ports.
func (t *PortTracker) GetOpenPorts() []*PortState {
	t.mu.RLock()
	defer t.mu.RUnlock()

	ports := make([]*PortState, 0, len(t.ports))
	for _, state := range t.ports {
		// Copy to avoid race
		cp := *state
		ports = append(ports, &cp)
	}
	return ports
}

// Close releases resources.
func (t *PortTracker) Close() error {
	if t.bindCollector != nil {
		return t.bindCollector.Close()
	}
	return nil
}

// itoa converts uint32 to string
func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
