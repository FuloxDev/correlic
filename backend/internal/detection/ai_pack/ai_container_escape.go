package ai_pack

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/correlic/correlic-backend/internal/detection"
)

// containerEscapeCriticalPaths are exact file paths that represent container escape vectors.
var containerEscapeCriticalPaths = map[string]bool{
	"/var/run/docker.sock":     true, // Docker socket — full container control
	"/run/docker.sock":         true, // Alternate Docker socket path
	"/var/run/containerd.sock": true, // containerd socket
	"/run/containerd.sock":     true, // Alternate containerd path
	"/var/run/crio.sock":       true, // CRI-O socket
	"/proc/sysrq-trigger":      true, // Kernel sysrq — can crash/reboot host
	"/proc/kcore":              true, // Kernel memory — read host memory
}

// containerEscapeCriticalDirs are directory prefixes for container escape.
var containerEscapeCriticalDirs = []string{
	"/proc/1/",         // Host PID 1 namespace — accessing init proc from container
	"/host/",           // Common host mount convention
	"/rootfs/",         // Host root filesystem mount
	"/mnt/host/",       // Another common host mount
	"/hostroot/",       // Alternative host mount
	"/sys/fs/cgroup/",  // Cgroup manipulation for escape
}

// containerEscapeHighPaths are file paths representing high-severity escape vectors.
var containerEscapeHighPaths = map[string]bool{
	"/proc/self/ns/mnt":  true, // Mount namespace escape
	"/proc/self/ns/pid":  true, // PID namespace escape
	"/proc/self/ns/net":  true, // Network namespace escape
	"/proc/self/ns/user": true, // User namespace escape
}

// containerEscapeExecBinaries are binaries that indicate container escape when run by AI.
var containerEscapeExecBinaries = map[string]bool{
	"runc":        true, // Container runtime — direct escape tool
	"ctr":         true, // containerd CLI
	"crictl":      true, // CRI CLI
	"docker":      true, // Docker CLI from within container
	"kubectl":     true, // Kubernetes CLI — potential cluster escape
	"kubelet":     true, // Kubelet — node-level access
}

// AIContainerEscape detects AI agent attempts to escape container isolation.
type AIContainerEscape struct{}

func (d *AIContainerEscape) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.container_escape",
		Pack:            "ai",
		Name:            "AI Container Escape",
		Severity:        "critical",
		Description:     "AI agent attempted to escape container isolation via socket access, namespace manipulation, or host filesystem mount",
		Tags:            []string{"ai", "container-escape", "breakout"},
		MITRETechniques: []string{"T1611", "T1610", "T1613"},
	}
}

func (d *AIContainerEscape) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"file_open", "process_exec"},
		WindowSecs: 0,
	}
}

func (d *AIContainerEscape) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil {
		return nil
	}

	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	switch evt.Type {
	case "file_open":
		return d.evaluateFileOpen(ctx, aiType)
	case "process_exec":
		return d.evaluateExec(ctx, aiType)
	default:
		return nil
	}
}

func (d *AIContainerEscape) evaluateFileOpen(ctx *detection.EvalContext, aiType string) []detection.Finding {
	evt := ctx.Event
	if evt.Target == nil || evt.Target.FilePath == "" {
		return nil
	}

	filePath := evt.Target.FilePath
	basename := filepath.Base(filePath)

	var severity string
	var confidence float64
	var escapeType string

	switch {
	// Critical: container runtime sockets and kernel interfaces
	case containerEscapeCriticalPaths[filePath]:
		severity = "critical"
		confidence = 0.95
		escapeType = "runtime_socket"
		if strings.Contains(filePath, "sysrq") || strings.Contains(filePath, "kcore") {
			escapeType = "kernel_interface"
		}

	// Critical: host filesystem / cgroup paths
	case matchesAnyPrefix(filePath, containerEscapeCriticalDirs):
		severity = "critical"
		confidence = 0.90
		escapeType = "host_filesystem"
		if strings.Contains(filePath, "cgroup") {
			escapeType = "cgroup_escape"
		}

	// Critical: cgroup release_agent (classic escape technique)
	case basename == "release_agent" && strings.Contains(filePath, "cgroup"):
		severity = "critical"
		confidence = 0.95
		escapeType = "cgroup_release_agent"

	// High: namespace file access
	case containerEscapeHighPaths[filePath]:
		severity = "high"
		confidence = 0.85
		escapeType = "namespace_access"

	// High: mounting block devices from within container
	case strings.HasPrefix(filePath, "/dev/sd") || strings.HasPrefix(filePath, "/dev/vd") ||
		strings.HasPrefix(filePath, "/dev/nvme") || strings.HasPrefix(filePath, "/dev/xvd"):
		severity = "high"
		confidence = 0.85
		escapeType = "block_device_access"

	default:
		return nil
	}

	title := fmt.Sprintf("AI agent container escape attempt: %s", escapeType)
	summary := fmt.Sprintf("%s accessed %s (%s)", aiType, filePath, escapeType)

	fctx := map[string]any{
		"ai_type":     aiType,
		"pid":         evt.Process.PID,
		"comm":        evt.Process.Comm,
		"file_path":   filePath,
		"escape_type": escapeType,
		"signal_type": "container_escape",
		"pattern":     filePath,
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}

	return []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Severity:   severity,
			Confidence: confidence,
			Context:    fctx,
		},
	}
}

func (d *AIContainerEscape) evaluateExec(ctx *detection.EvalContext, aiType string) []detection.Finding {
	evt := ctx.Event

	binaryName := ""
	if evt.Process.ExePath != "" {
		binaryName = filepath.Base(evt.Process.ExePath)
	}
	if binaryName == "" || binaryName == "." {
		binaryName = evt.Process.Comm
	}
	if binaryName == "" {
		return nil
	}

	if !containerEscapeExecBinaries[binaryName] {
		return nil
	}

	cmdline := ""
	if len(evt.Process.Cmdline) > 0 {
		cmdline = strings.Join(evt.Process.Cmdline, " ")
	}

	baselinePattern := binaryName
	if cmdline != "" && cmdline != binaryName {
		baselinePattern = truncate(cmdline, 200)
	}

	title := fmt.Sprintf("AI agent executed container management tool: %s", binaryName)
	summary := fmt.Sprintf("%s ran %s", aiType, binaryName)
	if cmdline != "" && cmdline != binaryName {
		summary = fmt.Sprintf("%s ran: %s", aiType, truncate(cmdline, 200))
	}

	fctx := map[string]any{
		"ai_type":     aiType,
		"binary":      binaryName,
		"cmdline":     cmdline,
		"pid":         evt.Process.PID,
		"ppid":        evt.Process.PPID,
		"escape_type": "container_tool",
		"signal_type": "binary",
		"pattern":     baselinePattern,
	}
	if evt.Process.SessionID != "" {
		fctx["session_id"] = evt.Process.SessionID
	}

	return []detection.Finding{
		{
			Title:      title,
			Summary:    summary,
			Severity:   "critical",
			Confidence: 0.90,
			Context:    fctx,
		},
	}
}
