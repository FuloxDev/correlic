package query

import "time"

// MaxResults is the hard cap for list query results. Responses set Truncated when hit.
const MaxResults = 200

// ContainerStartRow is one container_start event for list responses.
type ContainerStartRow struct {
	ID           string    `json:"id"`
	HostID       string    `json:"host_id"`
	Timestamp    time.Time `json:"timestamp"`
	ContainerID  string    `json:"container_id,omitempty"`
	ContainerImg string    `json:"container_img,omitempty"`
	ProcessPID   int       `json:"process_pid,omitempty"`
}

// OpenPortRow is one net_listen event for list responses.
type OpenPortRow struct {
	ID         string    `json:"id"`
	HostID     string    `json:"host_id"`
	Timestamp  time.Time `json:"timestamp"`
	Port       int       `json:"port,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	ProcessPID int       `json:"process_pid,omitempty"`
	ExePath    string    `json:"exe_path,omitempty"`
}

// ExternalConnectionRow is one net_connect event for list responses.
type ExternalConnectionRow struct {
	ID         string    `json:"id"`
	HostID     string    `json:"host_id"`
	Timestamp  time.Time `json:"timestamp"`
	IP         string    `json:"ip,omitempty"`
	Port       int       `json:"port,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	ProcessPID int       `json:"process_pid,omitempty"`
	ExePath    string    `json:"exe_path,omitempty"`
}

// InboundConnectionRow is one net_accept event for list responses (who connected to this host).
type InboundConnectionRow struct {
	ID         string    `json:"id"`
	HostID     string    `json:"host_id"`
	Timestamp  time.Time `json:"timestamp"`
	IP         string    `json:"ip,omitempty"`
	Port       int       `json:"port,omitempty"`
	Protocol   string    `json:"protocol,omitempty"`
	ProcessPID int       `json:"process_pid,omitempty"`
	ExePath    string    `json:"exe_path,omitempty"`
}

// ProcessByExecutableRow is one process_exec event matching an executable pattern.
type ProcessByExecutableRow struct {
	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	Timestamp time.Time `json:"timestamp"`
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	ExePath   string    `json:"exe_path,omitempty"`
	ExecClass string    `json:"exec_class,omitempty"` // primary | helper | shell | runtime | unknown (from context)
}

// ExecRow is one process_exec event (e.g. for ListPrimaryExecs).
type ExecRow struct {
	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	Timestamp time.Time `json:"timestamp"`
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	ExePath   string    `json:"exe_path,omitempty"`
}

// ProcessExitRow is one process_exit event for lifecycle and correlation.
type ProcessExitRow struct {
	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	Timestamp time.Time `json:"timestamp"`
	PID       int       `json:"pid"`
	PPID      int       `json:"ppid"`
	ExitCode  int       `json:"exit_code"`
}

// ProcessStats contains aggregated activity counts for a process
type ProcessStats struct {
	FilesAccessed   int `json:"files_accessed"`
	Connections     int `json:"connections"`
	SecretsAccessed int `json:"secrets_accessed"`
	PortsOpened     int `json:"ports_opened"`
	ChildCount      int `json:"child_count"`
	EventCount      int `json:"event_count"`
}

// ProcessNode represents a process with its activity and children for the timeline view
type ProcessNode struct {
	PID        int            `json:"pid"`
	PPID       int            `json:"ppid"`
	Comm       string         `json:"comm"`
	Role       string         `json:"role,omitempty"`
	ExePath    string         `json:"exe_path"`
	Cmdline    string         `json:"cmdline,omitempty"`
	User       string         `json:"user,omitempty"`
	HostID     string         `json:"host_id"`
	StartedAt  time.Time      `json:"started_at"`
	LastSeenAt time.Time      `json:"last_seen_at"`
	DurationMs int64          `json:"duration_ms"`
	AIType     string         `json:"ai_type,omitempty"` // null if not AI process
	AIRoot     string         `json:"ai_root,omitempty"` // event ID of the originating AI agent
	Stats      ProcessStats   `json:"stats"`
	Children   []*ProcessNode `json:"children,omitempty"`
}

// ProcessTreeResponse is the response for /api/processes/tree
type ProcessTreeResponse struct {
	Processes   []*ProcessNode `json:"processes"`
	TotalCount  int            `json:"total_count"`
	WindowStart time.Time      `json:"window_start"`
	WindowEnd   time.Time      `json:"window_end"`
}

// --- Agent Activity Stream types ---

// AgentAction represents a single meaningful action taken by an AI agent.
type AgentAction struct {
	Timestamp    time.Time `json:"timestamp"`
	Category     string    `json:"category"`     // "file", "network", "command", "dns"
	Action       string    `json:"action"`       // human-readable: "Edited timeline.go"
	Detail       string    `json:"detail"`       // raw path/IP/command
	Significance int       `json:"significance"` // 1-5 score
	EventID      string    `json:"event_id"`
	EventType    string    `json:"event_type"`             // original event type
	ProcessPID   int       `json:"process_pid,omitempty"`  // actor PID
	ProcessComm  string    `json:"process_comm,omitempty"` // actor comm (process name)
}

// AgentStats contains aggregated counts for an agent's activity.
type AgentStats struct {
	FilesModified int `json:"files_modified"`
	FilesRead     int `json:"files_read"`
	CommandsRun   int `json:"commands_run"`
	Connections   int `json:"connections"`
	DNSLookups    int `json:"dns_lookups"`
	TotalEvents   int `json:"total_events"`
}

// AgentSummary groups all actions and stats for one AI agent.
type AgentSummary struct {
	AgentName  string        `json:"agent_name"`
	AgentPID   int           `json:"agent_pid"`
	AIType     string        `json:"ai_type"`
	HostID     string        `json:"host_id"`
	ExePath    string        `json:"exe_path,omitempty"`
	StartedAt  time.Time     `json:"started_at"`
	Duration   string        `json:"duration"`
	Actions    []AgentAction `json:"actions"`
	Stats      AgentStats    `json:"stats"`
	ChildCount int           `json:"child_count"`
}

// AgentActivityResponse is the response for /agents/activity.
type AgentActivityResponse struct {
	Agents      []AgentSummary `json:"agents"`
	WindowStart time.Time      `json:"window_start"`
	WindowEnd   time.Time      `json:"window_end"`
}
