package intelligence

import "time"

// Layer 1: System Profile
type SystemProfile struct {
	Host struct {
		OS       string `json:"os"`
		Hostname string `json:"hostname"`
		User     string `json:"user"`
	} `json:"host"`
	AIAgents        []AgentInfo `json:"ai_agents"`
	NormalNetwork   []string    `json:"normal_network"`
	NormalBinaries  []string    `json:"normal_binaries"`
	InstalledTools  []string    `json:"installed_tools"`
	WorkingDirs     []string    `json:"working_dirs"`
	PathDirs        []string    `json:"path_dirs,omitempty"`
	BaselineSummary struct {
		FilePatterns int `json:"file_patterns"`
		NetworkDests int `json:"network_dests"`
		Binaries     int `json:"binaries"`
	} `json:"baseline_summary"`
}

type AgentInfo struct {
	Type        string `json:"type"`
	InstallPath string `json:"install_path"`
	FirstSeen   string `json:"first_seen"`
}

// Layer 2: Context Window
type ContextWindow struct {
	ID          int            `json:"id"`
	Granularity string         `json:"granularity"`
	WindowStart time.Time      `json:"window_start"`
	WindowEnd   time.Time      `json:"window_end"`
	Summary     ContextSummary `json:"summary"`
	CreatedAt   time.Time      `json:"created_at"`
}

type ContextSummary struct {
	// Event counts
	ProcessExecCount int `json:"process_exec_count"`
	FileOpenCount    int `json:"file_open_count"`
	NetConnectCount  int `json:"net_connect_count"`
	DNSQueryCount    int `json:"dns_query_count"`

	// Unique values (NEVER truncated — full lists)
	UniqueBinaries     []string `json:"unique_binaries"`
	UniqueDestinations []string `json:"unique_destinations"`
	UniqueDomains      []string `json:"unique_domains"`
	SensitiveFiles     []string `json:"sensitive_files,omitempty"`

	// Security signals
	FindingsGenerated  int      `json:"findings_generated"`
	FindingsSuppressed int      `json:"findings_suppressed"`
	ReconCommands      int      `json:"recon_commands"`
	CredentialAccesses int      `json:"credential_accesses"`
	NewBinaries        []string `json:"new_binaries,omitempty"`
	NewDestinations    []string `json:"new_destinations,omitempty"`

	// File access success/failure (for PATHEXT probe detection)
	FileExistsCount   int `json:"file_exists_count"`
	FileNotFoundCount int `json:"file_not_found_count"`

	// Temporal pattern — event counts per sub-slot
	// 1-min: 6 x 10-sec slots; 1-hr: 12 x 5-min slots; 24-hr: 24 x 1-hr slots
	EventSlots []int `json:"event_slots"`

	// Active processes and sessions (for drill-down reference)
	ActivePIDs     []int            `json:"active_pids,omitempty"`
	ActiveSessions []SessionSummary `json:"active_sessions,omitempty"`

	// Notable events (human-readable highlights)
	Notable []string `json:"notable,omitempty"`

	// Activity pattern classification (auto-detected)
	// Values: "active_development", "build_or_ci", "idle_with_background_network", "idle", "unknown"
	ActivityPattern string `json:"activity_pattern,omitempty"`
}

type SessionSummary struct {
	AIType        string   `json:"ai_type"`
	SessionID     string   `json:"session_id"`
	PID           int      `json:"pid"`
	CommandsRun   []string `json:"commands_run,omitempty"`
	FilesAccessed int      `json:"files_accessed"`
	NetworkConns  int      `json:"network_conns"`
}

// Layer 3: Learned Pattern
type LearnedPattern struct {
	ID         int       `json:"id"`
	PatternKey string    `json:"pattern_key"`
	Verdict    string    `json:"verdict"`
	Confidence float64   `json:"confidence"`
	Evidence   Evidence  `json:"evidence"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

type Evidence struct {
	Dismissed    int `json:"dismissed"`
	Investigated int `json:"investigated"`
	Blocked      int `json:"blocked"`
	Allowed      int `json:"allowed"`
	TotalSeen    int `json:"total_seen"`
}
