package event

type Actor struct {
	PID       int      `json:"pid"`
	PPID      int      `json:"ppid"`
	User      string   `json:"user"`
	ExePath   string   `json:"exe_path"`
	Cmdline   []string `json:"cmdline,omitempty"`
	Comm      string   `json:"comm,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	Role      string   `json:"role,omitempty"` // agent, shell, tool
}
