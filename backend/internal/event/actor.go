package event

// ActorStruct is the process context (PID, PPID, ExePath, etc.). Matches the agent's Actor struct 1:1.
// JSON key "actor". Exported name avoids "Actor redeclared in this block" with Event.Process *ActorStruct.
type ActorStruct struct {
	PID       int      `json:"pid"`
	PPID      int      `json:"ppid"`
	User      string   `json:"user,omitempty"`
	ExePath   string   `json:"exe_path,omitempty"`
	Comm      string   `json:"comm,omitempty"`
	Cmdline   []string `json:"cmdline,omitempty"`
	SessionID string   `json:"session_id,omitempty"`
	Role      string   `json:"role,omitempty"` // agent, shell, tool
}
