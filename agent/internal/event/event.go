package event

import "time"

type Event struct {
	SchemaVersion int `json:"schema_version"`

	ID        string    `json:"id"`
	HostID    string    `json:"host_id"`
	Timestamp time.Time `json:"timestamp"`

	Source string `json:"source"` // kernel, net, git, container
	Type   string `json:"type"`   // process_exec, net_connect, net_listen, etc.

	Actor  *Actor  `json:"actor,omitempty"`
	Target *Target `json:"target,omitempty"`

	// Context holds optional metadata. For Type == "process_exec", exec normalization may set:
	// exec_class (primary|helper|shell|runtime|unknown), exec_role (entrypoint|worker|fork|interpreter|ephemeral),
	// exec_normalized (bool), exec_group (e.g. bash, python). Omit for other types.
	Context map[string]any `json:"context,omitempty"`
}
