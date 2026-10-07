package dispatch

// DropReason is the reason an event was dropped (observability: metrics + logs).
type DropReason string

const (
	DropExecHelperBurst DropReason = "exec_helper_burst"
	DropExecEphemeral   DropReason = "exec_ephemeral"
)
