//go:build darwin

package enforcer

// descendantsOf returns no descendants on macOS: there is no /proc and the
// agent does not shell out to pgrep from the enforcement hot path, so a
// kill_tree rule kills the matched process only. Children that keep running
// are matched by their own events.
func descendantsOf(uint32) []uint32 { return nil }
