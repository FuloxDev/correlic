//go:build !darwin

package esevents

// lookupPPID has no Endpoint Security source to serve off macOS; the runners
// are only compiled here so they can be tested.
func lookupPPID(uint32) uint32 { return 0 }
