//go:build darwin && !esf

package main

import "context"

// startESF is a no-op in builds without the esf tag. Endpoint Security needs
// cgo, the macOS SDK and a binary signed with the
// com.apple.developer.endpoint-security.client entitlement, which the project
// does not hold; see backend/docs/MACOS_AGENT.md.
func startESF(context.Context, platformDeps) bool { return false }
