//go:build darwin && !esf

package main

import "context"

// startESF is a no-op in builds without the esf tag. Endpoint Security needs
// cgo, the macOS SDK's EndpointSecurity framework and a binary signed with
// the com.apple.developer.endpoint-security.client entitlement; see
// backend/docs/MACOS_ESF_SETUP.md for the build and the Apple side.
func startESF(context.Context, platformDeps) bool { return false }
