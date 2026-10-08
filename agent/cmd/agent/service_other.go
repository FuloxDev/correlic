//go:build !windows

package main

import "log/slog"

func handleServiceCommand(_ *slog.Logger, _ []string) bool { return false }
func runAsService(_ *slog.Logger, _ string)                {}
