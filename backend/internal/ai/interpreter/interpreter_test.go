package interpreter

import (
	"errors"
	"testing"
	"time"
)

func TestInterpret_LastMinute(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	toolName, params, err := Interpret("What processes ran in the last minute?", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	if params.Since.Before(now.Add(-2*time.Minute)) || params.Since.After(now.Add(-1*time.Minute)) {
		t.Errorf("since = %v, expected now − 1 minute (around %v)", params.Since, now.Add(-1*time.Minute))
	}
	if params.Until != now {
		t.Errorf("until = %v, expected %v", params.Until, now)
	}
	_ = toolName
}

func TestInterpret_LastFiveMinutes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	_, params, err := Interpret("Processes in the last 5 minutes", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	wantSince := now.Add(-5 * time.Minute)
	if params.Since.Before(wantSince.Add(-time.Second)) || params.Since.After(wantSince.Add(time.Second)) {
		t.Errorf("since = %v, expected ~%v", params.Since, wantSince)
	}
}

func TestInterpret_UnparsedMinutePhrase_ReturnsError(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	_, _, err := Interpret("What ran in the last few minutes?", "host-1", now)
	if err == nil {
		t.Fatal("expected error when 'minute' is present but phrase unparsed")
	}
	if !errors.Is(err, ErrUnparsedTimePhrase) {
		t.Errorf("expected ErrUnparsedTimePhrase, got %v", err)
	}
}

func TestInterpret_NoTimePhrase_UsesDefault(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	_, params, err := Interpret("What processes ran?", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	// Default is last 24h
	wantSince := now.Add(-24 * time.Hour)
	if params.Since.Before(wantSince.Add(-time.Second)) || params.Since.After(wantSince.Add(time.Second)) {
		t.Errorf("since = %v, expected default ~%v", params.Since, wantSince)
	}
}

func TestInterpret_LastHour(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	_, params, err := Interpret("What ran in the last hour?", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	wantSince := now.Add(-1 * time.Hour)
	if params.Since.Before(wantSince.Add(-time.Second)) || params.Since.After(wantSince.Add(time.Second)) {
		t.Errorf("since = %v, expected ~%v", params.Since, wantSince)
	}
}

func TestInterpret_Today(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	_, params, err := Interpret("What happened today?", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	startOfDay := time.Date(2026, 2, 5, 0, 0, 0, 0, time.UTC)
	if !params.Since.Equal(startOfDay) {
		t.Errorf("since = %v, expected start of day %v", params.Since, startOfDay)
	}
}

func TestInterpret_UnparsedHourPhrase_ReturnsError(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	_, _, err := Interpret("What ran in the last few hours?", "host-1", now)
	if err == nil {
		t.Fatal("expected error when 'hour' is present but phrase unparsed")
	}
	if !errors.Is(err, ErrUnparsedTimePhrase) {
		t.Errorf("expected ErrUnparsedTimePhrase, got %v", err)
	}
}

func TestInterpret_WindowTooLarge_ReturnsError(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 7, 5, 0, time.UTC)
	_, _, err := Interpret("What ran in the last 7 days?", "host-1", now)
	if err == nil {
		t.Fatal("expected error when window > 24h")
	}
	var windowErr *ErrWindowTooLarge
	if !errors.As(err, &windowErr) {
		t.Errorf("expected ErrWindowTooLarge, got %v", err)
	}
	if windowErr.Window != 7*24*time.Hour {
		t.Errorf("expected window 168h, got %v", windowErr.Window)
	}
}

func TestInterpret_WhatChanged_ReturnsDiffTool(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 0, 0, 0, time.UTC)
	toolName, params, err := Interpret("What changed since yesterday?", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	if toolName != "diff_processes" {
		t.Errorf("toolName = %q want diff_processes (default diff tool)", toolName)
	}
	// Default diff windows: base now-2h → now-1h, compare now-1h → now
	wantBaseSince := now.Add(-2 * time.Hour)
	wantBaseUntil := now.Add(-1 * time.Hour)
	wantCompareSince := now.Add(-1 * time.Hour)
	wantCompareUntil := now
	if params.BaseSince.Before(wantBaseSince.Add(-time.Second)) || params.BaseSince.After(wantBaseSince.Add(time.Second)) {
		t.Errorf("BaseSince = %v want ~%v", params.BaseSince, wantBaseSince)
	}
	if params.BaseUntil.Before(wantBaseUntil.Add(-time.Second)) || params.BaseUntil.After(wantBaseUntil.Add(time.Second)) {
		t.Errorf("BaseUntil = %v want ~%v", params.BaseUntil, wantBaseUntil)
	}
	if params.CompareSince.Before(wantCompareSince.Add(-time.Second)) || params.CompareSince.After(wantCompareSince.Add(time.Second)) {
		t.Errorf("CompareSince = %v want ~%v", params.CompareSince, wantCompareSince)
	}
	if params.CompareUntil.Before(wantCompareUntil.Add(-time.Second)) || params.CompareUntil.After(wantCompareUntil.Add(time.Second)) {
		t.Errorf("CompareUntil = %v want ~%v", params.CompareUntil, wantCompareUntil)
	}
}

func TestInterpret_WhatChanged_Connections_ReturnsDiffConnections(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 0, 0, 0, time.UTC)
	toolName, _, err := Interpret("What connections changed compared to last hour?", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	if toolName != "diff_connections" {
		t.Errorf("toolName = %q want diff_connections", toolName)
	}
}

func TestInterpret_DifferenceBetweenPorts_ReturnsDiffPorts(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 2, 5, 15, 0, 0, 0, time.UTC)
	toolName, _, err := Interpret("Difference between open ports in the last two hours?", "host-1", now)
	if err != nil {
		t.Fatalf("Interpret: %v", err)
	}
	if toolName != "diff_ports" {
		t.Errorf("toolName = %q want diff_ports", toolName)
	}
}
