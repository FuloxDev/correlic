package intelligence

import (
	"context"
	"log"
	"time"
)

type Rollup struct {
	store *Store
}

func NewRollup(store *Store) *Rollup {
	return &Rollup{store: store}
}

// RollupMinuteToHourly merges 60 x 1-min snapshots into a single 1-hr summary.
func (r *Rollup) RollupMinuteToHourly(ctx context.Context, orgID, hostID string, hourStart time.Time) error {
	hourEnd := hourStart.Add(1 * time.Hour)

	windows, err := r.store.GetWindowsForRollup(ctx, orgID, hostID, "1m", hourStart, hourEnd)
	if err != nil {
		return err
	}
	if len(windows) == 0 {
		return nil
	}

	merged := mergeSummaries(windows, 12) // 12 x 5-min slots for hourly
	return r.store.InsertContextWindow(ctx, orgID, hostID, "1h", hourStart, hourEnd, merged)
}

// RollupHourlyToDaily merges 24 x 1-hr summaries into a single 24-hr summary.
func (r *Rollup) RollupHourlyToDaily(ctx context.Context, orgID, hostID string, dayStart time.Time) error {
	dayEnd := dayStart.Add(24 * time.Hour)

	windows, err := r.store.GetWindowsForRollup(ctx, orgID, hostID, "1h", dayStart, dayEnd)
	if err != nil {
		return err
	}
	if len(windows) == 0 {
		return nil
	}

	merged := mergeSummaries(windows, 24) // 24 x 1-hr slots for daily
	return r.store.InsertContextWindow(ctx, orgID, hostID, "24h", dayStart, dayEnd, merged)
}

// RollupDailyToWeekly merges 7 x 24-hr summaries into a single weekly summary.
func (r *Rollup) RollupDailyToWeekly(ctx context.Context, orgID, hostID string, weekStart time.Time) error {
	weekEnd := weekStart.Add(7 * 24 * time.Hour)

	windows, err := r.store.GetWindowsForRollup(ctx, orgID, hostID, "24h", weekStart, weekEnd)
	if err != nil {
		return err
	}
	if len(windows) == 0 {
		return nil
	}

	merged := mergeSummaries(windows, 7) // 7 x day slots for weekly
	return r.store.InsertContextWindow(ctx, orgID, hostID, "weekly", weekStart, weekEnd, merged)
}

// Cleanup removes old context windows past their retention period.
func (r *Rollup) Cleanup(ctx context.Context) {
	now := time.Now()

	// 1-min: keep 1 hour
	if n, err := r.store.CleanupWindows(ctx, "1m", now.Add(-1*time.Hour)); err == nil && n > 0 {
		log.Printf("AI context cleanup: removed %d stale 1-min windows", n)
	}
	// 1-hr: keep 24 hours
	if n, err := r.store.CleanupWindows(ctx, "1h", now.Add(-24*time.Hour)); err == nil && n > 0 {
		log.Printf("AI context cleanup: removed %d stale 1-hr windows", n)
	}
	// 24-hr: keep 30 days
	if n, err := r.store.CleanupWindows(ctx, "24h", now.Add(-30*24*time.Hour)); err == nil && n > 0 {
		log.Printf("AI context cleanup: removed %d stale 24-hr windows", n)
	}
	// weekly: keep 1 year
	if n, err := r.store.CleanupWindows(ctx, "weekly", now.Add(-365*24*time.Hour)); err == nil && n > 0 {
		log.Printf("AI context cleanup: removed %d stale weekly windows", n)
	}
}

// mergeSummaries combines multiple ContextSummary windows into one.
func mergeSummaries(windows []ContextWindow, numSlots int) ContextSummary {
	merged := ContextSummary{
		EventSlots: make([]int, numSlots),
	}

	binSet := make(map[string]bool)
	destSet := make(map[string]bool)
	domainSet := make(map[string]bool)
	sensitiveSet := make(map[string]bool)
	newBinSet := make(map[string]bool)
	newDestSet := make(map[string]bool)
	pidSet := make(map[int]bool)

	for i, w := range windows {
		s := w.Summary

		// Aggregate counts
		merged.ProcessExecCount += s.ProcessExecCount
		merged.FileOpenCount += s.FileOpenCount
		merged.NetConnectCount += s.NetConnectCount
		merged.DNSQueryCount += s.DNSQueryCount
		merged.FindingsGenerated += s.FindingsGenerated
		merged.FindingsSuppressed += s.FindingsSuppressed
		merged.ReconCommands += s.ReconCommands
		merged.CredentialAccesses += s.CredentialAccesses

		// Union unique values
		for _, b := range s.UniqueBinaries {
			binSet[b] = true
		}
		for _, d := range s.UniqueDestinations {
			destSet[d] = true
		}
		for _, d := range s.UniqueDomains {
			domainSet[d] = true
		}
		for _, f := range s.SensitiveFiles {
			sensitiveSet[f] = true
		}
		for _, b := range s.NewBinaries {
			newBinSet[b] = true
		}
		for _, d := range s.NewDestinations {
			newDestSet[d] = true
		}
		for _, p := range s.ActivePIDs {
			pidSet[p] = true
		}

		// Map sub-window to parent slot
		if numSlots > 0 && len(windows) > 0 {
			slot := i * numSlots / len(windows)
			if slot >= numSlots {
				slot = numSlots - 1
			}
			totalEvents := s.ProcessExecCount + s.FileOpenCount + s.NetConnectCount + s.DNSQueryCount
			merged.EventSlots[slot] += totalEvents
		}

		// Carry over notable events
		merged.Notable = append(merged.Notable, s.Notable...)
		merged.ActiveSessions = append(merged.ActiveSessions, s.ActiveSessions...)
	}

	// Convert sets to slices
	for b := range binSet {
		merged.UniqueBinaries = append(merged.UniqueBinaries, b)
	}
	for d := range destSet {
		merged.UniqueDestinations = append(merged.UniqueDestinations, d)
	}
	for d := range domainSet {
		merged.UniqueDomains = append(merged.UniqueDomains, d)
	}
	for f := range sensitiveSet {
		merged.SensitiveFiles = append(merged.SensitiveFiles, f)
	}
	for b := range newBinSet {
		merged.NewBinaries = append(merged.NewBinaries, b)
	}
	for d := range newDestSet {
		merged.NewDestinations = append(merged.NewDestinations, d)
	}
	for p := range pidSet {
		merged.ActivePIDs = append(merged.ActivePIDs, p)
	}

	// Deduplicate sessions by session_id
	sessMap := make(map[string]SessionSummary)
	for _, s := range merged.ActiveSessions {
		if existing, ok := sessMap[s.SessionID]; ok {
			existing.FilesAccessed += s.FilesAccessed
			existing.NetworkConns += s.NetworkConns
			existing.CommandsRun = append(existing.CommandsRun, s.CommandsRun...)
			sessMap[s.SessionID] = existing
		} else {
			sessMap[s.SessionID] = s
		}
	}
	merged.ActiveSessions = nil
	for _, s := range sessMap {
		merged.ActiveSessions = append(merged.ActiveSessions, s)
	}

	// Truncate notable to last 20
	if len(merged.Notable) > 20 {
		merged.Notable = merged.Notable[len(merged.Notable)-20:]
	}

	return merged
}
