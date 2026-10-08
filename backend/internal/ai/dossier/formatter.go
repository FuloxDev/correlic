package dossier

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/incident"
)

const divider = "═══════════════════════════════════════════════════════════"

// FormatDossier converts DossierData into a human-readable text document.
// Never panics on nil inputs — all sections degrade gracefully.
func FormatDossier(d *DossierData) string {
	if d == nil || d.Detail == nil {
		return divider + "\nSECURITY INCIDENT DOSSIER — (no data)\n" + divider
	}

	detail := d.Detail
	inc := detail.Incident
	var b strings.Builder

	// ── Header ───────────────────────────────────────────────────────────────
	b.WriteString(divider + "\n")
	b.WriteString("SECURITY INCIDENT DOSSIER — " + inc.Title + "\n")
	b.WriteString(divider + "\n\n")

	// ── Overview ─────────────────────────────────────────────────────────────
	b.WriteString("OVERVIEW\n")
	b.WriteString(fmt.Sprintf("  Severity:    %s (confidence: %.0f%%)  |  Status: %s\n",
		inc.Severity, inc.Confidence*100, inc.Status))
	b.WriteString("  Host:        " + inc.HostID + "\n")

	// Time window
	started := inc.StartedAt.UTC()
	ended := inc.EndedAt.UTC()
	dur := ended.Sub(started)
	b.WriteString(fmt.Sprintf("  Time window: %s → %s UTC  (%s)\n",
		started.Format("2006-01-02 15:04:05"),
		ended.Format("2006-01-02 15:04:05"),
		formatDuration(dur)))

	// MITRE
	if len(inc.MITRETechniques) > 0 {
		b.WriteString("  MITRE:       " + strings.Join(inc.MITRETechniques, ", ") + "\n")
	} else {
		b.WriteString("  MITRE:       None identified\n")
	}

	// Detections count + chain info
	findingCount := len(inc.FindingIDs)
	chainInfo := ""
	if inc.ChainFindingID != "" {
		chainInfo = " [CHAIN ATTACK — chain finding: " + inc.ChainFindingID + "]"
	}
	b.WriteString(fmt.Sprintf("  Detections:  %d finding(s)%s\n", findingCount, chainInfo))
	b.WriteString("\n")

	// ── Attack Sequence ───────────────────────────────────────────────────────
	b.WriteString("ATTACK SEQUENCE (correlated from events)\n")
	b.WriteString(buildNarrative(detail) + "\n")
	b.WriteString("\n  NOTE: This narrative is derived from event timestamps and process relationships.\n")
	b.WriteString("  Causality between events is inferred, not confirmed.\n\n")

	// ── Process Chain ─────────────────────────────────────────────────────────
	b.WriteString("PROCESS CHAIN\n")
	if detail.ProcessTree != nil {
		renderProcessTree(&b, detail.ProcessTree, "", true)
	} else {
		b.WriteString("  Process tree unavailable (Neo4j unreachable at build time).\n")
	}
	b.WriteString("\n")

	// ── Process Details (grouped to reduce noise) ────────────────────────────
	if len(detail.ProcessDetails) > 0 {
		// Group processes by executable basename, show flagged/interesting ones in full
		type procGroup struct {
			exe    string
			pids   []int64
			detail *incident.ProcessDetail // first instance with cmdline/files/network
		}
		groups := make(map[string]*procGroup)
		var groupOrder []string
		var flaggedDetails []incident.ProcessDetail

		// Collect flagged process PIDs from process tree
		flaggedPIDs := make(map[int64]bool)
		if detail.ProcessTree != nil {
			collectFlaggedPIDs(detail.ProcessTree, flaggedPIDs)
		}

		for _, pd := range detail.ProcessDetails {
			baseName := filepath.Base(pd.Exe)
			if baseName == "" || baseName == "." {
				baseName = pd.Exe
			}

			// Processes with cmdline, files, network, or flagged — show in full
			isFlagged := flaggedPIDs[pd.PID]
			hasDetail := pd.Cmdline != "" || len(pd.Files) > 0 || len(pd.NetConns) > 0
			if isFlagged || hasDetail {
				flaggedDetails = append(flaggedDetails, pd)
			}

			g, exists := groups[baseName]
			if !exists {
				g = &procGroup{exe: baseName}
				groups[baseName] = g
				groupOrder = append(groupOrder, baseName)
			}
			g.pids = append(g.pids, pd.PID)
			if g.detail == nil && hasDetail {
				g.detail = &pd
			}
		}

		// Count unique executables
		uniqueCount := len(groups)
		b.WriteString(fmt.Sprintf("PROCESS DETAILS (%d processes, %d unique)\n", len(detail.ProcessDetails), uniqueCount))

		// Show flagged processes in full
		for _, pd := range flaggedDetails {
			b.WriteString(fmt.Sprintf("  [FLAGGED] %s  PID %d", filepath.Base(pd.Exe), pd.PID))
			if pd.PPID > 0 {
				b.WriteString(fmt.Sprintf("  (ppid: %d)", pd.PPID))
			}
			b.WriteString("\n")
			if pd.Cmdline != "" {
				b.WriteString("    cmdline: " + pd.Cmdline + "\n")
			}
			if !pd.StartedAt.IsZero() {
				b.WriteString("    started: " + pd.StartedAt.UTC().Format("15:04:05") + "\n")
			}
			if len(pd.Files) > 0 {
				shown := pd.Files
				if len(shown) > 5 {
					shown = shown[:5]
				}
				b.WriteString("    Files accessed:\n")
				for _, f := range shown {
					b.WriteString("      " + f + "\n")
				}
				if len(pd.Files) > 5 {
					b.WriteString(fmt.Sprintf("      [%d more]\n", len(pd.Files)-5))
				}
			}
			if len(pd.NetConns) > 0 {
				b.WriteString("    Network:\n")
				for _, nc := range pd.NetConns {
					b.WriteString("      " + nc + "\n")
				}
			}
		}

		// Show grouped summary for remaining processes
		for _, exe := range groupOrder {
			g := groups[exe]
			if len(g.pids) == 1 {
				// Skip if already shown as flagged
				if flaggedPIDs[g.pids[0]] {
					continue
				}
			}
			if len(g.pids) > 2 {
				b.WriteString(fmt.Sprintf("  %s (%d instances)\n", g.exe, len(g.pids)))
			} else {
				for _, pid := range g.pids {
					if !flaggedPIDs[pid] {
						b.WriteString(fmt.Sprintf("  %s  PID %d\n", g.exe, pid))
					}
				}
			}
		}
		b.WriteString("\n")
	}

	// ── Detections ───────────────────────────────────────────────────────────
	b.WriteString(fmt.Sprintf("DETECTIONS (%d)\n", len(detail.Findings)))
	renderFindings(&b, detail.Findings)
	b.WriteString("\n")

	// ── Timeline ─────────────────────────────────────────────────────────────
	b.WriteString("TIMELINE (chronological)\n")
	renderTimeline(&b, detail.Timeline)
	b.WriteString("\n")

	// ── Network Activity ──────────────────────────────────────────────────────
	b.WriteString("NETWORK ACTIVITY\n")
	renderNetworkActivity(&b, detail.Findings, detail.EventGraph)
	b.WriteString("\n")

	// ── Sensitive Files ───────────────────────────────────────────────────────
	b.WriteString("SENSITIVE FILES ACCESSED\n")
	renderSensitiveFiles(&b, detail.Findings)
	b.WriteString("\n")

	// ── Behavioral Context ────────────────────────────────────────────────────
	b.WriteString("BEHAVIORAL CONTEXT\n")
	renderBehavioralContext(&b, detail.ProcessTree, d.BaselinesByExe)
	b.WriteString("\n")

	// ── Related Incidents ─────────────────────────────────────────────────────
	b.WriteString("RELATED INCIDENTS (same host, last 30 days)\n")
	if len(d.RelatedIncidents) == 0 {
		b.WriteString("  No prior incidents on this host in the last 30 days.\n")
	} else {
		for _, ri := range d.RelatedIncidents {
			b.WriteString(fmt.Sprintf("  [%s] %s — %s (%s)\n",
				ri.Severity, ri.Title, ri.Status, ri.StartedAt.UTC().Format("Jan 2")))
		}
	}
	b.WriteString("\n")

	// ── Data Completeness ────────────────────────────────────────────────────
	b.WriteString("DATA COMPLETENESS\n")
	if detail.ProcessTree != nil {
		b.WriteString("  Process tree:   complete\n")
	} else {
		b.WriteString("  Process tree:   unavailable\n")
	}
	if len(detail.Timeline) > 0 {
		b.WriteString(fmt.Sprintf("  Timeline:       %d events\n", len(detail.Timeline)))
	} else {
		b.WriteString("  Timeline:       unavailable\n")
	}
	netCount := countNetworkFindings(detail.Findings)
	if netCount > 0 {
		b.WriteString(fmt.Sprintf("  Network events: %d connections\n", netCount))
	} else {
		b.WriteString("  Network events: unavailable\n")
	}
	if d.BaselinesByExe != nil {
		total := 0
		for _, entries := range d.BaselinesByExe {
			total += len(entries)
		}
		b.WriteString(fmt.Sprintf("  Baselines:      %d entries\n", total))
	} else {
		b.WriteString("  Baselines:      unavailable\n")
	}
	b.WriteString("\n")

	// ── Footer ────────────────────────────────────────────────────────────────
	b.WriteString(divider + "\n")
	b.WriteString("END DOSSIER — built at " + d.BuiltAt.UTC().Format("2006-01-02 15:04:05 UTC") + "\n")
	b.WriteString("Events after this timestamp may not be reflected.\n")
	b.WriteString(divider + "\n")

	return b.String()
}

// formatDuration returns a human-readable duration.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("%ds", secs)
	}
	mins := secs / 60
	remSecs := secs % 60
	if mins < 60 {
		return fmt.Sprintf("%dm %ds", mins, remSecs)
	}
	hours := mins / 60
	remMins := mins % 60
	return fmt.Sprintf("%dh %dm", hours, remMins)
}

// buildNarrative produces a 2-4 sentence attack sequence description from the timeline.
func buildNarrative(detail *incident.IncidentDetail) string {
	sorted := make([]incident.TimelineEntry, len(detail.Timeline))
	copy(sorted, detail.Timeline)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	// Filter to significant events only.
	var significant []incident.TimelineEntry
	for _, e := range sorted {
		if e.Type == "finding" || e.Type == "chain" {
			significant = append(significant, e)
		} else if e.EventType == "process_exec" || e.EventType == "net_connect" {
			significant = append(significant, e)
		}
	}

	if len(significant) < 2 {
		return "  Insufficient timeline data for narrative reconstruction."
	}

	var sentences []string

	// First event
	first := significant[0]
	pidInfo := ""
	if first.PID > 0 {
		pidInfo = fmt.Sprintf(" (PID %d)", first.PID)
	}
	sentences = append(sentences, fmt.Sprintf("  At %s, %s%s was observed.",
		first.Timestamp.UTC().Format("15:04:05"),
		first.Title,
		pidInfo))

	// Findings summary
	var findingTitles []string
	for _, e := range significant {
		if (e.Type == "finding" || e.Type == "chain") && e.Severity != "" {
			findingTitles = append(findingTitles, e.Title)
			if len(findingTitles) >= 3 {
				break
			}
		}
	}
	if len(findingTitles) > 0 {
		sentences = append(sentences, "  Detections: "+strings.Join(findingTitles, "; ")+".")
	}

	// Last event if different from first
	if len(significant) > 1 {
		last := significant[len(significant)-1]
		if last.Timestamp != first.Timestamp {
			lastPID := ""
			if last.PID > 0 {
				lastPID = fmt.Sprintf(" (PID %d)", last.PID)
			}
			sentences = append(sentences, fmt.Sprintf("  Activity concluded at %s with %s%s.",
				last.Timestamp.UTC().Format("15:04:05"),
				last.Title,
				lastPID))
		}
	}

	return strings.Join(sentences, "\n")
}

// renderProcessTree writes an ASCII process tree into b.
func renderProcessTree(b *strings.Builder, node *incident.ProcessNode, prefix string, isLast bool) {
	if node == nil {
		return
	}

	connector := ""
	childPrefix := prefix
	if prefix != "" {
		if isLast {
			connector = "└─ "
			childPrefix = prefix + "   "
		} else {
			connector = "├─ "
			childPrefix = prefix + "│  "
		}
	}

	// Build node line
	line := "  " + prefix + connector + node.Comm
	if node.PID > 0 {
		line += fmt.Sprintf("  PID %d", node.PID)
	}
	if node.AIType != "" {
		line += fmt.Sprintf("  [AI agent: %s]", node.AIType)
	}
	if len(node.FindingIDs) > 0 {
		line += fmt.Sprintf("  [FLAGGED: %s]", strings.Join(node.FindingIDs, ", "))
	}
	if node.ExePath != "" {
		line += "  exe: " + node.ExePath
	}
	b.WriteString(line + "\n")

	for i, child := range node.Children {
		renderProcessTree(b, child, childPrefix, i == len(node.Children)-1)
	}
}

// severityEmoji returns a text indicator for a severity level.
func severityEmoji(sev string) string {
	switch sev {
	case "critical":
		return "⚠"
	case "high":
		return "●"
	case "medium":
		return "○"
	default:
		return "·"
	}
}

// renderFindings writes all findings in a structured box format.
func renderFindings(b *strings.Builder, findings []incident.FindingSummary) {
	if len(findings) == 0 {
		b.WriteString("  No findings.\n")
		return
	}

	for i, f := range findings {
		boxChar := "├─"
		if i == 0 {
			boxChar = "┌─"
		}
		if i == len(findings)-1 {
			boxChar = "└─"
		}

		mitre := ""
		if f.Context != nil {
			if v, ok := f.Context["mitre_techniques"]; ok {
				switch mt := v.(type) {
				case []string:
					mitre = strings.Join(mt, ", ")
				case []any:
					var parts []string
					for _, s := range mt {
						if str, ok := s.(string); ok {
							parts = append(parts, str)
						}
					}
					mitre = strings.Join(parts, ", ")
				}
			}
		}
		mitreStr := ""
		if mitre != "" {
			mitreStr = "  — " + mitre
		}

		b.WriteString(fmt.Sprintf("  %s %s [%s %.0f%%] %s%s\n",
			boxChar, severityEmoji(f.Severity),
			strings.ToUpper(f.Severity), f.Confidence*100,
			f.DetectionID, mitreStr))

		// Process info from context
		comm := ""
		pid := 0
		if f.Context != nil {
			if v, ok := f.Context["comm"]; ok {
				comm, _ = v.(string)
			}
			if v, ok := f.Context["pid"]; ok {
				switch p := v.(type) {
				case float64:
					pid = int(p)
				case int:
					pid = p
				}
			}
		}
		if comm != "" || pid > 0 {
			procLine := "    Process:"
			if comm != "" {
				procLine += " " + comm
			}
			if pid > 0 {
				procLine += fmt.Sprintf(" PID %d", pid)
			}
			b.WriteString(procLine + "\n")
		}

		// Evidence fields
		if f.Context != nil {
			b.WriteString("    Evidence:\n")
			evidenceKeys := []string{
				"file_path", "file_size", "dst_ip", "dst_port", "domain",
				"asn_name", "bgp_prefix", "binary", "cmdline", "dns_query",
				"file_count", "file_rate",
			}
			for _, key := range evidenceKeys {
				v, ok := f.Context[key]
				if !ok || v == nil {
					continue
				}
				b.WriteString(fmt.Sprintf("      • %s: %v\n", key, v))
			}

			// Sensitive files array (up to 5)
			if sf, ok := f.Context["sensitive_files"]; ok {
				switch sfv := sf.(type) {
				case []any:
					shown := sfv
					if len(shown) > 5 {
						shown = shown[:5]
					}
					for _, f := range shown {
						b.WriteString(fmt.Sprintf("      • file: %v\n", f))
					}
					if len(sfv) > 5 {
						b.WriteString(fmt.Sprintf("      • [%d more — ask for complete list]\n", len(sfv)-5))
					}
				case []string:
					shown := sfv
					if len(shown) > 5 {
						shown = shown[:5]
					}
					for _, f := range shown {
						b.WriteString("      • file: " + f + "\n")
					}
					if len(sfv) > 5 {
						b.WriteString(fmt.Sprintf("      • [%d more — ask for complete list]\n", len(sfv)-5))
					}
				}
			}
		}
	}
}

// renderTimeline writes chronological timeline entries (up to 30).
func renderTimeline(b *strings.Builder, timeline []incident.TimelineEntry) {
	if len(timeline) == 0 {
		b.WriteString("  No timeline data available.\n")
		return
	}

	sorted := make([]incident.TimelineEntry, len(timeline))
	copy(sorted, timeline)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Timestamp.Before(sorted[j].Timestamp)
	})

	limit := 30
	shown := sorted
	if len(shown) > limit {
		shown = shown[:limit]
	}

	for _, e := range shown {
		flagStr := ""
		if e.Type == "finding" || e.Type == "chain" {
			flagStr = " ⚠"
		}
		pidStr := ""
		if e.PID > 0 {
			pidStr = fmt.Sprintf(" PID %d", e.PID)
		}
		b.WriteString(fmt.Sprintf("  %s%s  %s%s\n",
			e.Timestamp.UTC().Format("15:04:05"),
			flagStr,
			e.Title,
			pidStr))
	}

	if len(sorted) > limit {
		b.WriteString(fmt.Sprintf("  [%d more events — ask for complete timeline]\n", len(sorted)-limit))
	}
}

// renderNetworkActivity collects and prints network destinations.
type netDest struct {
	ip        string
	port      interface{}
	bgp       string
	asn       string
	comm      string
	pid       int
	timestamp time.Time
}

func renderNetworkActivity(b *strings.Builder, findings []incident.FindingSummary, graph *incident.EventGraph) {
	seen := make(map[string]*netDest)

	networkDetections := map[string]bool{
		"ai.unexpected_network": true,
		"ai.data_exfiltration":  true,
		"ai.suspicious_dns":     true,
	}

	for _, f := range findings {
		if !networkDetections[f.DetectionID] {
			continue
		}
		if f.Context == nil {
			continue
		}
		ip, _ := f.Context["dst_ip"].(string)
		if ip == "" {
			ip, _ = f.Context["domain"].(string)
		}
		if ip == "" {
			continue
		}
		port := f.Context["dst_port"]
		bgp, _ := f.Context["bgp_prefix"].(string)
		asn, _ := f.Context["asn_name"].(string)
		comm, _ := f.Context["comm"].(string)
		pid := 0
		if v, ok := f.Context["pid"]; ok {
			switch p := v.(type) {
			case float64:
				pid = int(p)
			case int:
				pid = p
			}
		}
		key := fmt.Sprintf("%v:%v", ip, port)
		if _, exists := seen[key]; !exists {
			seen[key] = &netDest{
				ip:        ip,
				port:      port,
				bgp:       bgp,
				asn:       asn,
				comm:      comm,
				pid:       pid,
				timestamp: f.Timestamp,
			}
		}
	}

	if len(seen) == 0 {
		b.WriteString("  No external network connections recorded in this incident.\n")
		return
	}

	for key, dest := range seen {
		_ = key
		portStr := ""
		if dest.port != nil {
			portStr = fmt.Sprintf(":%v", dest.port)
		}
		bgpStr := ""
		if dest.bgp != "" {
			bgpStr = "  BGP: " + dest.bgp
		}
		if dest.asn != "" {
			bgpStr += "  ASN: " + dest.asn
		}
		b.WriteString(fmt.Sprintf("  %s%s%s\n", dest.ip, portStr, bgpStr))
		if dest.comm != "" || dest.pid > 0 {
			byStr := "    Connected by:"
			if dest.comm != "" {
				byStr += " " + dest.comm
			}
			if dest.pid > 0 {
				byStr += fmt.Sprintf(" PID %d", dest.pid)
			}
			byStr += " at " + dest.timestamp.UTC().Format("15:04:05")
			b.WriteString(byStr + "\n")
		}
	}
}

// countNetworkFindings counts findings with network-related detection IDs.
func countNetworkFindings(findings []incident.FindingSummary) int {
	n := 0
	for _, f := range findings {
		switch f.DetectionID {
		case "ai.unexpected_network", "ai.data_exfiltration", "ai.suspicious_dns":
			n++
		}
	}
	return n
}

// renderSensitiveFiles groups credential_access and excessive_writes file paths by category.
func renderSensitiveFiles(b *strings.Builder, findings []incident.FindingSummary) {
	categories := map[string][]string{
		"SSH keys (.ssh/)":                nil,
		"Cloud creds (.aws/.gcp/.azure/)": nil,
		"Env files (.env)":                nil,
		"Config (/etc/)":                  nil,
		"Other":                           nil,
	}
	catOrder := []string{"SSH keys (.ssh/)", "Cloud creds (.aws/.gcp/.azure/)", "Env files (.env)", "Config (/etc/)", "Other"}

	relevant := map[string]bool{
		"ai.credential_access": true,
		"ai.excessive_writes":  true,
	}

	seen := make(map[string]bool)
	for _, f := range findings {
		if !relevant[f.DetectionID] || f.Context == nil {
			continue
		}
		fp, _ := f.Context["file_path"].(string)
		if fp == "" {
			fp, _ = f.Context["pattern"].(string)
		}
		if fp == "" || seen[fp] {
			continue
		}
		seen[fp] = true

		switch {
		case strings.Contains(fp, ".ssh/"):
			categories["SSH keys (.ssh/)"] = append(categories["SSH keys (.ssh/)"], fp)
		case strings.Contains(fp, ".aws/") || strings.Contains(fp, ".gcp/") || strings.Contains(fp, ".azure/") || strings.Contains(fp, ".gcloud/"):
			categories["Cloud creds (.aws/.gcp/.azure/)"] = append(categories["Cloud creds (.aws/.gcp/.azure/)"], fp)
		case strings.Contains(fp, ".env"):
			categories["Env files (.env)"] = append(categories["Env files (.env)"], fp)
		case strings.HasPrefix(fp, "/etc/"):
			categories["Config (/etc/)"] = append(categories["Config (/etc/)"], fp)
		default:
			categories["Other"] = append(categories["Other"], fp)
		}
	}

	anyFound := false
	for _, cat := range catOrder {
		files := categories[cat]
		if len(files) == 0 {
			continue
		}
		anyFound = true
		b.WriteString("  " + cat + ":\n")
		shown := files
		if len(shown) > 5 {
			shown = shown[:5]
		}
		for _, fp := range shown {
			b.WriteString("    " + fp + "\n")
		}
		if len(files) > 5 {
			b.WriteString(fmt.Sprintf("    [%d more — ask for complete list]\n", len(files)-5))
		}
	}

	if !anyFound {
		b.WriteString("  No sensitive file access findings.\n")
	}
}

// renderBehavioralContext writes per-exe baseline presence.
func renderBehavioralContext(b *strings.Builder, tree *incident.ProcessNode, baselinesByExe map[string][]detection.BaselineEntry) {
	if baselinesByExe == nil {
		b.WriteString("  Behavioral baseline data unavailable.\n")
		return
	}

	exePaths := collectExePaths(tree)
	if len(exePaths) == 0 {
		b.WriteString("  No process exe_paths identified.\n")
		return
	}

	sort.Strings(exePaths)
	for _, exe := range exePaths {
		entries, ok := baselinesByExe[exe]
		if !ok || entries == nil {
			b.WriteString(fmt.Sprintf("  %s: No baseline entries — behavior is NEW on this host.\n", exe))
		} else {
			b.WriteString(fmt.Sprintf("  %s: %d baseline entries — behavior is KNOWN for this host.\n", exe, len(entries)))
		}
	}
}

// collectFlaggedPIDs walks the process tree and collects PIDs that have findings.
func collectFlaggedPIDs(node *incident.ProcessNode, pids map[int64]bool) {
	if node == nil {
		return
	}
	if len(node.FindingIDs) > 0 {
		pids[int64(node.PID)] = true
	}
	for _, child := range node.Children {
		collectFlaggedPIDs(child, pids)
	}
}
