package ai_pack

import (
	"fmt"
	"net"
	"sort"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/enrichment"
	"github.com/correlic/correlic-backend/internal/event"
)

// AIDataExfiltration detects when an AI agent reads sensitive files
// and then makes an outbound network connection within a short window.
type AIDataExfiltration struct{}

const exfiltrationLookbackWindow = 15 * time.Minute

func (d *AIDataExfiltration) Meta() detection.DetectionMeta {
	return detection.DetectionMeta{
		ID:              "ai.data_exfiltration",
		Pack:            "ai",
		Name:            "AI Data Exfiltration",
		Severity:        "critical",
		Description:     "AI agent read sensitive files and then made an outbound network connection — possible data exfiltration",
		Tags:            []string{"ai", "exfiltration", "network", "sensitive-files"},
		MITRETechniques: []string{"T1041", "T1567"},
	}
}

func (d *AIDataExfiltration) Scope() detection.DetectionScope {
	return detection.DetectionScope{
		EventTypes: []string{"net_connect"},
		WindowSecs: int(exfiltrationLookbackWindow.Seconds()),
	}
}

func (d *AIDataExfiltration) Evaluate(ctx *detection.EvalContext) []detection.Finding {
	evt := ctx.Event
	if evt.Process == nil || evt.Target == nil || evt.Target.IP == "" {
		return nil
	}

	// Check if the process belongs to an AI agent tree
	isAI, aiType, err := ctx.GraphQuery.IsAIProcess(ctx.Ctx, ctx.HostID, evt.Process.PID)
	if err != nil || !isAI {
		return nil
	}

	// Skip internal connections — exfiltration goes external
	if isPrivateIP(evt.Target.IP) {
		return nil
	}

	since := evt.Timestamp.Add(-exfiltrationLookbackWindow)
	pids := []int{evt.Process.PID}
	correlationScope := "pid_tree"
	recentFileEvents := []event.Event{}
	// SessionID "0" is the kernel/unset sentinel — treat as missing and fall back to PID-tree.
	if evt.Process.SessionID != "" && evt.Process.SessionID != "0" {
		correlationScope = "session"
		recentFileEvents, err = ctx.GraphQuery.GetRecentEventsBySession(
			ctx.Ctx, ctx.HostID, evt.Process.SessionID, since, []string{"file_open"},
		)
	} else {
		// Fallback: PID-tree scope for events without a session identifier.
		ancestors, ancestorErr := ctx.GraphQuery.GetProcessAncestors(ctx.Ctx, ctx.HostID, evt.Process.PID, 5)
		if ancestorErr == nil {
			pids = append(pids, collectProcessPIDs(ancestors)...)
		}
		pids = uniqueSortedPIDs(pids)
		recentFileEvents, err = ctx.GraphQuery.GetRecentEventsMultiPID(
			ctx.Ctx, ctx.HostID, pids, since, []string{"file_open"},
		)
	}
	if err != nil || len(recentFileEvents) == 0 {
		return nil
	}

	// Check if any of the recent file reads were sensitive
	var sensitiveFiles []string
	for _, fe := range recentFileEvents {
		if fe.Target != nil && fe.Target.FilePath != "" && isSensitiveFile(fe.Target.FilePath) {
			sensitiveFiles = append(sensitiveFiles, fe.Target.FilePath)
		}
	}

	if len(sensitiveFiles) == 0 {
		return nil
	}

	// Build list of related event IDs
	var relatedIDs []string
	for _, fe := range recentFileEvents {
		if fe.Target != nil && fe.Target.FilePath != "" && isSensitiveFile(fe.Target.FilePath) {
			relatedIDs = append(relatedIDs, fe.ID)
		}
	}

	info := enrichment.GlobalEnricher.GetNetInfo(ctx.Ctx, evt.Target.IP)
	domain := info.Domain

	// Correlate with recent DNS queries from the same PID for a better domain name.
	// Reverse DNS often returns generic PTR records (e.g. "1.2.3.4.bc.googleusercontent.com")
	// while the DNS cache has the actual queried domain (e.g. "api.anthropic.com").
	var dnsDomain string
	if ctx.DNSCache != nil && evt.Process != nil {
		dnsDomain = ctx.DNSCache.Lookup(evt.Process.PID, evt.Timestamp)
	}
	if dnsDomain != "" && (domain == "" || isGenericPTR(domain)) {
		domain = dnsDomain
	}

	// Drop event if it's communicating with an explicitly allowed domain
	if domain != "" && ctx.SafeDomainChecker != nil && ctx.SafeDomainChecker.IsSafe(domain) {
		return nil
	}
	// Also check the DNS-correlated domain if different from reverse DNS
	if dnsDomain != "" && dnsDomain != domain && ctx.SafeDomainChecker != nil && ctx.SafeDomainChecker.IsSafe(dnsDomain) {
		return nil
	}

	// Group pattern by BGP prefix or fallback to CIDR /24
	patternIP := evt.Target.IP
	if info.BGPPrefix != "" {
		patternIP = info.BGPPrefix
	} else {
		ip := net.ParseIP(evt.Target.IP)
		if ip != nil && ip.To4() != nil {
			ip = ip.To4()
			patternIP = fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
		}
	}

	summary := fmt.Sprintf("%s read %d sensitive file(s) then connected to subnet %s (port %d)",
		aiType, len(sensitiveFiles), patternIP, evt.Target.Port)
	if info.ASNName != "" && domain != "" {
		summary = fmt.Sprintf("%s read %d sensitive file(s) then connected to %s on %s (subnet %s, port %d)",
			aiType, len(sensitiveFiles), domain, info.ASNName, patternIP, evt.Target.Port)
	} else if info.ASNName != "" {
		summary = fmt.Sprintf("%s read %d sensitive file(s) then connected to %s (subnet %s, port %d)",
			aiType, len(sensitiveFiles), info.ASNName, patternIP, evt.Target.Port)
	} else if domain != "" {
		summary = fmt.Sprintf("%s read %d sensitive file(s) then connected to %s (subnet %s, port %d)",
			aiType, len(sensitiveFiles), domain, patternIP, evt.Target.Port)
	}

	// Confidence depends on correlation scope and how many sensitive files were found.
	confidence := 0.65 // pid-tree fallback baseline
	if correlationScope == "session" {
		if len(sensitiveFiles) >= 3 {
			confidence = 0.90
		} else {
			confidence = 0.75
		}
	}

	return []detection.Finding{
		{
			Title:         "AI agent may be exfiltrating sensitive data",
			Summary:       summary,
			Confidence:    confidence,
			RelatedEvents: relatedIDs,
			Context: func() map[string]any {
				ctx := map[string]any{
					"ai_type":           aiType,
					"sensitive_files":   sensitiveFiles,
					"dst_ip":            evt.Target.IP,
					"dst_port":          evt.Target.Port,
					"domain":            domain,
					"pid":               evt.Process.PID,
					"session_id":        evt.Process.SessionID,
					"window_secs":       int(exfiltrationLookbackWindow.Seconds()),
					"tree_pids":         pids,
					"correlation_scope": correlationScope,
					"signal_type":       "network_dest",
					"pattern":           fmt.Sprintf("%s:%d", patternIP, evt.Target.Port),
				}
				if info.ASNName != "" {
					ctx["asn_name"] = info.ASNName
				}
				if info.ASN != "" {
					ctx["asn"] = info.ASN
				}
				if info.BGPPrefix != "" {
					ctx["bgp_prefix"] = info.BGPPrefix
				}
				if dnsDomain != "" {
					ctx["dns_domain"] = dnsDomain
				}
				return ctx
			}(),
		},
	}
}

func collectProcessPIDs(events []event.Event) []int {
	pids := make([]int, 0, len(events))
	for _, evt := range events {
		if evt.Process != nil && evt.Process.PID > 0 {
			pids = append(pids, evt.Process.PID)
		}
	}
	return pids
}

func uniqueSortedPIDs(pids []int) []int {
	uniq := make(map[int]bool, len(pids))
	for _, pid := range pids {
		if pid > 0 {
			uniq[pid] = true
		}
	}
	out := make([]int, 0, len(uniq))
	for pid := range uniq {
		out = append(out, pid)
	}
	sort.Ints(out)
	return out
}
