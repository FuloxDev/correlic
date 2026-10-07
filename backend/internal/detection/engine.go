package detection

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/enrichment"
	"github.com/correlic/correlic-backend/internal/event"
)

// Engine routes incoming events to registered detection rules and collects findings.
// It is safe for concurrent use.
type Engine struct {
	mu       sync.RWMutex
	rules    map[string][]Detection // eventType → detections
	dnsCache *DNSCache              // correlates net_connect with recent net_dns queries
}

// NewEngine creates a new detection engine.
func NewEngine() *Engine {
	return &Engine{
		rules:    make(map[string][]Detection),
		dnsCache: NewDNSCache(60 * time.Second),
	}
}

// Register adds a detection rule, indexed by its scoped event types.
func (e *Engine) Register(d Detection) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, et := range d.Scope().EventTypes {
		e.rules[et] = append(e.rules[et], d)
	}
	meta := d.Meta()
	log.Printf("Detection registered: [%s] %s (severity=%s, events=%v)",
		meta.Pack, meta.ID, meta.Severity, d.Scope().EventTypes)
}

// RegisterPack bulk-registers a slice of detection rules.
func (e *Engine) RegisterPack(pack []Detection) {
	for _, d := range pack {
		e.Register(d)
	}
}

// Evaluate runs all detection rules scoped to evt.Type and returns any findings.
// Each finding gets a unique ID and "pending" status.
func (e *Engine) Evaluate(ctx *EvalContext) []Finding {
	if ctx == nil || ctx.Event == nil {
		return nil
	}

	evt := ctx.Event

	// Feed DNS queries into the cache for IP→domain correlation.
	if evt.Type == "net_dns" && evt.Target != nil && evt.Target.Domain != "" && evt.Process != nil {
		e.dnsCache.Record(evt.Process.PID, evt.Target.Domain, evt.Timestamp)
	}

	// Attach DNS cache to context so detection rules can look up correlated domains.
	if ctx.DNSCache == nil {
		ctx.DNSCache = e.dnsCache
	}

	e.mu.RLock()
	detections := e.rules[evt.Type]
	e.mu.RUnlock()

	if len(detections) == 0 {
		return nil
	}

	var findings []Finding
	for _, d := range detections {
		results := safeEvaluate(d, ctx)
		meta := d.Meta()
		if len(results) > 0 {
			log.Printf("detection: rule %s fired on event %s (host=%s, matches=%d)",
				meta.ID, evt.ID, ctx.HostID, len(results))
		}
		for i := range results {
			// Stamp each finding with standard fields
			results[i].ID = generateFindingID(ctx.Ctx, meta.ID, ctx.Event, &results[i])
			results[i].DetectionID = meta.ID
			results[i].HostID = ctx.HostID
			if results[i].Severity == "" {
				results[i].Severity = meta.Severity
			}
			// Dampen severity when confidence is low — a CRITICAL finding at 52%
			// confidence should not alarm the user as much as one at 95%.
			if results[i].Confidence > 0 && results[i].Confidence < 0.60 {
				switch results[i].Severity {
				case "critical":
					results[i].Severity = "high"
				case "high":
					results[i].Severity = "medium"
				}
			}
			results[i].AnchorEventID = ctx.Event.ID
			// If the event was blocked by the agent's enforcer, mark the finding as "blocked"
			// so it appears in the Blocked tab instead of Pending.
			if ctx.Event.Context != nil {
				if action, ok := ctx.Event.Context["action"].(string); ok && action == "blocked" {
					results[i].Status = "blocked"
					if results[i].Context == nil {
						results[i].Context = make(map[string]any)
					}
					results[i].Context["action"] = "blocked"
				}
			}
			if results[i].Status == "" {
				results[i].Status = "pending"
			}
			results[i].Timestamp = time.Now()
			// Stamp MITRE ATT&CK techniques into context.
			// If the rule's Evaluate() already set specific techniques on
			// the finding, prefer those over the static Meta() list.
			if results[i].Context == nil {
				results[i].Context = make(map[string]any)
			}
			if _, hasSpecific := results[i].Context["mitre_techniques"]; !hasSpecific && len(meta.MITRETechniques) > 0 {
				results[i].Context["mitre_techniques"] = meta.MITRETechniques
			}
			log.Printf("detection: finding generated id=%s rule=%s severity=%s confidence=%.2f host=%s",
				results[i].ID, meta.ID, results[i].Severity, results[i].Confidence, ctx.HostID)
		}
		findings = append(findings, results...)
	}
	return findings
}

// RuleCount returns the total number of registered rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	count := 0
	for _, rules := range e.rules {
		count += len(rules)
	}
	return count
}

// safeEvaluate wraps detection evaluation with panic recovery.
func safeEvaluate(d Detection, ctx *EvalContext) (findings []Finding) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("ERROR: detection %s panicked: %v", d.Meta().ID, r)
			findings = nil
		}
	}()
	return d.Evaluate(ctx)
}

// generateFindingID creates a deterministic ID for deduplication.
// Uses detection rule + host + pattern key, so the same AI behavior on the same
// host produces one finding (the INSERT's ON CONFLICT DO NOTHING takes care of the rest).
// If the finding's context contains a "pattern" key (set by windowed rules like
// ai.excessive_writes), that takes priority over the per-event pattern key.
func generateFindingID(ctx context.Context, detectionID string, evt *event.Event, f *Finding) string {
	// Prefer the finding-level pattern (set by the detection rule) for windowed
	// detections that aggregate multiple events into one finding.
	if f != nil && f.Context != nil {
		if p, ok := f.Context["pattern"].(string); ok && p != "" {
			return fmt.Sprintf("%s:%s:%s", detectionID, evt.HostID, p)
		}
	}
	patternKey := extractPatternKey(ctx, evt)
	if patternKey != "" {
		return fmt.Sprintf("%s:%s:%s", detectionID, evt.HostID, patternKey)
	}
	// Fallback: use event ID (no dedup possible)
	return fmt.Sprintf("%s:%s", detectionID, evt.ID)
}

// extractPatternKey returns a stable key representing the behavior pattern of the event.
// Same pattern key = same behavior = should be deduplicated into one finding.
func extractPatternKey(ctx context.Context, evt *event.Event) string {
	if evt == nil {
		return ""
	}
	switch evt.Type {
	case "file_open", "file_write":
		if evt.Target != nil && evt.Target.FilePath != "" {
			return evt.Target.FilePath
		}
	case "process_exec":
		if evt.Process != nil {
			if evt.Process.ExePath != "" {
				return evt.Process.ExePath
			}
			return evt.Process.Comm
		}
	case "net_connect":
		if evt.Target != nil && evt.Target.IP != "" {
			// Leverage Cymru DNS lookup to group by BGP Prefix rather than manual /24
			info := enrichment.GlobalEnricher.GetNetInfo(ctx, evt.Target.IP)
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
			return fmt.Sprintf("%s:%d", patternIP, evt.Target.Port)
		}
	case "net_dns":
		if evt.Target != nil && evt.Target.Domain != "" {
			return evt.Target.Domain
		}
	case "registry_write":
		// Dedup by registry key path
		if evt.Target != nil && evt.Target.FilePath != "" {
			return evt.Target.FilePath
		}
	case "privilege_use":
		// Dedup by PID + privilege list
		if evt.Process != nil {
			if privs, ok := evt.Context["privileges"].([]string); ok {
				return fmt.Sprintf("pid:%d:%s", evt.Process.PID, strings.Join(privs, ","))
			}
		}
	case "schtask_create":
		if taskName, ok := evt.Context["task_name"].(string); ok {
			return taskName
		}
	case "file_access":
		// Same as file_open dedup
		if evt.Target != nil && evt.Target.FilePath != "" {
			return evt.Target.FilePath
		}
	}
	return ""
}
