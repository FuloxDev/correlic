package query

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// GetAgentActivityStream returns a structured activity stream for all AI agents.
// It queries Neo4j for agent root processes and their descendant activity events,
// translates raw events into human-readable actions with significance scores,
// and groups everything per agent. The graph is not tenant-scoped, so orgID is
// accepted for interface symmetry with PostgresActivityStream and not applied.
func (s *TimelineService) GetAgentActivityStream(ctx context.Context, orgID string, since time.Time, minSignificance int) (*AgentActivityResponse, error) {
	_ = orgID
	sinceStr := since.Format(time.RFC3339)

	// Find TOPMOST AI agent processes: those with no AIAgent parent via PROCESS_PARENT.
	// This filters out cargo, rustfmt, etc. that are children of the real AI agent
	// but also match AI patterns (and thus have their own ai_type + ai_root IS NULL).
	// Then collect all descendant PIDs and their activity events.
	query := `
		// Find AIAgent root processes — no time filter on the agent itself,
		// because long-running agents (e.g. Claude Code) may have started hours ago
		// but are still actively producing events within the window.
		MATCH (agent:Event:AIAgent)
		WHERE agent.type = 'process_exec'
		  AND agent.ai_type IS NOT NULL

		  // Must NOT have a parent that is also an AIAgent
		  AND NOT EXISTS {
		    MATCH (parent:Event:AIAgent {type: 'process_exec'})-[:PROCESS_PARENT]->(agent)
		    WHERE parent.host_id = agent.host_id
		  }
		WITH agent

		// Collect all descendant PIDs via PROCESS_PARENT edges
		OPTIONAL MATCH (agent)-[:PROCESS_PARENT*0..15]->(descendant:Event {type: 'process_exec'})
		WITH agent, collect(DISTINCT descendant.actor_pid) as agentPids

		// Fetch activity events for all agent PIDs
		UNWIND agentPids as pid
		OPTIONAL MATCH (activity:Event)
		WHERE activity.actor_pid = pid
		  AND activity.host_id = agent.host_id
		  AND activity.timestamp >= datetime($since)
		  AND activity.type IN ['file_open', 'file_write', 'net_connect', 'net_dns', 'net_accept', 'net_listen', 'process_exec']
		  AND (activity.is_synthetic IS NULL OR activity.is_synthetic = false)
		WITH agent, agentPids,
			 collect(DISTINCT activity {
				 .id, .type, .timestamp,
				 .actor_pid, .actor_comm, .actor_exe_path, .actor_cmdline,
				 .target_path, .target_ip, .target_port, .target_domain,
				 .host_id
			 }) as activities

		// Only return agents that have activity in the time window
		WHERE ANY(a IN activities WHERE a.id IS NOT NULL)

		RETURN agent.actor_comm as agent_name,
		       agent.actor_pid as agent_pid,
		       agent.ai_type as ai_type,
		       agent.host_id as host_id,
		       agent.actor_exe_path as exe_path,
		       agent.timestamp as started_at,
		       size(agentPids) - 1 as child_count,
		       activities
		ORDER BY agent.timestamp DESC
	`

	result, err := s.client.ExecuteRead(ctx, query, map[string]any{
		"since": sinceStr,
	})
	if err != nil {
		return nil, fmt.Errorf("agent activity query failed: %w", err)
	}

	now := time.Now()

	// Merge results by ai_type + host_id.
	// The eBPF agent re-reports long-running processes, creating multiple process_exec
	// events for the same AI tool. We merge them into a single summary per ai_type.
	type agentKey struct {
		hostID string
		aiType string
	}
	mergedAgents := make(map[agentKey]*AgentSummary)
	agentOrder := make([]agentKey, 0)   // preserve display order
	seenEvents := make(map[string]bool) // track unique events to prevent UI duplication

	for _, record := range result.Records {
		agentName := ""
		if v, ok := record.Values[0].(string); ok {
			agentName = v
		}
		agentPID := 0
		if v, ok := record.Values[1].(int64); ok {
			agentPID = int(v)
		}

		hostID := ""
		if v, ok := record.Values[3].(string); ok {
			hostID = v
		}

		aiType := ""
		if v, ok := record.Values[2].(string); ok {
			aiType = v
		}
		// hostID already extracted above for dedup
		exePath := ""
		if v, ok := record.Values[4].(string); ok {
			exePath = v
		}

		var startedAt time.Time
		if v, ok := record.Values[5].(time.Time); ok {
			startedAt = v
		}

		childCount := 0
		if v, ok := record.Values[6].(int64); ok {
			childCount = int(v)
		}

		// Parse activity events into actions
		var actions []AgentAction
		var stats AgentStats

		if activities, ok := record.Values[7].([]any); ok {
			for _, act := range activities {
				actMap, ok := act.(map[string]any)
				if !ok {
					continue
				}

				eventType := getStringFromMap(actMap, "type")
				if eventType == "" {
					continue
				}

				var ts time.Time
				if v, ok := actMap["timestamp"].(time.Time); ok {
					ts = v
				}

				eventID := getStringFromMap(actMap, "id")
				if eventID != "" {
					if seenEvents[eventID] {
						continue
					}
					seenEvents[eventID] = true
				}

				filePath := getStringFromMap(actMap, "target_path")
				dstIP := getStringFromMap(actMap, "target_ip")
				dstPort := 0
				if v, ok := actMap["target_port"].(int64); ok {
					dstPort = int(v)
				}
				dnsName := getStringFromMap(actMap, "target_domain")
				cmdline := getStringFromMap(actMap, "actor_cmdline")
				comm := getStringFromMap(actMap, "actor_comm")
				actorExe := getStringFromMap(actMap, "actor_exe_path")

				action := buildAction(eventType, filePath, dstIP, dstPort, dnsName, cmdline, comm, actorExe)
				if action.Significance < minSignificance {
					continue
				}
				action.Timestamp = ts
				action.EventID = eventID
				action.EventType = eventType
				if pid, ok := actMap["actor_pid"].(int64); ok {
					action.ProcessPID = int(pid)
				}
				action.ProcessComm = comm

				actions = append(actions, action)

				// Update stats
				stats.TotalEvents++
				switch action.Category {
				case "file":
					if eventType == "file_write" {
						stats.FilesModified++
					} else {
						stats.FilesRead++
					}
				case "network":
					stats.Connections++
				case "dns":
					stats.DNSLookups++
				case "command":
					stats.CommandsRun++
				}
			}
		}

		// Merge into existing summary for this ai_type+host, or create new one
		key := agentKey{hostID: hostID, aiType: aiType}
		if existing, ok := mergedAgents[key]; ok {
			// Merge: add actions and stats, pick earliest startedAt, sum childCount
			existing.Actions = append(existing.Actions, actions...)
			existing.Stats.TotalEvents += stats.TotalEvents
			existing.Stats.FilesModified += stats.FilesModified
			existing.Stats.FilesRead += stats.FilesRead
			existing.Stats.CommandsRun += stats.CommandsRun
			existing.Stats.Connections += stats.Connections
			existing.Stats.DNSLookups += stats.DNSLookups
			existing.ChildCount += childCount
			if startedAt.Before(existing.StartedAt) {
				existing.StartedAt = startedAt
				existing.Duration = formatDuration(now.Sub(startedAt))
			}
		} else {
			duration := now.Sub(startedAt)
			durationStr := formatDuration(duration)

			summary := &AgentSummary{
				AgentName:  agentName,
				AgentPID:   agentPID,
				AIType:     aiType,
				HostID:     hostID,
				ExePath:    exePath,
				StartedAt:  startedAt,
				Duration:   durationStr,
				Actions:    actions,
				Stats:      stats,
				ChildCount: childCount,
			}
			mergedAgents[key] = summary
			agentOrder = append(agentOrder, key)
		}
	}

	// Build final ordered slice, sort actions within each agent
	agents := make([]AgentSummary, 0, len(agentOrder))
	for _, key := range agentOrder {
		summary := mergedAgents[key]
		sortActionsByTime(summary.Actions)
		agents = append(agents, *summary)
	}

	return &AgentActivityResponse{
		Agents:      agents,
		WindowStart: since,
		WindowEnd:   now,
	}, nil
}

// buildAction translates a raw event into a human-readable AgentAction with significance score.
func buildAction(eventType, filePath, dstIP string, dstPort int, dnsName, cmdline, comm, exePath string) AgentAction {
	switch eventType {
	case "file_write":
		return buildFileAction("file", filePath, true)
	case "file_open":
		return buildFileAction("file", filePath, false)
	case "net_connect":
		return buildNetworkAction(dstIP, dstPort)
	case "net_accept":
		return AgentAction{
			Category:     "network",
			Action:       fmt.Sprintf("📥 Accepted connection from %s:%d", dstIP, dstPort),
			Detail:       fmt.Sprintf("%s:%d", dstIP, dstPort),
			Significance: 3,
		}
	case "net_listen":
		return AgentAction{
			Category:     "network",
			Action:       fmt.Sprintf("🔊 Listening on port %d", dstPort),
			Detail:       fmt.Sprintf(":%d", dstPort),
			Significance: 4,
		}
	case "net_dns":
		return buildDNSAction(dnsName)
	case "process_exec":
		return buildCommandAction(cmdline, comm, exePath)
	default:
		return AgentAction{
			Category:     "other",
			Action:       eventType,
			Significance: 1,
		}
	}
}

// --- File action helpers ---

// Source code extensions that indicate high-significance file activity.
var sourceCodeExts = map[string]bool{
	".go": true, ".ts": true, ".tsx": true, ".js": true, ".jsx": true,
	".py": true, ".rs": true, ".c": true, ".cpp": true, ".h": true,
	".java": true, ".rb": true, ".php": true, ".swift": true, ".kt": true,
	".cs": true, ".vue": true, ".svelte": true, ".html": true, ".css": true,
	".sql": true, ".sh": true, ".bash": true, ".zsh": true,
	".yaml": true, ".yml": true, ".json": true, ".toml": true, ".xml": true,
	".md": true, ".txt": true, ".env": true, ".dockerfile": true,
}

// Sensitive file paths that indicate high significance.
var sensitivePathPrefixes = []string{
	".ssh/", ".gnupg/", ".aws/", ".kube/", ".docker/",
	"/etc/shadow", "/etc/passwd", "/etc/sudoers",
}

// Low-significance path prefixes to filter out noise.
var noisyPathPrefixes = []string{
	"/proc/", "/sys/", "/dev/", "/tmp/", "/var/run/",
	"/usr/share/zoneinfo/", "/usr/lib/locale/",
}

func buildFileAction(category, filePath string, isWrite bool) AgentAction {
	if filePath == "" {
		return AgentAction{Category: category, Action: "file access", Significance: 1}
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	// Check noisy paths
	for _, prefix := range noisyPathPrefixes {
		if strings.HasPrefix(filePath, prefix) {
			verb := "Read"
			if isWrite {
				verb = "Wrote"
			}
			return AgentAction{
				Category:     category,
				Action:       fmt.Sprintf("%s %s", verb, filePath),
				Detail:       filePath,
				Significance: 1,
			}
		}
	}

	// Check sensitive paths
	for _, prefix := range sensitivePathPrefixes {
		if strings.Contains(filePath, prefix) {
			icon := "🔑"
			verb := "Read sensitive file"
			if isWrite {
				verb = "Modified sensitive file"
				icon = "⚠️"
			}
			return AgentAction{
				Category:     category,
				Action:       fmt.Sprintf("%s %s %s", icon, verb, filePath),
				Detail:       filePath,
				Significance: 5,
			}
		}
	}

	// Source code file
	if sourceCodeExts[ext] {
		if isWrite {
			return AgentAction{
				Category:     category,
				Action:       fmt.Sprintf("📝 Edited %s", filePath),
				Detail:       filePath,
				Significance: 5,
			}
		}
		return AgentAction{
			Category:     category,
			Action:       fmt.Sprintf("📄 Read %s", filePath),
			Detail:       filePath,
			Significance: 3,
		}
	}

	// Generic file
	if isWrite {
		return AgentAction{
			Category:     category,
			Action:       fmt.Sprintf("📝 Wrote %s", filePath),
			Detail:       filePath,
			Significance: 3,
		}
	}
	return AgentAction{
		Category:     category,
		Action:       fmt.Sprintf("📄 Read %s", filePath),
		Detail:       filePath,
		Significance: 2,
	}
}

// --- Network action helpers ---

// Known high-significance network targets — only specific, reliable prefixes.
// Broad ranges like 52.*/54.* (AWS) are omitted because they produce false positives.
// For cloud provider detection, rely on DNS lookups (net_dns events) instead.
var knownHosts = map[string]string{
	"140.82.121.": "github.com",
	"140.82.112.": "github.com",
	"140.82.113.": "github.com",
	"140.82.114.": "github.com",
	"192.30.255.": "github.com",
	"151.101.":    "github.com (CDN)",
	"142.250.":    "google.com",
	"172.217.":    "google.com",
}

// formatAddr formats an IP:port pair, omitting :0 when port is missing.
func formatAddr(ip string, port int) string {
	if port > 0 {
		return fmt.Sprintf("%s:%d", ip, port)
	}
	return ip
}

func buildNetworkAction(ip string, port int) AgentAction {
	if ip == "" {
		return AgentAction{Category: "network", Action: "network connection", Significance: 1}
	}

	// Check if localhost
	if strings.HasPrefix(ip, "127.") || ip == "::1" || ip == "0.0.0.0" {
		return AgentAction{
			Category:     "network",
			Action:       fmt.Sprintf("🔄 Localhost connection %s", formatAddr(ip, port)),
			Detail:       formatAddr(ip, port),
			Significance: 1,
		}
	}

	// Try to match known hosts
	hostLabel := ""
	for prefix, label := range knownHosts {
		if strings.HasPrefix(ip, prefix) {
			hostLabel = label
			break
		}
	}

	if hostLabel != "" {
		addr := formatAddr(ip, port)
		return AgentAction{
			Category:     "network",
			Action:       fmt.Sprintf("🌐 Connected to %s", hostLabel),
			Detail:       fmt.Sprintf("%s (%s)", addr, hostLabel),
			Significance: 4,
		}
	}

	// Generic external connection
	addr := formatAddr(ip, port)
	return AgentAction{
		Category:     "network",
		Action:       fmt.Sprintf("🌐 Connected to %s", addr),
		Detail:       addr,
		Significance: 3,
	}
}

func buildDNSAction(name string) AgentAction {
	if name == "" {
		return AgentAction{Category: "dns", Action: "DNS lookup", Significance: 1}
	}
	return AgentAction{
		Category:     "dns",
		Action:       fmt.Sprintf("🔍 DNS lookup: %s", name),
		Detail:       name,
		Significance: 3,
	}
}

// --- Command action helpers ---

// High-significance commands.
var significantCommands = map[string]int{
	"git":       4,
	"go":        4,
	"npm":       4,
	"npx":       4,
	"yarn":      4,
	"pnpm":      4,
	"make":      4,
	"docker":    4,
	"kubectl":   5,
	"curl":      3,
	"wget":      3,
	"pip":       4,
	"cargo":     4,
	"rustc":     4,
	"gcc":       4,
	"g++":       4,
	"javac":     4,
	"mvn":       4,
	"gradle":    4,
	"ssh":       5,
	"scp":       5,
	"rsync":     4,
	"terraform": 5,
	"ansible":   5,
	"helm":      5,
}

// formatCmdline parses JSON argv arrays (e.g. ["ssh","-T","git@github.com"])
// into a readable command string (e.g. "ssh -T git@github.com").
// Non-JSON strings are returned as-is.
func formatCmdline(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw[0] != '[' {
		return raw
	}
	var argv []string
	if err := json.Unmarshal([]byte(raw), &argv); err != nil {
		return raw
	}
	if len(argv) == 0 {
		return raw
	}
	return strings.Join(argv, " ")
}

func buildCommandAction(cmdline, comm, exePath string) AgentAction {
	name := comm
	if name == "" {
		name = filepath.Base(exePath)
	}

	// Parse JSON argv arrays into readable strings
	readable := formatCmdline(cmdline)

	// Check significant commands
	if sig, ok := significantCommands[name]; ok {
		summary := readable
		if summary == "" {
			summary = name
		}
		// Truncate long cmdlines but keep enough to be useful
		if len(summary) > 120 {
			summary = summary[:117] + "…"
		}
		return AgentAction{
			Category:     "command",
			Action:       fmt.Sprintf("⚙️ Ran: %s", summary),
			Detail:       readable,
			Significance: sig,
		}
	}

	// Default command — always show cmdline when available
	summary := name
	if readable != "" {
		summary = readable
		if len(summary) > 120 {
			summary = summary[:117] + "…"
		}
	}
	return AgentAction{
		Category:     "command",
		Action:       fmt.Sprintf("⚙️ %s", summary),
		Detail:       readable,
		Significance: 2,
	}
}

// --- Helpers ---

func getStringFromMap(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func sortActionsByTime(actions []AgentAction) {
	// Simple insertion sort (actions are usually already mostly sorted)
	for i := 1; i < len(actions); i++ {
		for j := i; j > 0 && actions[j].Timestamp.Before(actions[j-1].Timestamp); j-- {
			actions[j], actions[j-1] = actions[j-1], actions[j]
		}
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	hours := int(d.Hours())
	mins := int(d.Minutes()) % 60
	if mins == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, mins)
}

// Ensure neo4jdriver import is used (the query returns neo4j.Record)
var _ = (*neo4jdriver.Record)(nil)
