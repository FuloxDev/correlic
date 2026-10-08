package incident

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/process"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
	"github.com/correlic/correlic-backend/internal/storage/neo4j"
)

// ContextAssembler builds full IncidentDetail objects on-demand by combining
// PostgreSQL data (incident + findings) with Neo4j graph data (events, process tree, edges).
type ContextAssembler struct {
	incidentStore *IncidentStore
	findingStore  *storage.FindingStore
	graphStore    *neo4j.GraphStore     // nil = Neo4j unavailable, gracefully degrade
	eventStore    eventstore.EventStore // nil = PostgreSQL fallback unavailable
}

// NewContextAssembler creates a new context assembler.
func NewContextAssembler(incidentStore *IncidentStore, findingStore *storage.FindingStore, graphStore *neo4j.GraphStore, evtStore eventstore.EventStore) *ContextAssembler {
	return &ContextAssembler{
		incidentStore: incidentStore,
		findingStore:  findingStore,
		graphStore:    graphStore,
		eventStore:    evtStore,
	}
}

// Assemble builds the full IncidentDetail including Neo4j event context.
func (a *ContextAssembler) Assemble(ctx context.Context, orgID, incidentID string) (*IncidentDetail, error) {
	// 1. Load incident from PostgreSQL.
	inc, err := a.incidentStore.GetByID(ctx, orgID, incidentID)
	if err != nil {
		return nil, fmt.Errorf("get incident: %w", err)
	}

	detail := &IncidentDetail{
		Incident: *inc,
	}

	// 2. Load all findings for this incident.
	var findings []FindingSummary
	var pids []int64
	var anchorEventIDs []string
	for _, fid := range inc.FindingIDs {
		f, err := a.findingStore.GetByID(orgID, fid)
		if err != nil {
			log.Printf("WARN: finding %s not found for incident %s: %v", fid, incidentID, err)
			continue
		}

		// Collect anchor event IDs for Neo4j attack chain query.
		if f.AnchorEvent != "" {
			anchorEventIDs = append(anchorEventIDs, f.AnchorEvent)
		}

		// Copy context and inject anchor_event_id so event graph can highlight finding nodes.
		ctx := f.Context
		if f.AnchorEvent != "" {
			if ctx == nil {
				ctx = map[string]any{}
			} else {
				// Shallow copy to avoid mutating the original.
				ctxCopy := make(map[string]any, len(ctx)+1)
				for k, v := range ctx {
					ctxCopy[k] = v
				}
				ctx = ctxCopy
			}
			ctx["anchor_event_id"] = f.AnchorEvent
		}

		fs := FindingSummary{
			ID:          f.ID,
			DetectionID: f.DetectionID,
			Severity:    f.Severity,
			Confidence:  f.Confidence,
			Title:       f.Title,
			Summary:     f.Summary,
			Context:     ctx,
			Timestamp:   f.CreatedAt,
			Status:      f.Status,
		}
		findings = append(findings, fs)

		// Collect PIDs for process tree query.
		if f.Context != nil {
			if pid, ok := f.Context["pid"]; ok {
				switch p := pid.(type) {
				case float64:
					pids = append(pids, int64(p))
				case int:
					pids = append(pids, int64(p))
				}
			}
		}
	}
	detail.Findings = findings

	// 3. Build timeline from findings.
	timeline := buildFindingTimeline(findings)

	// 4. Query Neo4j for event context (if available).
	// Use a timeout so the endpoint degrades gracefully when Neo4j is down or slow.
	if a.graphStore != nil && len(findings) > 0 {
		graphCtx, graphCancel := context.WithTimeout(ctx, 10*time.Second)
		defer graphCancel()

		// Find the oldest finding's anchor event to start the attack chain query.
		firstFinding := findings[0]
		for _, f := range findings {
			if f.Timestamp.Before(firstFinding.Timestamp) {
				firstFinding = f
			}
		}

		// Time window: incident duration + 10min padding on each side.
		duration := inc.EndedAt.Sub(inc.StartedAt)
		if duration < time.Minute {
			duration = time.Minute
		}
		timeWindow := duration + 20*time.Minute

		// Get the anchor event ID from the earliest finding.
		anchorEventID := ""
		if len(anchorEventIDs) > 0 {
			anchorEventID = anchorEventIDs[0]
		}
		// Use the first finding's context to get an event ID for the chain query.
		// Fall back to PID-based query if no event ID available.
		var graphResult *neo4j.GraphQueryResult
		if anchorEventID != "" {
			graphResult, err = a.graphStore.QueryAttackChain(graphCtx, neo4j.AttackChainQuery{
				StartEventID: anchorEventID,
				HostID:       inc.HostID,
				MaxDepth:     15,
				TimeWindow:   timeWindow,
			})
		} else if len(pids) > 0 {
			graphResult, err = a.graphStore.QueryAttackChain(graphCtx, neo4j.AttackChainQuery{
				StartPID:   pids[0],
				HostID:     inc.HostID,
				MaxDepth:   15,
				TimeWindow: timeWindow,
			})
		}

		if err != nil {
			log.Printf("WARN: attack chain query failed for incident %s: %v", incidentID, err)
		}

		if graphResult != nil {
			// Add event nodes to timeline.
			eventTimeline := graphResultToTimeline(graphResult)
			timeline = append(timeline, eventTimeline...)

			// Convert to incident event graph.
			detail.EventGraph = graphResultToEventGraph(graphResult, findings)
		}

		// 5. Build process tree from ALL unique PIDs in a single batch query.
		if len(pids) > 0 {
			uniquePIDs := deduplicatePIDs(pids)
			// Cap at 20 PIDs to prevent runaway queries
			if len(uniquePIDs) > 20 {
				uniquePIDs = uniquePIDs[:20]
			}
			treeResult, treeErr := a.graphStore.GetProcessTreeMultiPID(graphCtx, uniquePIDs, inc.HostID)
			if treeErr != nil {
				log.Printf("WARN: batch process tree query failed for incident %s (%d PIDs): %v", incidentID, len(uniquePIDs), treeErr)
			}
			if treeResult != nil {
				detail.ProcessTree = graphResultToProcessTree(treeResult, findings)
			}
		}

		// 6. Build ProcessDetails from attack chain events.
		if graphResult != nil {
			detail.ProcessDetails = buildProcessDetailsFromEventNodes(graphResult.Events)
		}
	}

	// 7. PostgreSQL fallback: if Neo4j did not produce a process tree and we have
	// an event store, query the events table for host_id + time window and build
	// a tree from process_exec/process_exit events.
	if detail.ProcessTree == nil && a.eventStore != nil && inc.HostID != "" {
		fallbackCtx, fallbackCancel := context.WithTimeout(ctx, 10*time.Second)
		defer fallbackCancel()

		from := inc.StartedAt.Add(-5 * time.Minute)
		to := inc.EndedAt.Add(5 * time.Minute)
		events, evtErr := a.eventStore.GetRange(fallbackCtx, inc.HostID, from, to)
		if evtErr != nil {
			log.Printf("WARN: event store fallback failed for incident %s: %v", incidentID, evtErr)
		} else if len(events) > 0 {
			lifecycles := process.BuildLifecyclesFromEvents(events)
			if len(lifecycles) > 0 {
				detail.ProcessTree = lifecyclesToProcessTree(lifecycles, findings)
			}
			if len(detail.ProcessDetails) == 0 {
				detail.ProcessDetails = buildProcessDetailsFromEvents(events)
			}
		}
	}

	// Sort timeline chronologically.
	sort.Slice(timeline, func(i, j int) bool {
		return timeline[i].Timestamp.Before(timeline[j].Timestamp)
	})
	detail.Timeline = timeline

	return detail, nil
}

// AssembleTimeline returns only the timeline for an incident (lighter endpoint).
func (a *ContextAssembler) AssembleTimeline(ctx context.Context, orgID, incidentID string) ([]TimelineEntry, error) {
	detail, err := a.Assemble(ctx, orgID, incidentID)
	if err != nil {
		return nil, err
	}
	return detail.Timeline, nil
}

// buildFindingTimeline creates timeline entries from findings.
func buildFindingTimeline(findings []FindingSummary) []TimelineEntry {
	var entries []TimelineEntry
	for _, f := range findings {
		entryType := "finding"
		if len(f.DetectionID) > 6 && f.DetectionID[:6] == "chain." {
			entryType = "chain"
		}
		entries = append(entries, TimelineEntry{
			Timestamp: f.Timestamp,
			Type:      entryType,
			Title:     f.Title,
			Detail:    f.Summary,
			Severity:  f.Severity,
			FindingID: f.ID,
			PID:       extractPIDFromContext(f.Context),
		})
	}
	return entries
}

// graphResultToTimeline converts Neo4j graph result events into timeline entries.
func graphResultToTimeline(result *neo4j.GraphQueryResult) []TimelineEntry {
	var entries []TimelineEntry
	for _, evt := range result.Events {
		label := eventLabel(evt)
		entries = append(entries, TimelineEntry{
			Timestamp: evt.Timestamp,
			Type:      "event",
			EventType: evt.Type,
			Title:     label,
			EventID:   evt.ID,
			PID:       int(evt.ActorPID),
		})
	}
	return entries
}

// graphResultToEventGraph converts a Neo4j graph result into the incident event graph format.
func graphResultToEventGraph(result *neo4j.GraphQueryResult, findings []FindingSummary) *EventGraph {
	if result == nil {
		return nil
	}

	// Build a set of finding anchor event IDs for highlighting.
	findingEvents := make(map[string]bool)
	for _, f := range findings {
		if f.Context != nil {
			if eid, ok := f.Context["anchor_event_id"]; ok {
				if s, ok := eid.(string); ok {
					findingEvents[s] = true
				}
			}
		}
	}

	graph := &EventGraph{}
	for _, evt := range result.Events {
		graph.Nodes = append(graph.Nodes, EventNode{
			ID:        evt.ID,
			Type:      evt.Type,
			Timestamp: evt.Timestamp,
			PID:       int(evt.ActorPID),
			Label:     eventLabel(evt),
			IsFinding: findingEvents[evt.ID],
		})
	}
	for _, edge := range result.Relationships {
		graph.Edges = append(graph.Edges, EventEdge{
			From: edge.FromID,
			To:   edge.ToID,
			Type: edge.Type,
		})
	}
	return graph
}

// graphResultToProcessTree converts a Neo4j process tree result into a ProcessNode tree.
func graphResultToProcessTree(result *neo4j.GraphQueryResult, findings []FindingSummary) *ProcessNode {
	if result == nil || len(result.Events) == 0 {
		return nil
	}

	// Build finding PID lookup for highlighting.
	findingPIDs := make(map[int64][]string)
	for _, f := range findings {
		if f.Context != nil {
			if pid, ok := f.Context["pid"]; ok {
				switch p := pid.(type) {
				case float64:
					findingPIDs[int64(p)] = append(findingPIDs[int64(p)], f.ID)
				case int:
					findingPIDs[int64(p)] = append(findingPIDs[int64(p)], f.ID)
				}
			}
		}
	}

	// Build node map.
	nodeMap := make(map[int64]*ProcessNode)
	for _, evt := range result.Events {
		if evt.Type != "process_exec" {
			continue
		}
		node := &ProcessNode{
			PID:        int(evt.ActorPID),
			PPID:       int(evt.ActorPPID),
			Comm:       getStringProp(evt.Properties, "actor_comm"),
			ExePath:    evt.ActorExe,
			User:       evt.ActorUser,
			FindingIDs: findingPIDs[evt.ActorPID],
		}
		if aiType, ok := evt.Properties["ai_type"]; ok {
			if s, ok := aiType.(string); ok {
				node.AIType = s
			}
		}
		ts := evt.Timestamp
		node.StartedAt = &ts
		nodeMap[evt.ActorPID] = node
	}

	// Link children to parents.
	var roots []*ProcessNode
	for _, node := range nodeMap {
		parent, exists := nodeMap[int64(node.PPID)]
		if exists {
			parent.Children = append(parent.Children, node)
		} else {
			roots = append(roots, node)
		}
	}

	if len(roots) == 0 {
		return nil
	}
	// Return the first root (most common case: single process ancestry).
	return roots[0]
}

// eventLabel creates a human-readable label for a graph event node.
func eventLabel(evt neo4j.EventNode) string {
	switch evt.Type {
	case "process_exec":
		if evt.ActorExe != "" {
			return fmt.Sprintf("exec %s (PID %d)", evt.ActorExe, evt.ActorPID)
		}
		return fmt.Sprintf("exec PID %d", evt.ActorPID)
	case "process_exit":
		return fmt.Sprintf("exit PID %d", evt.ActorPID)
	case "file_open":
		if evt.TargetPath != "" {
			return fmt.Sprintf("open %s", evt.TargetPath)
		}
		return "file_open"
	case "net_connect":
		if evt.TargetIP != "" {
			return fmt.Sprintf("connect %s:%d", evt.TargetIP, evt.TargetPort)
		}
		return "net_connect"
	case "net_dns":
		if props := evt.Properties; props != nil {
			if domain, ok := props["target_domain"]; ok {
				return fmt.Sprintf("DNS %v", domain)
			}
		}
		return "net_dns"
	default:
		return evt.Type
	}
}

// extractPIDFromContext gets a PID from a finding's context map.
// getStringProp safely extracts a string value from a properties map.
func getStringProp(props map[string]any, key string) string {
	if v, ok := props[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func extractPIDFromContext(ctx map[string]any) int {
	if ctx == nil {
		return 0
	}
	if pid, ok := ctx["pid"]; ok {
		switch p := pid.(type) {
		case float64:
			return int(p)
		case int:
			return p
		}
	}
	return 0
}

// deduplicatePIDs returns unique PIDs preserving order.
func deduplicatePIDs(pids []int64) []int64 {
	seen := make(map[int64]bool, len(pids))
	var out []int64
	for _, pid := range pids {
		if !seen[pid] {
			seen[pid] = true
			out = append(out, pid)
		}
	}
	return out
}

// buildProcessDetailsFromEventNodes groups attack chain EventNodes by PID and
// builds a ProcessDetail for each process, aggregating file, network, and DNS activity.
func buildProcessDetailsFromEventNodes(events []neo4j.EventNode) []ProcessDetail {
	type pidInfo struct {
		detail ProcessDetail
		files  map[string]bool
		conns  map[string]bool
		dns    map[string]bool
	}
	byPID := make(map[int64]*pidInfo)

	for _, evt := range events {
		pid := evt.ActorPID
		if pid == 0 {
			continue
		}
		info, exists := byPID[pid]
		if !exists {
			info = &pidInfo{
				detail: ProcessDetail{
					PID:       pid,
					PPID:      evt.ActorPPID,
					Exe:       evt.ActorExe,
					User:      evt.ActorUser,
					StartedAt: evt.Timestamp,
				},
				files: make(map[string]bool),
				conns: make(map[string]bool),
				dns:   make(map[string]bool),
			}
			if cmdline := getStringProp(evt.Properties, "cmdline"); cmdline != "" {
				info.detail.Cmdline = cmdline
			}
			byPID[pid] = info
		}
		// Track earliest timestamp as StartedAt.
		if evt.Timestamp.Before(info.detail.StartedAt) {
			info.detail.StartedAt = evt.Timestamp
		}
		// Prefer cmdline from process_exec events.
		if evt.Type == "process_exec" {
			if cmdline := getStringProp(evt.Properties, "cmdline"); cmdline != "" {
				info.detail.Cmdline = cmdline
			}
			if evt.ActorExe != "" {
				info.detail.Exe = evt.ActorExe
			}
		}

		switch evt.Type {
		case "file_open":
			if evt.TargetPath != "" && !info.files[evt.TargetPath] {
				info.files[evt.TargetPath] = true
				info.detail.Files = append(info.detail.Files, evt.TargetPath)
			}
		case "net_connect":
			if evt.TargetIP != "" {
				conn := fmt.Sprintf("%s:%d", evt.TargetIP, evt.TargetPort)
				if !info.conns[conn] {
					info.conns[conn] = true
					info.detail.NetConns = append(info.detail.NetConns, conn)
				}
			}
		case "net_dns":
			domain := getStringProp(evt.Properties, "target_domain")
			if domain != "" && !info.dns[domain] {
				info.dns[domain] = true
				info.detail.DNSQueries = append(info.detail.DNSQueries, domain)
			}
		}
	}

	details := make([]ProcessDetail, 0, len(byPID))
	for _, info := range byPID {
		details = append(details, info.detail)
	}
	// Sort by StartedAt for deterministic output.
	sort.Slice(details, func(i, j int) bool {
		return details[i].StartedAt.Before(details[j].StartedAt)
	})
	return details
}

// lifecyclesToProcessTree converts process.Lifecycle trees into the incident ProcessNode tree.
func lifecyclesToProcessTree(lifecycles []*process.Lifecycle, findings []FindingSummary) *ProcessNode {
	// Build finding PID lookup for highlighting.
	findingPIDs := make(map[int64][]string)
	for _, f := range findings {
		if f.Context != nil {
			if pid, ok := f.Context["pid"]; ok {
				switch p := pid.(type) {
				case float64:
					findingPIDs[int64(p)] = append(findingPIDs[int64(p)], f.ID)
				case int:
					findingPIDs[int64(p)] = append(findingPIDs[int64(p)], f.ID)
				}
			}
		}
	}

	var convert func(lc *process.Lifecycle) *ProcessNode
	convert = func(lc *process.Lifecycle) *ProcessNode {
		node := &ProcessNode{
			PID:        lc.PID,
			PPID:       lc.PPID,
			ExePath:    lc.ExePath,
			FindingIDs: findingPIDs[int64(lc.PID)],
		}
		if lc.ExecEvent != nil && lc.ExecEvent.Process != nil {
			node.Comm = lc.ExecEvent.Process.Comm
			node.User = lc.ExecEvent.Process.User
		}
		ts := lc.StartTime
		node.StartedAt = &ts
		for _, child := range lc.Children {
			node.Children = append(node.Children, convert(child))
		}
		return node
	}

	if len(lifecycles) == 1 {
		return convert(lifecycles[0])
	}
	// Multiple roots: create a synthetic root node.
	root := &ProcessNode{
		PID:  0,
		Comm: "(root)",
	}
	for _, lc := range lifecycles {
		root.Children = append(root.Children, convert(lc))
	}
	return root
}

// buildProcessDetailsFromEvents builds ProcessDetails from raw event.Event slices
// (PostgreSQL fallback path). Groups by PID and aggregates file, network, DNS activity.
func buildProcessDetailsFromEvents(events []event.Event) []ProcessDetail {
	type pidInfo struct {
		detail ProcessDetail
		files  map[string]bool
		conns  map[string]bool
		dns    map[string]bool
	}
	byPID := make(map[int64]*pidInfo)

	for _, evt := range events {
		if evt.Process == nil || evt.Process.PID == 0 {
			continue
		}
		pid := int64(evt.Process.PID)
		info, exists := byPID[pid]
		if !exists {
			info = &pidInfo{
				detail: ProcessDetail{
					PID:       pid,
					PPID:      int64(evt.Process.PPID),
					Exe:       evt.Process.ExePath,
					User:      evt.Process.User,
					StartedAt: evt.Timestamp,
				},
				files: make(map[string]bool),
				conns: make(map[string]bool),
				dns:   make(map[string]bool),
			}
			if len(evt.Process.Cmdline) > 0 {
				info.detail.Cmdline = strings.Join(evt.Process.Cmdline, " ")
			}
			byPID[pid] = info
		}
		if evt.Timestamp.Before(info.detail.StartedAt) {
			info.detail.StartedAt = evt.Timestamp
		}
		// Prefer identity from process_exec events.
		if evt.Type == "process_exec" {
			if evt.Process.ExePath != "" {
				info.detail.Exe = evt.Process.ExePath
			}
			if len(evt.Process.Cmdline) > 0 {
				info.detail.Cmdline = strings.Join(evt.Process.Cmdline, " ")
			}
			if evt.Process.User != "" {
				info.detail.User = evt.Process.User
			}
		}

		if evt.Target == nil {
			continue
		}
		switch evt.Type {
		case "file_open":
			if evt.Target.FilePath != "" && !info.files[evt.Target.FilePath] {
				info.files[evt.Target.FilePath] = true
				info.detail.Files = append(info.detail.Files, evt.Target.FilePath)
			}
		case "net_connect":
			if evt.Target.IP != "" {
				conn := fmt.Sprintf("%s:%d", evt.Target.IP, evt.Target.Port)
				if !info.conns[conn] {
					info.conns[conn] = true
					info.detail.NetConns = append(info.detail.NetConns, conn)
				}
			}
		case "net_dns":
			if evt.Target.Domain != "" && !info.dns[evt.Target.Domain] {
				info.dns[evt.Target.Domain] = true
				info.detail.DNSQueries = append(info.detail.DNSQueries, evt.Target.Domain)
			}
		}
	}

	details := make([]ProcessDetail, 0, len(byPID))
	for _, info := range byPID {
		details = append(details, info.detail)
	}
	sort.Slice(details, func(i, j int) bool {
		return details[i].StartedAt.Before(details[j].StartedAt)
	})
	return details
}
