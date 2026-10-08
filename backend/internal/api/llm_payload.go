package api

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/incident"
)

// ---------- LLM-specific types (unexported) ----------

type llmPayload struct {
	ID              string             `json:"id"`
	Severity        string             `json:"severity"`
	Confidence      float64            `json:"confidence"`
	Title           string             `json:"title"`
	MITRETechniques []string           `json:"mitre_techniques,omitempty"`
	HostID          string             `json:"host_id"`
	StartedAt       time.Time          `json:"started_at"`
	EndedAt         time.Time          `json:"ended_at"`
	Status          string             `json:"status"`
	FindingGroups   []llmFindingGroup  `json:"finding_groups,omitempty"`
	UniqueFindings  []llmFinding       `json:"unique_findings,omitempty"`
	Timeline        []llmTimelineEntry `json:"timeline,omitempty"`
	ProcessTree     *llmProcessNode    `json:"process_tree,omitempty"`
	EventGraph      *llmEventGraph     `json:"event_graph,omitempty"`
	DataTruncated   map[string]int     `json:"_data_truncated,omitempty"`
}

type llmFindingGroup struct {
	DetectionID     string           `json:"detection_id"`
	Count           int              `json:"count"`
	Severity        string           `json:"severity"`
	ConfidenceRange [2]float64       `json:"confidence_range"`
	Title           string           `json:"title"`
	Process         *llmProcess      `json:"process,omitempty"`
	SampleEvidence  []map[string]any `json:"sample_evidence"`
	Patterns        []string         `json:"patterns,omitempty"`
}

type llmProcess struct {
	PID    int    `json:"pid"`
	Comm   string `json:"comm,omitempty"`
	AIType string `json:"ai_type,omitempty"`
}

type llmFinding struct {
	DetectionID string         `json:"detection_id"`
	Severity    string         `json:"severity"`
	Confidence  float64        `json:"confidence"`
	Title       string         `json:"title"`
	Context     map[string]any `json:"context,omitempty"`
}

type llmTimelineEntry struct {
	Timestamp string `json:"t"`
	Type      string `json:"type"`
	Title     string `json:"title"`
	Severity  string `json:"sev,omitempty"`
	PID       int    `json:"pid,omitempty"`
}

type llmProcessNode struct {
	PID        int               `json:"pid"`
	PPID       int               `json:"ppid"`
	Comm       string            `json:"comm"`
	ExePath    string            `json:"exe_path,omitempty"`
	AIType     string            `json:"ai_type,omitempty"`
	FindingIDs []string          `json:"finding_ids,omitempty"`
	Children   []*llmProcessNode `json:"children,omitempty"`
}

type llmEventGraph struct {
	Nodes []llmEventNode       `json:"nodes"`
	Edges []incident.EventEdge `json:"edges"`
}

type llmEventNode struct {
	ID        string `json:"id"`
	Type      string `json:"type"`
	Timestamp string `json:"t"`
	PID       int    `json:"pid,omitempty"`
	Label     string `json:"label"`
	IsFinding bool   `json:"is_finding,omitempty"`
}

// ---------- Context field allowlist ----------

var llmContextAllowlist = map[string]bool{
	"ai_type":         true,
	"pid":             true,
	"comm":            true,
	"file_path":       true,
	"file_size":       true,
	"dst_ip":          true,
	"dst_port":        true,
	"domain":          true,
	"binary":          true,
	"cmdline":         true,
	"dns_query":       true,
	"category":        true,
	"file_count":      true,
	"file_rate":       true,
	"affected_dirs":   true,
	"sensitive_files": true,
	"chain_pattern":   true,
	"chain_steps":     true,
	"chain_name":      true,
	"reason":          true,
	"internal_threat": true,
	"asn_name":        true,
	"asn":             true,
	"bgp_prefix":      true,
	"dns_domain":      true,
}

// Discriminant fields per detection rule — used to build sample_evidence in rollups.
var discriminantFields = map[string][]string{
	"ai.credential_access":  {"file_path", "file_size"},
	"ai.unauthorized_exec":  {"binary", "cmdline"},
	"ai.excessive_writes":   {"file_count", "file_rate", "affected_dirs"},
	"ai.data_exfiltration":  {"dst_ip", "dst_port", "domain", "dns_domain", "asn_name", "sensitive_files"},
	"ai.unexpected_network": {"dst_ip", "dst_port", "domain", "dns_domain", "asn_name"},
	"ai.suspicious_dns":     {"dns_query", "category"},
}

// ---------- Configurable caps ----------

type payloadCaps struct {
	maxFindingGroups   int
	maxUniqueFindings  int
	maxTimelineEntries int
	maxTreeDepth       int
	maxTreeChildren    int
	maxGraphNodes      int
	maxSampleEvidence  int
}

var standardCaps = payloadCaps{
	maxFindingGroups:   10,
	maxUniqueFindings:  10,
	maxTimelineEntries: 20,
	maxTreeDepth:       5,
	maxTreeChildren:    10,
	maxGraphNodes:      30,
	maxSampleEvidence:  5,
}

var deepCaps = payloadCaps{
	maxFindingGroups:   50,
	maxUniqueFindings:  50,
	maxTimelineEntries: 100,
	maxTreeDepth:       10,
	maxTreeChildren:    20,
	maxGraphNodes:      100,
	maxSampleEvidence:  15,
}

// ---------- Main entry points ----------

// buildLLMPayload creates a token-optimized JSON representation using standard caps.
func buildLLMPayload(detail *incident.IncidentDetail) string {
	return buildLLMPayloadCapped(detail, standardCaps)
}

// buildLLMPayloadDeep creates a detailed JSON representation using deep caps (more tokens).
func buildLLMPayloadDeep(detail *incident.IncidentDetail) string {
	return buildLLMPayloadCapped(detail, deepCaps)
}

func buildLLMPayloadCapped(detail *incident.IncidentDetail, caps payloadCaps) string {
	if detail == nil {
		return "{}"
	}

	truncated := map[string]int{}

	payload := llmPayload{
		ID:              detail.ID,
		Severity:        detail.Severity,
		Confidence:      detail.Confidence,
		Title:           detail.Title,
		MITRETechniques: detail.MITRETechniques,
		HostID:          detail.HostID,
		StartedAt:       detail.StartedAt,
		EndedAt:         detail.EndedAt,
		Status:          detail.Status,
	}

	// A. Finding rollup
	groups, unique := rollupFindings(detail.Findings, truncated, caps)
	payload.FindingGroups = groups
	payload.UniqueFindings = unique

	// B. Timeline compaction
	payload.Timeline = compactTimeline(detail.Timeline, detail.Findings, truncated, caps)

	// C. Process tree capping
	if detail.ProcessTree != nil {
		payload.ProcessTree = capProcessTreeForLLM(detail.ProcessTree, 0, caps)
	}

	// D. Event graph slimming
	if detail.EventGraph != nil {
		payload.EventGraph = slimEventGraph(detail.EventGraph, truncated, caps)
	}

	if len(truncated) > 0 {
		payload.DataTruncated = truncated
	}

	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("ERROR: buildLLMPayload marshal failed: %v", err)
		return "{}"
	}

	log.Printf("[LLM Payload] incident=%s findings=%d→%d_groups+%d_unique timeline=%d→%d graph_nodes=%d→%d bytes=%d est_tokens=%d",
		detail.ID,
		len(detail.Findings), len(groups), len(unique),
		len(detail.Timeline), len(payload.Timeline),
		countGraphNodes(detail.EventGraph), countGraphNodes2(payload.EventGraph),
		len(data), len(data)/4,
	)

	return string(data)
}

// ---------- A. Finding rollup ----------

type findingGroupKey struct {
	DetectionID string
	PID         int
}

func rollupFindings(findings []incident.FindingSummary, truncated map[string]int, caps payloadCaps) ([]llmFindingGroup, []llmFinding) {
	if len(findings) == 0 {
		return nil, nil
	}

	// Sort by severity (desc) then confidence (desc) for smart selection.
	sorted := make([]incident.FindingSummary, len(findings))
	copy(sorted, findings)
	sort.Slice(sorted, func(i, j int) bool {
		si, sj := severityRank(sorted[i].Severity), severityRank(sorted[j].Severity)
		if si != sj {
			return si > sj
		}
		return sorted[i].Confidence > sorted[j].Confidence
	})

	// Group by detection_id + PID.
	groups := map[findingGroupKey][]incident.FindingSummary{}
	var groupOrder []findingGroupKey
	for _, f := range sorted {
		pid := extractPIDFromFinding(f)
		key := findingGroupKey{DetectionID: f.DetectionID, PID: pid}
		if _, exists := groups[key]; !exists {
			groupOrder = append(groupOrder, key)
		}
		groups[key] = append(groups[key], f)
	}

	var resultGroups []llmFindingGroup
	var resultUnique []llmFinding

	// Track detection_id diversity.
	seenDetections := map[string]bool{}

	for _, key := range groupOrder {
		members := groups[key]
		seenDetections[key.DetectionID] = true

		if len(members) == 1 {
			// Singleton — emit as unique finding with stripped context.
			f := members[0]
			resultUnique = append(resultUnique, llmFinding{
				DetectionID: f.DetectionID,
				Severity:    f.Severity,
				Confidence:  f.Confidence,
				Title:       f.Title,
				Context:     stripContext(f.Context),
			})
			continue
		}

		// Multi-member group — rollup.
		best := members[0] // already sorted by severity+confidence
		minConf, maxConf := best.Confidence, best.Confidence
		for _, f := range members[1:] {
			if f.Confidence < minConf {
				minConf = f.Confidence
			}
			if f.Confidence > maxConf {
				maxConf = f.Confidence
			}
		}

		group := llmFindingGroup{
			DetectionID:     key.DetectionID,
			Count:           len(members),
			Severity:        best.Severity,
			ConfidenceRange: [2]float64{minConf, maxConf},
			Title:           best.Title,
		}

		// Process info from the best finding.
		if key.PID != 0 {
			proc := &llmProcess{PID: key.PID}
			if best.Context != nil {
				if v, ok := best.Context["comm"].(string); ok {
					proc.Comm = v
				}
				if v, ok := best.Context["ai_type"].(string); ok {
					proc.AIType = v
				}
			}
			group.Process = proc
		}

		// Sample evidence — extract discriminant fields.
		group.SampleEvidence = extractSampleEvidence(key.DetectionID, members, caps.maxSampleEvidence)

		// Path patterns for credential_access.
		if key.DetectionID == "ai.credential_access" {
			group.Patterns = computePathPatterns(members)
		}

		resultGroups = append(resultGroups, group)
	}

	// Cap total groups.
	if len(resultGroups) > caps.maxFindingGroups {
		truncated["finding_groups_total"] = len(resultGroups)
		resultGroups = resultGroups[:caps.maxFindingGroups]
	}
	if len(resultUnique) > caps.maxUniqueFindings {
		truncated["unique_findings_total"] = len(resultUnique)
		resultUnique = resultUnique[:caps.maxUniqueFindings]
	}

	return resultGroups, resultUnique
}

func extractSampleEvidence(detectionID string, members []incident.FindingSummary, maxSamples int) []map[string]any {
	// For chain findings, keep full stripped context of each member.
	if strings.HasPrefix(detectionID, "chain.") {
		var samples []map[string]any
		for i, f := range members {
			if i >= maxSamples {
				break
			}
			samples = append(samples, stripContext(f.Context))
		}
		return samples
	}

	fields := discriminantFields[detectionID]
	if len(fields) == 0 {
		// Unknown detection — keep full stripped context for first N.
		var samples []map[string]any
		for i, f := range members {
			if i >= maxSamples {
				break
			}
			samples = append(samples, stripContext(f.Context))
		}
		return samples
	}

	// Extract only discriminant fields from each member, dedup by first field.
	seen := map[string]bool{}
	var samples []map[string]any
	for _, f := range members {
		if len(samples) >= maxSamples {
			break
		}
		if f.Context == nil {
			continue
		}

		// Dedup key: first discriminant field's string value.
		dedupVal := fmt.Sprintf("%v", f.Context[fields[0]])
		if seen[dedupVal] {
			continue
		}
		seen[dedupVal] = true

		sample := map[string]any{}
		for _, field := range fields {
			if v, ok := f.Context[field]; ok {
				sample[field] = capArrayValue(v)
			}
		}
		if len(sample) > 0 {
			samples = append(samples, sample)
		}
	}
	return samples
}

func computePathPatterns(members []incident.FindingSummary) []string {
	dirCounts := map[string]int{}
	for _, f := range members {
		if f.Context == nil {
			continue
		}
		fp, ok := f.Context["file_path"].(string)
		if !ok || fp == "" {
			continue
		}
		// Group by 2nd-level directory from home.
		// e.g. /home/user/.cache/fontconfig/... → .cache/fontconfig/*
		dir := filepath.Dir(fp)
		parts := strings.Split(dir, "/")
		// Find the segment after home/user (index 3 typically).
		prefix := dir
		for i, p := range parts {
			if p == "" {
				continue
			}
			// After /home/<user>/ take 2 more segments.
			if i >= 3 && i+1 < len(parts) {
				prefix = strings.Join(parts[:i+2], "/") + "/*"
				break
			}
		}
		dirCounts[prefix]++
	}

	// Sort by count descending.
	type kv struct {
		Pattern string
		Count   int
	}
	var sorted []kv
	for p, c := range dirCounts {
		sorted = append(sorted, kv{p, c})
	}
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Count > sorted[j].Count
	})

	// Top 5 patterns.
	var patterns []string
	for i, kv := range sorted {
		if i >= 5 {
			break
		}
		patterns = append(patterns, fmt.Sprintf("%s (%d)", kv.Pattern, kv.Count))
	}
	return patterns
}

func stripContext(ctx map[string]any) map[string]any {
	if ctx == nil {
		return nil
	}
	stripped := map[string]any{}
	for k, v := range ctx {
		if llmContextAllowlist[k] {
			stripped[k] = capArrayValue(v)
		}
	}
	if len(stripped) == 0 {
		return nil
	}
	return stripped
}

// capArrayValue truncates slice values to at most 10 items to prevent
// massive arrays (e.g. sensitive_files with 176 entries) from blowing up tokens.
func capArrayValue(v any) any {
	const maxArrayItems = 10
	switch arr := v.(type) {
	case []any:
		if len(arr) > maxArrayItems {
			return arr[:maxArrayItems]
		}
	case []string:
		if len(arr) > maxArrayItems {
			return arr[:maxArrayItems]
		}
	}
	return v
}

// ---------- B. Timeline compaction ----------

func compactTimeline(entries []incident.TimelineEntry, findings []incident.FindingSummary, truncated map[string]int, caps payloadCaps) []llmTimelineEntry {
	if len(entries) == 0 {
		return nil
	}

	// Build set of anchor event IDs from findings to deduplicate.
	anchorEventIDs := map[string]bool{}
	for _, f := range findings {
		if f.Context != nil {
			if eid, ok := f.Context["anchor_event_id"].(string); ok && eid != "" {
				anchorEventIDs[eid] = true
			}
		}
	}

	var compacted []llmTimelineEntry
	for _, e := range entries {
		// Deduplicate: skip event-type entries whose EventID matches a finding's anchor.
		if e.Type == "event" && e.EventID != "" && anchorEventIDs[e.EventID] {
			continue
		}

		compacted = append(compacted, llmTimelineEntry{
			Timestamp: e.Timestamp.Format(time.RFC3339),
			Type:      e.Type,
			Title:     e.Title,
			Severity:  e.Severity,
			PID:       e.PID,
		})
	}

	// Cap at configured limit.
	if len(compacted) > caps.maxTimelineEntries {
		truncated["timeline_total"] = len(compacted)
		compacted = compacted[:caps.maxTimelineEntries]
	}

	return compacted
}

// ---------- C. Process tree capping ----------

func capProcessTreeForLLM(node *incident.ProcessNode, depth int, caps payloadCaps) *llmProcessNode {
	if node == nil || depth > caps.maxTreeDepth {
		return nil
	}

	out := &llmProcessNode{
		PID:    node.PID,
		PPID:   node.PPID,
		Comm:   node.Comm,
		AIType: node.AIType,
	}

	// Keep ExePath only for root and finding-bearing nodes.
	if depth == 0 || len(node.FindingIDs) > 0 {
		out.ExePath = node.ExePath
		out.FindingIDs = node.FindingIDs
	}

	if len(node.Children) == 0 {
		return out
	}

	// Sort children: those with FindingIDs first, then by PID.
	children := make([]*incident.ProcessNode, len(node.Children))
	copy(children, node.Children)
	sort.Slice(children, func(i, j int) bool {
		if len(children[i].FindingIDs) != len(children[j].FindingIDs) {
			return len(children[i].FindingIDs) > len(children[j].FindingIDs)
		}
		return children[i].PID < children[j].PID
	})

	cap := caps.maxTreeChildren
	if len(children) < cap {
		cap = len(children)
	}

	for _, child := range children[:cap] {
		if cn := capProcessTreeForLLM(child, depth+1, caps); cn != nil {
			out.Children = append(out.Children, cn)
		}
	}

	return out
}

// ---------- D. Event graph slimming ----------

func slimEventGraph(graph *incident.EventGraph, truncated map[string]int, caps payloadCaps) *llmEventGraph {
	if graph == nil || len(graph.Nodes) == 0 {
		return nil
	}

	nodes := graph.Nodes
	if len(nodes) > caps.maxGraphNodes {
		truncated["graph_nodes_total"] = len(nodes)
		nodes = nodes[:caps.maxGraphNodes]
	}

	nodeSet := make(map[string]bool, len(nodes))
	slim := &llmEventGraph{}
	for _, n := range nodes {
		nodeSet[n.ID] = true
		slim.Nodes = append(slim.Nodes, llmEventNode{
			ID:        n.ID,
			Type:      n.Type,
			Timestamp: n.Timestamp.Format(time.RFC3339),
			PID:       n.PID,
			Label:     n.Label,
			IsFinding: n.IsFinding,
		})
	}

	for _, e := range graph.Edges {
		if nodeSet[e.From] && nodeSet[e.To] {
			slim.Edges = append(slim.Edges, e)
		}
	}

	return slim
}

// ---------- Helpers ----------

func severityRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func extractPIDFromFinding(f incident.FindingSummary) int {
	if f.Context == nil {
		return 0
	}
	switch v := f.Context["pid"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

func countGraphNodes(g *incident.EventGraph) int {
	if g == nil {
		return 0
	}
	return len(g.Nodes)
}

func countGraphNodes2(g *llmEventGraph) int {
	if g == nil {
		return 0
	}
	return len(g.Nodes)
}
