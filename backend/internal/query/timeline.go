package query

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/storage/neo4j"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// TimelineService provides timeline reconstruction queries
type TimelineService struct {
	graphStore *neo4j.GraphStore
	client     *neo4j.Client
	db         *sql.DB
}

// NewTimelineService creates a new timeline service
func NewTimelineService(client *neo4j.Client, graphStore *neo4j.GraphStore, db *sql.DB) *TimelineService {
	return &TimelineService{
		client:     client,
		graphStore: graphStore,
		db:         db,
	}
}

// Timeline represents a correlated sequence of events
type Timeline struct {
	AnchorEvent *event.Event   `json:"anchor_event"`
	Events      []*event.Event `json:"events"`
	TotalEvents int            `json:"total_events"`
	WindowStart time.Time      `json:"window_start"`
	WindowEnd   time.Time      `json:"window_end"`
}

// ProcessTree represents a process hierarchy
type ProcessTree struct {
	RootProcess *event.Event   `json:"root_process"`
	Children    []*event.Event `json:"children"`
	Depth       int            `json:"depth"`
}

// AttackPath represents a potential attack chain
type AttackPath struct {
	RootEvent *event.Event   `json:"root_event"`
	Path      []*event.Event `json:"path"`
	EdgeTypes []string       `json:"edge_types"`
}

// GetTimeline retrieves all correlated events within a time window
func (s *TimelineService) GetTimeline(ctx context.Context, anchorID string, windowMinutes int) (*Timeline, error) {
	query := `
		MATCH (anchor:Event {id: $anchor_id})
		MATCH path = (anchor)-[*0..10]-(related:Event)
		WHERE related.timestamp >= datetime(anchor.timestamp) - duration({minutes: $window})
		  AND related.timestamp <= datetime(anchor.timestamp) + duration({minutes: $window})
		RETURN DISTINCT related
		ORDER BY related.timestamp
	`

	params := map[string]any{
		"anchor_id": anchorID,
		"window":    windowMinutes,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("timeline query failed: %w", err)
	}

	var events []*event.Event
	for _, record := range result.Records {
		node, ok := record.Values[0].(neo4jdriver.Node)
		if !ok {
			continue
		}
		evt := nodeToEvent(node)
		events = append(events, evt)
	}

	// Get anchor event
	var anchorEvent *event.Event
	if len(events) > 0 {
		anchorEvent = events[0]
	}

	return &Timeline{
		AnchorEvent: anchorEvent,
		Events:      events,
		TotalEvents: len(events),
		WindowStart: time.Now().Add(-time.Duration(windowMinutes) * time.Minute),
		WindowEnd:   time.Now().Add(time.Duration(windowMinutes) * time.Minute),
	}, nil
}

// GetProcessTree retrieves the process hierarchy for a given PID
func (s *TimelineService) GetProcessTree(ctx context.Context, rootPID int, hostID string, maxDepth int) (*ProcessTree, error) {
	query := `
		MATCH (root:Event {actor_pid: $pid, host_id: $host_id, type: 'process_exec'})
		MATCH path = (root)-[:PROCESS_PARENT*0..%d]->(child:Event)
		WHERE child.type = 'process_exec'
		RETURN DISTINCT child
		ORDER BY child.timestamp
	`

	if maxDepth <= 0 {
		maxDepth = 5
	}
	query = fmt.Sprintf(query, maxDepth)

	params := map[string]any{
		"pid":     rootPID,
		"host_id": hostID,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("process tree query failed: %w", err)
	}

	var children []*event.Event
	var rootProcess *event.Event

	for _, record := range result.Records {
		node, ok := record.Values[0].(neo4jdriver.Node)
		if !ok {
			continue
		}
		evt := nodeToEvent(node)

		if evt.Process != nil && evt.Process.PID == rootPID {
			rootProcess = evt
		} else {
			children = append(children, evt)
		}
	}

	return &ProcessTree{
		RootProcess: rootProcess,
		Children:    children,
		Depth:       maxDepth,
	}, nil
}

// GetAttackPath finds potential attack chains from a root event
func (s *TimelineService) GetAttackPath(ctx context.Context, rootEventID string) (*AttackPath, error) {
	query := `
		MATCH path = (root:Event {id: $root_id})
		  -[:PROCESS_PARENT|NET_CONNECT|FILE_ACCESS*1..10]->(related:Event)
		WHERE related.type IN ['process_exec', 'net_connect', 'file_open']
		RETURN path
		LIMIT 100
	`

	params := map[string]any{
		"root_id": rootEventID,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("attack path query failed: %w", err)
	}

	var pathEvents []*event.Event
	var edgeTypes []string

	for _, record := range result.Records {
		path, ok := record.Values[0].(neo4jdriver.Path)
		if !ok {
			continue
		}

		// Extract nodes and relationships from path
		for _, node := range path.Nodes {
			evt := nodeToEvent(node)
			pathEvents = append(pathEvents, evt)
		}

		for _, rel := range path.Relationships {
			edgeTypes = append(edgeTypes, rel.Type)
		}
	}

	var rootEvent *event.Event
	if len(pathEvents) > 0 {
		rootEvent = pathEvents[0]
	}

	return &AttackPath{
		RootEvent: rootEvent,
		Path:      pathEvents,
		EdgeTypes: edgeTypes,
	}, nil
}

// GetActiveProcesses returns all active processes with their activity stats for the timeline view
func (s *TimelineService) GetActiveProcesses(ctx context.Context, since time.Time, aiOnly bool) (*ProcessTreeResponse, error) {
	sinceStr := since.Format(time.RFC3339)

	// First get total count for accurate stats
	countQuery := `
		MATCH (p:Event)
		WHERE p.type = 'process_exec' 
		  AND p.timestamp >= datetime($since)
		  AND ($ai_only = false OR p.ai_type IS NOT NULL)
		RETURN count(p) as total
	`
	countResult, err := s.client.ExecuteRead(ctx, countQuery, map[string]any{
		"since":   sinceStr,
		"ai_only": aiOnly,
	})
	if err != nil {
		return nil, fmt.Errorf("count query failed: %w", err)
	}
	var actualTotal int
	if len(countResult.Records) > 0 {
		if val, ok := countResult.Records[0].Values[0].(int64); ok {
			actualTotal = int(val)
		}
	}

	// Query to get all process_exec events with their activity counts.
	// KEY CHANGE: Returns the actual PROCESS_PARENT graph edge parent (graphParent.id)
	// instead of relying on Go-side PPID matching. This ensures the tree is always
	// correct regardless of PID reuse or time window boundaries.
	query := `
		// 1. Find active processes in the window
		MATCH (active:Event)
		WHERE active.type = 'process_exec' 
		  AND active.timestamp >= datetime($since)
		  AND ($ai_only = false OR active.ai_type IS NOT NULL)
		WITH collect(DISTINCT active) as activeNodes

		// 2. Find their ancestors (parents) regardless of timestamp to connect the tree
		UNWIND activeNodes as active
		OPTIONAL MATCH (ancestor:Event)-[:PROCESS_PARENT*1..10]->(active)
		WHERE ancestor.type = 'process_exec'
		WITH activeNodes, collect(DISTINCT ancestor) as ancestorNodes

		// 3. Union all nodes, mark all as active for display
		WITH activeNodes + ancestorNodes as allNodes, activeNodes
		UNWIND allNodes as p
		WITH DISTINCT p, true as isActive

		// 4. Find the ACTUAL graph-edge parent for each node (key fix for tree building)
		OPTIONAL MATCH (graphParent:Event)-[:PROCESS_PARENT]->(p)

		// 5. Get activity stats
		RETURN p, 
		       CASE WHEN isActive THEN count { 
                   MATCH (p)-[:PROCESS_PARENT|AI_SPAWNED]->(child:Event {type: 'process_exec'}) 
               } ELSE 0 END as child_count,
		       
		       CASE WHEN isActive THEN count { 
                   MATCH (file:Event) 
                   WHERE file.type IN ['file_open', 'file_write'] 
                     AND file.actor_pid = p.actor_pid 
                     AND file.host_id = p.host_id 
               } ELSE 0 END as file_count,
		       
		       CASE WHEN isActive THEN count { 
                   MATCH (net:Event) 
                   WHERE net.type IN ['net_connect', 'net_accept', 'net_dns'] 
                     AND net.actor_pid = p.actor_pid 
                     AND net.host_id = p.host_id 
               } ELSE 0 END as net_count,
		       
		       CASE WHEN isActive THEN count { 
                   MATCH (port:Event) 
                   WHERE port.type = 'net_listen' 
                     AND port.actor_pid = p.actor_pid 
                     AND port.host_id = p.host_id 
               } ELSE 0 END as port_count,
		       
		       p.ai_type as ai_type, 
		       p.ai_root as ai_root,
		       graphParent.id as graph_parent_id
		ORDER BY CASE WHEN p.ai_type IS NOT NULL THEN 0 ELSE 1 END, p.timestamp DESC
		LIMIT 2000
	`

	params := map[string]any{
		"since":   sinceStr,
		"ai_only": aiOnly,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("active processes query failed: %w", err)
	}

	// Build tree: dedup by PID+HostID (one node per actual running process),
	// preferring the event that has a PROCESS_PARENT graph edge.
	// The eBPF agent may emit multiple process_exec events for the same long-running
	// process (periodic re-reporting), so we must collapse them into one UI node.
	type pidKey struct {
		pid    int
		hostID string
	}
	type nodeEntry struct {
		node          *ProcessNode
		graphParentID string // event ID of parent from PROCESS_PARENT edge
		eventID       string // the chosen event ID for this PID
	}
	nodesByPID := make(map[pidKey]*nodeEntry)
	rootNodes := make([]*ProcessNode, 0)

	for _, record := range result.Records {
		node, ok := record.Values[0].(neo4jdriver.Node)
		if !ok {
			continue
		}
		props := node.Props

		eventID := getString(props, "id")
		if eventID == "" {
			continue
		}

		pid := getInt(props, "actor_pid")
		ppid := getInt(props, "actor_ppid")
		hostID := getString(props, "host_id")

		// Get the graph-edge parent ID (returned by query as graph_parent_id, index 7)
		graphParentID := ""
		if len(record.Values) > 7 {
			if v, ok := record.Values[7].(string); ok {
				graphParentID = v
			}
		}

		key := pidKey{pid: pid, hostID: hostID}

		// Dedup by PID+HostID: keep the event that HAS a graph-edge parent.
		// If we already have an entry with a parent edge, skip this one.
		// If we have an entry WITHOUT a parent edge but this one HAS one, replace.
		if existing, exists := nodesByPID[key]; exists {
			if existing.graphParentID != "" {
				// Already have a well-linked event for this PID, skip
				continue
			}
			if graphParentID == "" {
				// Both lack parent edges, keep the existing one
				continue
			}
			// This event has a parent edge but existing doesn't — replace
		}

		// Parse timestamps
		var startedAt, lastSeenAt time.Time
		if ts := getTime(props, "timestamp"); !ts.IsZero() {
			startedAt = ts
			lastSeenAt = ts
		}

		pn := &ProcessNode{
			PID:  pid,
			PPID: ppid,
			Comm: func() string {
				c := getString(props, "actor_comm")
				if c != "" {
					return c
				}
				exe := getString(props, "actor_exe_path")
				if exe != "" {
					if idx := len(exe) - 1; idx >= 0 {
						for i := idx; i >= 0; i-- {
							if exe[i] == '/' {
								return exe[i+1:]
							}
						}
						return exe
					}
				}
				return "unknown"
			}(),
			Role:       getString(props, "actor_role"),
			ExePath:    getString(props, "actor_exe_path"),
			Cmdline:    getString(props, "actor_cmdline"),
			User:       getString(props, "actor_user"),
			HostID:     hostID,
			StartedAt:  startedAt,
			LastSeenAt: lastSeenAt,
			DurationMs: time.Since(startedAt).Milliseconds(),
			AIType:     getString(props, "ai_type"),
			AIRoot:     getString(props, "ai_root"),
			Stats: ProcessStats{
				FilesAccessed: getIntFromRecord(record, 2),
				Connections:   getIntFromRecord(record, 3),
				PortsOpened:   getIntFromRecord(record, 4),
				ChildCount:    getIntFromRecord(record, 1),
				EventCount:    1 + getIntFromRecord(record, 2) + getIntFromRecord(record, 3),
			},
			Children: make([]*ProcessNode, 0),
		}

		nodesByPID[key] = &nodeEntry{
			node:          pn,
			graphParentID: graphParentID,
			eventID:       eventID,
		}
	}

	// Build an eventID → pidKey lookup for graph-edge parent resolution
	eventIDToPID := make(map[string]pidKey)
	for key, entry := range nodesByPID {
		eventIDToPID[entry.eventID] = key
	}

	// Build tree structure using graph edges first, then PPID fallback.
	for key, entry := range nodesByPID {
		// Strategy 1: Use graph-edge parent (most accurate)
		if entry.graphParentID != "" {
			if parentKey, ok := eventIDToPID[entry.graphParentID]; ok {
				if parentEntry, ok2 := nodesByPID[parentKey]; ok2 {
					parentEntry.node.Children = append(parentEntry.node.Children, entry.node)
					parentEntry.node.Stats.ChildCount = len(parentEntry.node.Children)
					continue
				}
			}
		}

		// Strategy 2: PPID fallback — find a node with matching PID in the same host
		parentKey := pidKey{pid: entry.node.PPID, hostID: key.hostID}
		if parentEntry, ok := nodesByPID[parentKey]; ok && parentKey != key {
			parentEntry.node.Children = append(parentEntry.node.Children, entry.node)
			parentEntry.node.Stats.ChildCount = len(parentEntry.node.Children)
			continue
		}

		// No parent found → root node
		rootNodes = append(rootNodes, entry.node)
	}

	return &ProcessTreeResponse{
		Processes:   rootNodes,
		TotalCount:  actualTotal,
		WindowStart: since,
		WindowEnd:   time.Now(),
	}, nil
}

// AIStatsFromGraph contains aggregate AI metrics from Neo4j
type AIStatsFromGraph struct {
	Connections     int `json:"connections"`
	FilesAccessed   int `json:"files_accessed"`
	PortsOpened     int `json:"ports_opened"`
	UniqueProcesses int `json:"unique_processes"`
}

// GetAIStats returns aggregate network/file/port stats for AI processes scoped to an org.
// It queries PostgreSQL for the org's agent_ids (which map to Neo4j host_ids) and filters.
func (s *TimelineService) GetAIStats(ctx context.Context, orgID string, since time.Time) (*AIStatsFromGraph, error) {
	// Query PostgreSQL for host_ids belonging to this org
	rows, err := s.db.QueryContext(ctx,
		`SELECT agent_id FROM agents WHERE org_id = $1::uuid`, orgID)
	if err != nil {
		return nil, fmt.Errorf("query org hosts: %w", err)
	}
	defer rows.Close()
	var hostIDs []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			continue
		}
		hostIDs = append(hostIDs, h)
	}
	if len(hostIDs) == 0 {
		return &AIStatsFromGraph{}, nil
	}

	sinceStr := since.Format(time.RFC3339)

	query := `
		MATCH (p:Event)
		WHERE p.type = 'process_exec'
		  AND p.timestamp >= datetime($since)
		  AND p.ai_type IS NOT NULL
		  AND p.host_id IN $host_ids
		WITH p, p.actor_pid as pid, p.host_id as host_id
		OPTIONAL MATCH (net:Event)
		WHERE net.type IN ['net_connect', 'net_accept'] 
		  AND net.actor_pid = pid 
		  AND net.host_id = host_id
		WITH p, pid, host_id, count(DISTINCT net) as net_count
		OPTIONAL MATCH (file:Event)
		WHERE file.type IN ['file_open', 'file_write'] 
		  AND file.actor_pid = pid 
		  AND file.host_id = host_id
		WITH p, pid, host_id, net_count, count(DISTINCT file) as file_count
		OPTIONAL MATCH (port:Event)
		WHERE port.type = 'net_listen' 
		  AND port.actor_pid = pid 
		  AND port.host_id = host_id
		WITH p, net_count, file_count, count(DISTINCT port) as port_count
		RETURN sum(net_count) as total_connections, 
		       sum(file_count) as total_files, 
		       sum(port_count) as total_ports,
		       count(DISTINCT p) as unique_processes
	`

	params := map[string]any{
		"since":    sinceStr,
		"host_ids": hostIDs,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("AI stats query failed: %w", err)
	}

	stats := &AIStatsFromGraph{}
	if len(result.Records) > 0 {
		record := result.Records[0]
		if val, ok := record.Values[0].(int64); ok {
			stats.Connections = int(val)
		}
		if val, ok := record.Values[1].(int64); ok {
			stats.FilesAccessed = int(val)
		}
		if val, ok := record.Values[2].(int64); ok {
			stats.PortsOpened = int(val)
		}
		if val, ok := record.Values[3].(int64); ok {
			stats.UniqueProcesses = int(val)
		}
	}

	return stats, nil
}

// nodeToEvent converts a Neo4j node to an Event struct
func nodeToEvent(node neo4jdriver.Node) *event.Event {
	props := node.Props

	evt := &event.Event{
		ID:     getString(props, "id"),
		HostID: getString(props, "host_id"),
		Source: getString(props, "source"),
		Type:   getString(props, "type"),
	}

	// Parse timestamp (the driver returns time.Time; older nodes may hold strings)
	if ts := getTime(props, "timestamp"); !ts.IsZero() {
		evt.Timestamp = ts
	} else if tsStr := getString(props, "timestamp"); tsStr != "" {
		if ts, err := time.Parse(time.RFC3339Nano, tsStr); err == nil {
			evt.Timestamp = ts
		}
	}

	// Parse actor (field name is Process, type is ActorStruct)
	if getInt(props, "actor_pid") > 0 {
		evt.Process = &event.ActorStruct{
			PID:     getInt(props, "actor_pid"),
			PPID:    getInt(props, "actor_ppid"),
			ExePath: getString(props, "actor_exe_path"),
			User:    getString(props, "actor_user"),
		}
	}

	// Parse target (Target is *TargetStruct)
	if getString(props, "target_ip") != "" || getInt(props, "target_port") > 0 || getString(props, "target_path") != "" {
		evt.Target = &event.TargetStruct{
			IP:       getString(props, "target_ip"),
			Port:     getInt(props, "target_port"),
			FilePath: getString(props, "target_path"),
		}
	}

	return evt
}

func getString(props map[string]any, key string) string {
	if val, ok := props[key].(string); ok {
		return val
	}
	return ""
}

func getInt(props map[string]any, key string) int {
	if val, ok := props[key].(int64); ok {
		return int(val)
	}
	if val, ok := props[key].(int); ok {
		return val
	}
	return 0
}

func getIntFromRecord(record *neo4jdriver.Record, index int) int {
	if index >= len(record.Values) {
		return 0
	}
	if val, ok := record.Values[index].(int64); ok {
		return int(val)
	}
	if val, ok := record.Values[index].(int); ok {
		return val
	}
	return 0
}

func getTime(props map[string]any, key string) time.Time {
	if val, ok := props[key].(time.Time); ok {
		return val
	}
	// Neo4j may return as LocalDateTime or other types
	if val, ok := props[key].(neo4jdriver.LocalDateTime); ok {
		return val.Time()
	}
	return time.Time{}
}

// NetworkEvent represents a network connection event with destination details
type NetworkEvent struct {
	ID         string    `json:"id"`
	Timestamp  time.Time `json:"timestamp"`
	Type       string    `json:"type"`
	TargetIP   string    `json:"target_ip"`
	TargetPort int       `json:"target_port"`
	Protocol   string    `json:"protocol,omitempty"`
	Category   string    `json:"category,omitempty"`
}

// ProcessActivityResponse contains network and file activity for a process
type ProcessActivityResponse struct {
	PID              int            `json:"pid"`
	HostID           string         `json:"host_id"`
	NetworkEvents    []NetworkEvent `json:"network_events"`
	TotalConnections int            `json:"total_connections"`
}

// GetProcessNetworkEvents retrieves network connection events for specific processes
func (s *TimelineService) GetProcessNetworkEvents(ctx context.Context, pids []int, hostID string, limit int) (*ProcessActivityResponse, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	// Get network events for the processes (connect, accept, dns, listen)
	query := `
		MATCH (net:Event)
		WHERE net.type IN ['net_connect', 'net_accept', 'net_dns', 'net_listen']
		  AND net.actor_pid IN $pids
		  AND net.host_id = $host_id
		RETURN net
		ORDER BY net.timestamp DESC
		LIMIT $limit
	`

	params := map[string]any{
		"pids":    pids,
		"host_id": hostID,
		"limit":   limit,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("failed to query network events: %w", err)
	}

	var events []NetworkEvent
	for _, record := range result.Records {
		node, ok := record.Values[0].(neo4jdriver.Node)
		if !ok {
			continue
		}
		props := node.Props

		evt := NetworkEvent{
			ID:         getString(props, "id"),
			Type:       getString(props, "type"),
			TargetIP:   getString(props, "target_ip"),
			TargetPort: getInt(props, "target_port"),
			Protocol:   getString(props, "target_protocol"),
		}

		// Parse timestamp
		if ts := getTime(props, "timestamp"); !ts.IsZero() {
			evt.Timestamp = ts
		}

		events = append(events, evt)
	}

	// Get total count for pagination metadata (rough count)
	// For now we just return the events.
	// The previous implementation returned total count of ALL events for the process?
	// Let's keep it simple and just return what we found or do a count query if needed.
	// The struct ProcessActivityResponse has TotalConnections.

	// Get total count
	countQuery := `
		MATCH (net:Event)
		WHERE net.type IN ['net_connect', 'net_accept', 'net_dns', 'net_listen']
		  AND net.actor_pid IN $pids
		  AND net.host_id = $host_id
		RETURN count(net) as total
	`

	countResult, err := s.client.ExecuteRead(ctx, countQuery, params)
	total := 0
	if err == nil && len(countResult.Records) > 0 {
		if val, ok := countResult.Records[0].Values[0].(int64); ok {
			total = int(val)
		}
	}

	return &ProcessActivityResponse{
		PID:              pids[0], // Return first PID as primary
		HostID:           hostID,
		NetworkEvents:    events,
		TotalConnections: total,
	}, nil
}

// NetworkSummary represents aggregated network and file stats
type NetworkSummary struct {
	Ports       []PortSummary       `json:"ports"`
	Connections []ConnectionSummary `json:"connections"`
	Files       []FileSummary       `json:"files"`
	DNS         []DNSSummary        `json:"dns"`
}

type PortSummary struct {
	Port  int    `json:"port"`
	IP    string `json:"ip"` // 0.0.0.0 vs 127.0.0.1
	Count int    `json:"count"`
}

type ConnectionSummary struct {
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	Domain     string `json:"domain,omitempty"`
	Count      int    `json:"count"`
	IsExternal bool   `json:"is_external"`
}

type FileSummary struct {
	Path  string `json:"path"`
	Count int    `json:"count"`
}

type DNSSummary struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// GetNetworkSummary aggregates network and file events for a list of PIDs
func (s *TimelineService) GetNetworkSummary(ctx context.Context, pids []int, hostID string) (*NetworkSummary, error) {
	// 1. Ports (net_listen)
	portQuery := `
		MATCH (e:Event)
		WHERE e.type = 'net_listen'
		  AND e.actor_pid IN $pids
		  AND e.host_id = $host_id
		RETURN e.target_port, e.target_ip, count(e) as c
		ORDER BY c DESC
	`
	// 2. Connections (net_connect)
	connQuery := `
		MATCH (e:Event)
		WHERE e.type = 'net_connect'
		  AND e.actor_pid IN $pids
		  AND e.host_id = $host_id
		
		// Try to find a DNS resolution for this IP
		OPTIONAL MATCH (d:Event)
		WHERE d.type = 'net_dns'
		  AND d.host_id = $host_id
		  AND d.res_ip = e.target_ip
		  AND d.timestamp <= e.timestamp
		  AND d.timestamp >= datetime(e.timestamp) - duration({minutes: 30})
		
		WITH e, d
		ORDER BY d.timestamp DESC

		RETURN e.target_ip, e.target_port, count(e) as c, head(collect(d.target_domain)) as domain
		ORDER BY c DESC
	`
	// 3. Files (file_open)
	fileQuery := `
		MATCH (e:Event)
		WHERE e.type = 'file_open'
		  AND e.actor_pid IN $pids
		  AND e.host_id = $host_id
		RETURN e.target_path as path, count(e) as c
		ORDER BY c DESC
		LIMIT 100
	`
	// 4. DNS (net_dns)
	dnsQuery := `
		MATCH (e:Event)
		WHERE e.type = 'net_dns'
		  AND e.actor_pid IN $pids
		  AND e.host_id = $host_id
		RETURN e.target_domain, count(e) as c
		ORDER BY c DESC
	`

	params := map[string]any{
		"pids":    pids,
		"host_id": hostID,
	}

	summary := &NetworkSummary{
		Ports:       []PortSummary{},
		Connections: []ConnectionSummary{},
		Files:       []FileSummary{},
		DNS:         []DNSSummary{},
	}

	// Execute Ports Query
	pRes, err := s.client.ExecuteRead(ctx, portQuery, params)
	if err == nil {
		for _, rec := range pRes.Records {
			var port int64
			if v, ok := rec.Values[0].(int64); ok {
				port = v
			}
			var ip string
			if v, ok := rec.Values[1].(string); ok {
				ip = v
			}
			var count int64
			if v, ok := rec.Values[2].(int64); ok {
				count = v
			}
			summary.Ports = append(summary.Ports, PortSummary{
				Port:  int(port),
				IP:    ip,
				Count: int(count),
			})
		}
	}

	// Execute Connections Query
	cRes, err := s.client.ExecuteRead(ctx, connQuery, params)
	if err == nil {
		for _, rec := range cRes.Records {
			var ip string
			if v, ok := rec.Values[0].(string); ok {
				ip = v
			}
			var port int64
			if v, ok := rec.Values[1].(int64); ok {
				port = v
			}
			var count int64
			if v, ok := rec.Values[2].(int64); ok {
				count = v
			}
			var domain string
			if v, ok := rec.Values[3].(string); ok {
				domain = v
			}

			summary.Connections = append(summary.Connections, ConnectionSummary{
				RemoteIP:   ip,
				RemotePort: int(port),
				Domain:     domain,
				Count:      int(count),
				IsExternal: ip != "127.0.0.1" && ip != "::1" && ip != "localhost",
			})
		}
	}

	// Execute Files Query
	fRes, err := s.client.ExecuteRead(ctx, fileQuery, params)
	if err == nil {
		for _, rec := range fRes.Records {
			path := "unknown"
			if v, ok := rec.Values[0].(string); ok && v != "" {
				path = v
			}

			var count int64
			if v, ok := rec.Values[1].(int64); ok {
				count = v
			}
			summary.Files = append(summary.Files, FileSummary{
				Path:  path,
				Count: int(count),
			})
		}
	}

	// Execute DNS Query
	dRes, err := s.client.ExecuteRead(ctx, dnsQuery, params)
	if err == nil {
		for _, rec := range dRes.Records {
			if domain, ok := rec.Values[0].(string); ok {
				summary.DNS = append(summary.DNS, DNSSummary{
					Domain: domain,
					Count:  int(rec.Values[1].(int64)),
				})
			}
		}
	}

	return summary, nil
}
