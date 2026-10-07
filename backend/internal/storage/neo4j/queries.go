package neo4j

import (
	"context"
	"fmt"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// GraphQueryResult represents a result from a graph query.
type GraphQueryResult struct {
	Events        []EventNode `json:"events"`
	Relationships []GraphEdge `json:"relationships"`
	Paths         []GraphPath `json:"paths,omitempty"`
}

// EventNode represents an event node from Neo4j.
type EventNode struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	Timestamp   time.Time      `json:"timestamp"`
	HostID      string         `json:"host_id"`
	ActorPID    int64          `json:"actor_pid,omitempty"`
	ActorPPID   int64          `json:"actor_ppid,omitempty"`
	ActorExe    string         `json:"actor_exe,omitempty"`
	ActorUser   string         `json:"actor_user,omitempty"`
	TargetIP    string         `json:"target_ip,omitempty"`
	TargetPort  int            `json:"target_port,omitempty"`
	TargetPath  string         `json:"target_path,omitempty"`
	ContainerID string         `json:"container_id,omitempty"`
	SessionID   int64          `json:"session_id,omitempty"`
	Properties  map[string]any `json:"properties,omitempty"`
}

// GraphEdge represents a relationship between two events.
type GraphEdge struct {
	FromID string `json:"from_id"`
	ToID   string `json:"to_id"`
	Type   string `json:"type"`
}

// GraphPath represents a path of connected events.
type GraphPath struct {
	Events []EventNode `json:"events"`
	Edges  []GraphEdge `json:"edges"`
	Length int         `json:"length"`
}

// AttackChainQuery represents parameters for attack chain queries.
type AttackChainQuery struct {
	StartEventID string        // Starting event ID
	StartPID     int64         // Or starting PID
	HostID       string        // Host to search on
	MaxDepth     int           // Max hops to traverse
	TimeWindow   time.Duration // Time window to search
	EventTypes   []string      // Filter by event types
}

// QueryAttackChain finds all events connected to a starting point.
// This is the primary LLM query method for understanding attack chains.
func (g *GraphStore) QueryAttackChain(ctx context.Context, q AttackChainQuery) (*GraphQueryResult, error) {
	if q.MaxDepth == 0 {
		q.MaxDepth = 10
	}

	var query string
	params := map[string]any{
		"max_depth": q.MaxDepth,
	}

	if q.StartEventID != "" {
		query = fmt.Sprintf(`
			MATCH path = (start:Event {id: $start_id})-[*1..%d]-(connected:Event)
			WHERE connected.host_id = start.host_id
			RETURN path, connected
			ORDER BY connected.timestamp
			LIMIT 100
		`, q.MaxDepth)
		params["start_id"] = q.StartEventID
	} else if q.StartPID > 0 && q.HostID != "" {
		query = fmt.Sprintf(`
			MATCH (start:Event {actor_pid: $pid, host_id: $host_id})
			MATCH path = (start)-[*1..%d]-(connected:Event)
			WHERE connected.host_id = $host_id
			RETURN path, connected
			ORDER BY connected.timestamp
			LIMIT 100
		`, q.MaxDepth)
		params["pid"] = q.StartPID
		params["host_id"] = q.HostID
	} else {
		return nil, fmt.Errorf("must provide StartEventID or (StartPID and HostID)")
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("attack chain query failed: %w", err)
	}

	return parseGraphQueryResult(result)
}

// GetProcessTree returns the process tree for a given process.
// Shows parent, children, and all spawned processes.
func (g *GraphStore) GetProcessTree(ctx context.Context, pid int64, hostID string) (*GraphQueryResult, error) {
	query := `
		// Find the starting process
		MATCH (start:Event {actor_pid: $pid, host_id: $host_id, type: 'process_exec'})
		
		// Get parent chain (up to 5 levels)
		OPTIONAL MATCH parentPath = (start)<-[:PROCESS_PARENT*1..5]-(parent:Event)
		
		// Get child chain (down to 10 levels)
		OPTIONAL MATCH childPath = (start)-[:PROCESS_PARENT*1..10]->(child:Event)
		
		// Return all paths
		RETURN start, collect(DISTINCT parentPath) as parents, collect(DISTINCT childPath) as children
	`

	params := map[string]any{
		"pid":     pid,
		"host_id": hostID,
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("process tree query failed: %w", err)
	}

	return parseGraphQueryResult(result)
}

// GetProcessTreeMultiPID fetches process trees for multiple PIDs in a single query.
// This avoids N+1 queries when building incident detail pages with many findings.
func (g *GraphStore) GetProcessTreeMultiPID(ctx context.Context, pids []int64, hostID string) (*GraphQueryResult, error) {
	if len(pids) == 0 {
		return nil, nil
	}

	query := `
		UNWIND $pids AS pid
		MATCH (start:Event {actor_pid: pid, host_id: $host_id, type: 'process_exec'})
		WITH DISTINCT start

		// Get parent chain (up to 5 levels)
		OPTIONAL MATCH parentPath = (start)<-[:PROCESS_PARENT*1..5]-(parent:Event)

		// Get child chain (up to 5 levels)
		OPTIONAL MATCH childPath = (start)-[:PROCESS_PARENT*1..5]->(child:Event)

		// Return all paths
		RETURN start, collect(DISTINCT parentPath) as parents, collect(DISTINCT childPath) as children
	`

	params := map[string]any{
		"pids":    pids,
		"host_id": hostID,
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("batch process tree query failed: %w", err)
	}

	return parseGraphQueryResult(result)
}

// FindRelatedEvents finds events related to a specific file or network target.
func (g *GraphStore) FindRelatedEvents(ctx context.Context, targetPath string, targetIP string, hostID string, limit int) (*GraphQueryResult, error) {
	if limit == 0 {
		limit = 50
	}

	var query string
	params := map[string]any{
		"host_id": hostID,
		"limit":   limit,
	}

	if targetPath != "" {
		query = `
			MATCH (e:Event {host_id: $host_id})
			WHERE e.target_path CONTAINS $path
			RETURN e
			ORDER BY e.timestamp DESC
			LIMIT $limit
		`
		params["path"] = targetPath
	} else if targetIP != "" {
		query = `
			MATCH (e:Event {host_id: $host_id})
			WHERE e.target_ip = $ip
			RETURN e
			ORDER BY e.timestamp DESC
			LIMIT $limit
		`
		params["ip"] = targetIP
	} else {
		return nil, fmt.Errorf("must provide targetPath or targetIP")
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("related events query failed: %w", err)
	}

	return parseGraphQueryResult(result)
}

// GetLateralMovement finds potential lateral movement patterns.
// Looks for processes that connect to external IPs and spawn suspicious children.
func (g *GraphStore) GetLateralMovement(ctx context.Context, hostID string, since time.Time) (*GraphQueryResult, error) {
	query := `
		// Find processes that made network connections
		MATCH (netEvent:Event {host_id: $host_id, type: 'net_connect'})
		WHERE netEvent.timestamp >= datetime($since)
		
		// Find processes spawned after the network connection (from same parent)
		MATCH (netEvent)<-[:PROCESS_PARENT]-(parent:Event)-[:PROCESS_PARENT]->(child:Event)
		WHERE child.timestamp > netEvent.timestamp
		  AND child.type = 'process_exec'
		
		// Return the chain: parent -> net_connect, parent -> child
		RETURN parent, netEvent, child
		ORDER BY netEvent.timestamp
		LIMIT 50
	`

	params := map[string]any{
		"host_id": hostID,
		"since":   since.Format(time.RFC3339),
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("lateral movement query failed: %w", err)
	}

	return parseGraphQueryResult(result)
}

// GetSessionActivity returns all activity for a login session.
func (g *GraphStore) GetSessionActivity(ctx context.Context, sessionID int64, hostID string) (*GraphQueryResult, error) {
	query := `
		MATCH (e:Event {host_id: $host_id})
		WHERE e.session_id = $session_id
		RETURN e
		ORDER BY e.timestamp
		LIMIT 500
	`

	params := map[string]any{
		"session_id": sessionID,
		"host_id":    hostID,
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("session activity query failed: %w", err)
	}

	return parseGraphQueryResult(result)
}

// GetContainerActivity returns all activity within a container.
func (g *GraphStore) GetContainerActivity(ctx context.Context, containerID string) (*GraphQueryResult, error) {
	query := `
		MATCH (e:Event)
		WHERE e.container_id = $container_id
		RETURN e
		ORDER BY e.timestamp
		LIMIT 500
	`

	params := map[string]any{
		"container_id": containerID,
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("container activity query failed: %w", err)
	}

	return parseGraphQueryResult(result)
}

// parseGraphQueryResult converts Neo4j result to GraphQueryResult.
func parseGraphQueryResult(result *neo4j.EagerResult) (*GraphQueryResult, error) {
	gqr := &GraphQueryResult{
		Events:        make([]EventNode, 0),
		Relationships: make([]GraphEdge, 0),
	}

	if result == nil || len(result.Records) == 0 {
		return gqr, nil
	}

	eventsSeen := make(map[string]bool)
	edgesSeen := make(map[string]bool)

	// addNode deduplicates and appends an event node.
	addNode := func(node neo4j.Node) {
		id := getString(node.GetProperties(), "id")
		if id == "" || eventsSeen[id] {
			return
		}
		eventNode := nodeToEventNode(node)
		gqr.Events = append(gqr.Events, eventNode)
		eventsSeen[id] = true
	}

	// addRelationship deduplicates and appends a graph edge.
	// Neo4j relationships reference start/end by ElementId; we need to map
	// those to our event IDs. We build this mapping from already-seen nodes.
	addRelationship := func(rel neo4j.Relationship, nodeIndex map[string]string) {
		fromID := nodeIndex[rel.StartElementId]
		toID := nodeIndex[rel.EndElementId]
		if fromID == "" || toID == "" {
			return
		}
		edgeKey := fromID + "->" + toID + ":" + rel.Type
		if edgesSeen[edgeKey] {
			return
		}
		gqr.Relationships = append(gqr.Relationships, GraphEdge{
			FromID: fromID,
			ToID:   toID,
			Type:   rel.Type,
		})
		edgesSeen[edgeKey] = true
	}

	// processPath extracts all nodes and relationships from a neo4j.Path.
	processPath := func(path neo4j.Path, nodeIndex map[string]string) {
		for _, node := range path.Nodes {
			addNode(node)
			id := getString(node.GetProperties(), "id")
			if id != "" {
				nodeIndex[node.ElementId] = id
			}
		}
		for _, rel := range path.Relationships {
			addRelationship(rel, nodeIndex)
		}
	}

	// processValue recursively handles nodes, paths, relationships, and lists.
	var processValue func(value any, nodeIndex map[string]string)
	processValue = func(value any, nodeIndex map[string]string) {
		if value == nil {
			return
		}
		switch v := value.(type) {
		case neo4j.Node:
			addNode(v)
			id := getString(v.GetProperties(), "id")
			if id != "" {
				nodeIndex[v.ElementId] = id
			}
		case neo4j.Path:
			processPath(v, nodeIndex)
		case neo4j.Relationship:
			addRelationship(v, nodeIndex)
		case []any:
			for _, item := range v {
				processValue(item, nodeIndex)
			}
		}
	}

	for _, record := range result.Records {
		// Map from Neo4j ElementId to our event ID, built per-record.
		nodeIndex := make(map[string]string)
		// Two passes: first extract all nodes so nodeIndex is populated,
		// then extract relationships (which need nodeIndex).
		for _, value := range record.Values {
			processValue(value, nodeIndex)
		}
	}

	return gqr, nil
}

// nodeToEventNode converts a Neo4j node to an EventNode.
func nodeToEventNode(node neo4j.Node) EventNode {
	props := node.GetProperties()

	event := EventNode{
		ID:         getString(props, "id"),
		Type:       getString(props, "type"),
		HostID:     getString(props, "host_id"),
		ActorExe:   getString(props, "actor_exe_path"),
		ActorUser:  getString(props, "actor_user"),
		TargetIP:   getString(props, "target_ip"),
		TargetPath: getString(props, "target_path"),
		Properties: props,
	}

	if ts, ok := props["timestamp"]; ok {
		if tsTime, ok := ts.(time.Time); ok {
			event.Timestamp = tsTime
		}
	}

	if pid, ok := props["actor_pid"]; ok {
		if pidInt, ok := pid.(int64); ok {
			event.ActorPID = pidInt
		}
	}

	if ppid, ok := props["actor_ppid"]; ok {
		if ppidInt, ok := ppid.(int64); ok {
			event.ActorPPID = ppidInt
		}
	}

	if port, ok := props["target_port"]; ok {
		if portInt, ok := port.(int64); ok {
			event.TargetPort = int(portInt)
		}
	}

	return event
}

func getString(props map[string]any, key string) string {
	if val, ok := props[key]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}
