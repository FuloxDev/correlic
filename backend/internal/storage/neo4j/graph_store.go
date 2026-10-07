package neo4j

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// GraphStore handles persistence of correlation graphs to Neo4j
type GraphStore struct {
	client      *Client
	aiPatterns  map[string]string // comm -> agent_type
	aiPatternsM sync.RWMutex
}

// NewGraphStore creates a new graph store
func NewGraphStore(client *Client) *GraphStore {
	return &GraphStore{
		client:     client,
		aiPatterns: make(map[string]string),
	}
}

// LoadAIPatterns loads AI agent patterns from the database for labeling
func (g *GraphStore) LoadAIPatterns(db *sql.DB) error {
	rows, err := db.Query(`SELECT pattern, agent_type FROM ai_agent_patterns`)
	if err != nil {
		return err
	}
	defer rows.Close()

	g.aiPatternsM.Lock()
	defer g.aiPatternsM.Unlock()
	g.aiPatterns = make(map[string]string)

	for rows.Next() {
		var pattern, agentType string
		if err := rows.Scan(&pattern, &agentType); err != nil {
			return err
		}
		g.aiPatterns[strings.ToLower(pattern)] = agentType
	}
	return rows.Err()
}

// getAIType checks if a process name matches an AI pattern.
// Uses exact → prefix → substring matching (consistent with agent's CheckPattern).
func (g *GraphStore) getAIType(comm string) string {
	if comm == "" {
		return ""
	}
	g.aiPatternsM.RLock()
	defer g.aiPatternsM.RUnlock()

	commLower := strings.ToLower(comm)

	// Try exact match first (fastest path)
	if agentType, ok := g.aiPatterns[commLower]; ok {
		return agentType
	}
	// Try substring match — catches "openclaw-gateway" matching "openclaw",
	// "cursor-helper" matching "cursor", etc.
	for pattern, agentType := range g.aiPatterns {
		if strings.Contains(commLower, pattern) {
			return agentType
		}
	}
	return ""
}

// GetPatterns returns a copy of the loaded AI patterns
func (g *GraphStore) GetPatterns() map[string]string {
	g.aiPatternsM.RLock()
	defer g.aiPatternsM.RUnlock()

	patterns := make(map[string]string, len(g.aiPatterns))
	for k, v := range g.aiPatterns {
		patterns[k] = v
	}
	return patterns
}

// Edge represents a relationship between two events
type Edge struct {
	From     string
	To       string
	Type     string
	Metadata map[string]any
}

// InitializeSchema creates indexes and constraints
func (g *GraphStore) InitializeSchema(ctx context.Context) error {
	queries := []string{
		// Unique constraint on event ID
		"CREATE CONSTRAINT event_id_unique IF NOT EXISTS FOR (e:Event) REQUIRE e.id IS UNIQUE",

		// Indexes for common queries
		"CREATE INDEX event_timestamp IF NOT EXISTS FOR (e:Event) ON (e.timestamp)",
		"CREATE INDEX event_type IF NOT EXISTS FOR (e:Event) ON (e.type)",
		"CREATE INDEX event_host IF NOT EXISTS FOR (e:Event) ON (e.host_id)",
		"CREATE INDEX event_pid_host IF NOT EXISTS FOR (e:Event) ON (e.actor_pid, e.host_id)",
		"CREATE INDEX event_session_host IF NOT EXISTS FOR (e:Event) ON (e.session_id, e.host_id)",
		"CREATE INDEX event_ai_session IF NOT EXISTS FOR (e:Event) ON (e.ai_session_id, e.host_id)",
		"CREATE INDEX event_type_time IF NOT EXISTS FOR (e:Event) ON (e.type, e.timestamp)",
		// AI agent index for fast lookups
		"CREATE INDEX event_ai_type IF NOT EXISTS FOR (e:Event) ON (e.ai_type)",
	}

	for _, query := range queries {
		if err := g.client.ExecuteWrite(ctx, query, nil); err != nil {
			return fmt.Errorf("failed to execute schema query: %w", err)
		}
	}

	return nil
}

// CreateEvent creates a single event node in Neo4j
func (g *GraphStore) CreateEvent(ctx context.Context, evt *event.Event) error {
	// Build dynamic SET clause based on available fields
	setFields := []string{
		"e.timestamp = datetime($timestamp)",
		"e.host_id = $host_id",
		"e.source = $source",
		"e.type = $type",
	}

	params := map[string]any{
		"id":        evt.ID,
		"timestamp": evt.Timestamp.Format(time.RFC3339Nano),
		"host_id":   evt.HostID,
		"source":    evt.Source,
		"type":      evt.Type,
	}

	if synthetic, ok := evt.Context["synthetic_exec"].(bool); ok && synthetic {
		setFields = append(setFields, "e.is_synthetic = $is_synthetic")
		params["is_synthetic"] = true
	}

	// Track if this is an AI agent for labeling
	var aiType string

	// Add actor fields if present (field name is Process, type is ActorStruct)
	if evt.Process != nil {
		setFields = append(setFields,
			"e.actor_pid = $actor_pid",
			"e.actor_ppid = $actor_ppid",
			"e.actor_exe_path = $actor_exe_path",
			"e.actor_user = $actor_user",
			"e.actor_comm = $actor_comm",
			"e.actor_role = $actor_role",
		)
		params["actor_pid"] = evt.Process.PID
		params["actor_ppid"] = evt.Process.PPID
		params["actor_exe_path"] = evt.Process.ExePath
		params["actor_user"] = evt.Process.User
		params["actor_comm"] = evt.Process.Comm
		params["actor_role"] = evt.Process.Role
		if evt.Process.SessionID != "" && evt.Process.SessionID != "0" {
			setFields = append(setFields, "e.session_id = $session_id")
			params["session_id"] = evt.Process.SessionID
		}

		// Store AI session ID from event context (cross-PID correlation).
		if aiSessID, ok := evt.Context["ai_session_id"].(string); ok && aiSessID != "" {
			setFields = append(setFields, "e.ai_session_id = $ai_session_id")
			params["ai_session_id"] = aiSessID
		}

		// Store the full command line as JSON array so individual args are preserved
		if len(evt.Process.Cmdline) > 0 {
			setFields = append(setFields, "e.actor_cmdline = $actor_cmdline")
			cmdlineJSON, err := json.Marshal(evt.Process.Cmdline)
			if err == nil {
				params["actor_cmdline"] = string(cmdlineJSON)
			} else {
				params["actor_cmdline"] = strings.Join(evt.Process.Cmdline, " ")
			}
		}

		// For process_exec events, check if this matches an AI agent pattern.
		// Try all available identifiers — ExePath basename, Cmdline[0] basename,
		// and Comm — because AI tools running under generic runtimes (e.g. node,
		// python) have an ExePath like "/usr/local/bin/node" that won't match,
		// but their Comm or Cmdline[0] will (e.g. "openclaw").
		if evt.Type == "process_exec" {
			var candidates []string
			if evt.Process.ExePath != "" {
				parts := strings.Split(evt.Process.ExePath, "/")
				candidates = append(candidates, parts[len(parts)-1])
			}
			if len(evt.Process.Cmdline) > 0 {
				parts := strings.Split(evt.Process.Cmdline[0], "/")
				candidates = append(candidates, parts[len(parts)-1])
			}
			if evt.Process.Comm != "" {
				candidates = append(candidates, evt.Process.Comm)
			}

			for _, name := range candidates {
				aiType = g.getAIType(name)
				if aiType != "" {
					break
				}
			}
			if aiType != "" {
				setFields = append(setFields, "e.ai_type = $ai_type")
				params["ai_type"] = aiType
			}
		}
	}

	// Persist open_flags for file_open events so detection rules can distinguish reads from writes.
	if evt.Type == "file_open" {
		if flags, ok := evt.Context["open_flags"]; ok {
			setFields = append(setFields, "e.open_flags = $open_flags")
			switch v := flags.(type) {
			case int:
				params["open_flags"] = v
			case float64:
				params["open_flags"] = int(v)
			case int32:
				params["open_flags"] = int(v)
			case int64:
				params["open_flags"] = int(v)
			}
		}
	}

	// Add target fields if present (Target is *TargetStruct)
	if evt.Target != nil {
		if evt.Target.IP != "" {
			setFields = append(setFields, "e.target_ip = $target_ip")
			params["target_ip"] = evt.Target.IP
		}
		if evt.Target.Port > 0 {
			setFields = append(setFields, "e.target_port = $target_port")
			params["target_port"] = evt.Target.Port
		}
		if evt.Target.FilePath != "" {
			setFields = append(setFields, "e.target_path = $target_path")
			params["target_path"] = evt.Target.FilePath
		}
		if evt.Target.Domain != "" {
			setFields = append(setFields, "e.target_domain = $target_domain")
			params["target_domain"] = evt.Target.Domain
		}
	}

	// If AI agent, add :AIAgent label; otherwise just :Event
	var query string
	if aiType != "" {
		query = fmt.Sprintf(`
			MERGE (e:Event:AIAgent {id: $id})
			SET %s
		`, strings.Join(setFields, ",\n\t\t    "))
	} else {
		query = fmt.Sprintf(`
			MERGE (e:Event {id: $id})
			SET %s
		`, strings.Join(setFields, ",\n\t\t    "))
	}

	return g.client.ExecuteWrite(ctx, query, params)
}

// CreateEdge creates a relationship between two events
func (g *GraphStore) CreateEdge(ctx context.Context, edge Edge) error {
	// Map edge type to Neo4j relationship type
	relType := edgeTypeToNeo4j(edge.Type)

	query := fmt.Sprintf(`
		MATCH (from:Event {id: $from_id})
		MATCH (to:Event {id: $to_id})
		MERGE (from)-[r:%s]->(to)
	`, relType)

	params := map[string]any{
		"from_id": edge.From,
		"to_id":   edge.To,
	}

	return g.client.ExecuteWrite(ctx, query, params)
}

// BatchCreateEvents creates multiple event nodes efficiently
func (g *GraphStore) BatchCreateEvents(ctx context.Context, events []*event.Event) error {
	if len(events) == 0 {
		return nil
	}

	// Create events in batches of 100
	batchSize := 100
	for i := 0; i < len(events); i += batchSize {
		end := i + batchSize
		if end > len(events) {
			end = len(events)
		}

		batch := events[i:end]
		for _, evt := range batch {
			if err := g.CreateEvent(ctx, evt); err != nil {
				return fmt.Errorf("failed to create event %s: %w", evt.ID, err)
			}
		}
	}

	return nil
}

// BatchCreateEdges creates multiple edges efficiently
func (g *GraphStore) BatchCreateEdges(ctx context.Context, edges []Edge) error {
	if len(edges) == 0 {
		return nil
	}

	// Create edges in batches
	for _, edge := range edges {
		if err := g.CreateEdge(ctx, edge); err != nil {
			return fmt.Errorf("failed to create edge %s->%s: %w", edge.From, edge.To, err)
		}
	}

	return nil
}

// CreateGraph creates both events and edges in a single transaction
func (g *GraphStore) CreateGraph(ctx context.Context, events []*event.Event, edges []Edge) error {
	// Create events first
	if err := g.BatchCreateEvents(ctx, events); err != nil {
		return fmt.Errorf("failed to create events: %w", err)
	}

	// Then create edges
	if err := g.BatchCreateEdges(ctx, edges); err != nil {
		return fmt.Errorf("failed to create edges: %w", err)
	}

	return nil
}

// edgeTypeToNeo4j converts correlation edge type to Neo4j relationship type
func edgeTypeToNeo4j(edgeType string) string {
	switch edgeType {
	case "temporal":
		return "TEMPORAL"
	case "process_parent":
		return "PROCESS_PARENT"
	case "process_lifecycle_exit":
		return "LIFECYCLE"
	case "process_net_connect":
		return "NET_CONNECT"
	case "process_net_listen":
		return "NET_LISTEN"
	case "process_net_accept":
		return "NET_ACCEPT"
	case "process_net_msg":
		return "NET_MSG"
	case "process_net_tls":
		return "NET_TLS"
	case "process_container_start":
		return "CONTAINER_START"
	case "process_file_open":
		return "FILE_OPEN"
	case "process_file_write":
		return "FILE_WRITE"
	case "process_file_unlink":
		return "FILE_UNLINK"
	case "file_access":
		return "FILE_ACCESS"
	case "ai_spawned":
		return "AI_SPAWNED"
	default:
		return "RELATED"
	}
}

// CreateAISpawnedEdge creates an AI_SPAWNED relationship linking a child process to its AI root.
// Also adds the AIAgent label to the child and sets ai_root property.
func (g *GraphStore) CreateAISpawnedEdge(ctx context.Context, aiRootEventID, childEventID, aiType string) error {
	query := `
		MATCH (parent:Event:AIAgent {id: $parent_id})
		MATCH (child:Event {id: $child_id})
		MERGE (parent)-[:AI_SPAWNED]->(child)
		SET child:AIAgent, child.ai_type = $ai_type, child.ai_root = $parent_id
	`
	params := map[string]any{
		"parent_id": aiRootEventID,
		"child_id":  childEventID,
		"ai_type":   aiType,
	}
	return g.client.ExecuteWrite(ctx, query, params)
}

// PropagateAILabels propagates AI labels through the process tree using PROCESS_PARENT edges.
// Returns the count of nodes that were labeled.
func (g *GraphStore) PropagateAILabels(ctx context.Context, hostID string) (int, error) {
	// Walk PROCESS_PARENT edges from AI agents and label descendants
	query := `
		MATCH (ai:Event:AIAgent {host_id: $host_id, type: 'process_exec'})
		WHERE ai.ai_root IS NULL
		MATCH path = (ai)-[:PROCESS_PARENT*1..20]->(child:Event {type: 'process_exec'})
		WHERE NOT child:AIAgent
		WITH ai, child
		MERGE (ai)-[:AI_SPAWNED]->(child)
		SET child:AIAgent, child.ai_type = ai.ai_type, child.ai_root = ai.id
		RETURN count(child) as labeled_count
	`
	params := map[string]any{
		"host_id": hostID,
	}

	result, err := g.client.ExecuteWriteWithResult(ctx, query, params)
	if err != nil {
		return 0, err
	}

	if len(result.Records) > 0 {
		if count, ok := result.Records[0].Values[0].(int64); ok {
			return int(count), nil
		}
	}
	return 0, nil
}

// FindAIAncestor searches up the process tree for an AI agent ancestor.
// Returns the AI root event ID and type if found.
func (g *GraphStore) FindAIAncestor(ctx context.Context, hostID string, pid int) (string, string, error) {
	// Search up the PROCESS_PARENT chain for an AI agent
	query := `
		MATCH (child:Event {host_id: $host_id, actor_pid: $pid, type: 'process_exec'})
		MATCH path = (ai:Event:AIAgent {type: 'process_exec'})-[:PROCESS_PARENT*1..20]->(child)
		WHERE ai.ai_root IS NULL
		RETURN ai.id as ai_id, ai.ai_type as ai_type
		LIMIT 1
	`
	params := map[string]any{
		"host_id": hostID,
		"pid":     pid,
	}

	result, err := g.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return "", "", err
	}

	if len(result.Records) > 0 {
		aiID, _ := result.Records[0].Values[0].(string)
		aiType, _ := result.Records[0].Values[1].(string)
		return aiID, aiType, nil
	}
	return "", "", nil
}

// UpsertProcessAndLink creates a process_exec event node and immediately links it to its
// parent process in a single operation. This is Tier 1 of the correlation engine:
// process tree structure is built in real-time, one event at a time, ensuring the tree
// is always correct regardless of batch boundaries or time windows.
//
// The parent is found by matching (host_id, actor_pid == child.actor_ppid, type == process_exec)
// with the most recent timestamp before the child. Uses MERGE for idempotency.
func (g *GraphStore) UpsertProcessAndLink(ctx context.Context, evt *event.Event) error {
	if evt == nil || evt.Process == nil || evt.Process.PID == 0 {
		return nil
	}

	// Step 1: Create the event node (reuse existing CreateEvent which handles AI labeling)
	if err := g.CreateEvent(ctx, evt); err != nil {
		return fmt.Errorf("failed to create process event: %w", err)
	}

	// Step 2: Link to parent if PPID is set and valid
	if evt.Process.PPID == 0 || evt.Process.PPID == evt.Process.PID {
		return nil // root process or self-referencing, no parent to link
	}

	linkQuery := `
		MATCH (child:Event {id: $child_id, type: 'process_exec'})
		WHERE NOT ( ()-[:PROCESS_PARENT]->(child) )
		WITH child
		MATCH (parent:Event {
			host_id: $host_id,
			actor_pid: $ppid,
			type: 'process_exec'
		})
		WHERE parent.timestamp < child.timestamp
		  AND parent.id <> child.id
		WITH child, parent
		ORDER BY parent.timestamp DESC
		LIMIT 1
		MERGE (parent)-[:PROCESS_PARENT]->(child)
	`
	params := map[string]any{
		"child_id": evt.ID,
		"host_id":  evt.HostID,
		"ppid":     evt.Process.PPID,
	}

	if err := g.client.ExecuteWrite(ctx, linkQuery, params); err != nil {
		// Non-fatal: the node exists, just the edge wasn't created.
		// This can happen if the parent hasn't been ingested yet (rare, parent usually starts first).
		return fmt.Errorf("failed to link process to parent: %w", err)
	}

	return nil
}

// LinkOrphans attempts to link recently created process_exec events to their parents
// if the parent was processed in a previous batch (and thus missed by in-memory correlation).
func (g *GraphStore) LinkOrphans(ctx context.Context, eventIDs []string) (int, error) {
	if len(eventIDs) == 0 {
		return 0, nil
	}

	query := `
		UNWIND $ids as child_id
		MATCH (child:Event {id: child_id, type: 'process_exec'})
		WHERE NOT ( ()-[:PROCESS_PARENT]->(child) )
		// Find potential parent by PID + HostID (time constrained)
		MATCH (parent:Event {host_id: child.host_id, actor_pid: child.actor_ppid, type: 'process_exec'})
		WHERE parent.timestamp < child.timestamp
		// Removed 24h limit to support long-running processes (e.g. servers/daemons)
		// Index on (host_id, actor_pid) ensures this is still fast.
		WITH child, parent
		ORDER BY parent.timestamp DESC
		WITH child, head(collect(parent)) as real_parent
		WHERE real_parent IS NOT NULL
		MERGE (real_parent)-[:PROCESS_PARENT]->(child)
		RETURN count(real_parent) as linked_count
	`
	params := map[string]any{
		"ids": eventIDs,
	}

	err := g.client.ExecuteWrite(ctx, query, params)
	if err != nil {
		return 0, err
	}

	// We can't get the count from ExecuteWrite wrapper, so just return 0 or 1
	// The count is informational only.
	return 1, nil
}
