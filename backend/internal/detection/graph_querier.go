package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	neo4jstore "github.com/correlic/correlic-backend/internal/storage/neo4j"
)

// Neo4jGraphQuerier implements GraphQuerier using the Neo4j client.
type Neo4jGraphQuerier struct {
	client *neo4jstore.Client
}

// NewNeo4jGraphQuerier creates a GraphQuerier backed by Neo4j.
func NewNeo4jGraphQuerier(client *neo4jstore.Client) *Neo4jGraphQuerier {
	return &Neo4jGraphQuerier{client: client}
}

// GetRecentEvents returns events for a PID within a time window.
func (q *Neo4jGraphQuerier) GetRecentEvents(ctx context.Context, hostID string, pid int, since time.Time, eventTypes []string) ([]event.Event, error) {
	sinceStr := since.Format(time.RFC3339Nano)

	typeFilter := ""
	if len(eventTypes) > 0 {
		typeFilter = "AND e.type IN $event_types "
	}

	query := fmt.Sprintf(`
		MATCH (e:Event)
		WHERE e.host_id = $host_id
		  AND e.actor_pid = $pid
		  AND e.timestamp >= datetime($since)
		  %s
		RETURN e.id as id, e.type as type, e.timestamp as ts,
		       e.actor_comm as comm, e.actor_exe_path as exe,
		       e.actor_cmdline as cmdline,
		       e.target_path as target_path,
		       e.target_ip as target_ip, e.target_port as target_port,
		       e.open_flags as open_flags
		ORDER BY e.timestamp DESC
		LIMIT 100
	`, typeFilter)

	params := map[string]any{
		"host_id": hostID,
		"pid":     pid,
		"since":   sinceStr,
	}
	if len(eventTypes) > 0 {
		params["event_types"] = eventTypes
	}

	result, err := q.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("GetRecentEvents query failed: %w", err)
	}

	var events []event.Event
	for _, record := range result.Records {
		evt := event.Event{}
		if v, ok := record.Values[0].(string); ok {
			evt.ID = v
		}
		if v, ok := record.Values[1].(string); ok {
			evt.Type = v
		}
		if v, ok := record.Values[2].(time.Time); ok {
			evt.Timestamp = v
		}
		evt.HostID = hostID
		evt.Process = &event.ActorStruct{}
		if v, ok := record.Values[3].(string); ok {
			evt.Process.Comm = v
		}
		if v, ok := record.Values[4].(string); ok {
			evt.Process.ExePath = v
		}
		if v, ok := record.Values[5].(string); ok {
			var cmdline []string
			if err := json.Unmarshal([]byte(v), &cmdline); err != nil {
				cmdline = []string{v} // fallback for pre-JSON data
			}
			evt.Process.Cmdline = cmdline
		}
		// Target
		evt.Target = &event.TargetStruct{}
		if v, ok := record.Values[6].(string); ok {
			evt.Target.FilePath = v
		}
		if v, ok := record.Values[7].(string); ok {
			evt.Target.IP = v
		}
		if v, ok := record.Values[8].(int64); ok {
			evt.Target.Port = int(v)
		}
		// Populate open_flags into Context so detection rules can use isWriteOpen()
		if v, ok := record.Values[9].(int64); ok {
			evt.Context = map[string]any{"open_flags": int(v)}
		}

		events = append(events, evt)
	}

	return events, nil
}

// GetRecentEventsMultiPID returns events for a list of PIDs within a time window.
func (q *Neo4jGraphQuerier) GetRecentEventsMultiPID(ctx context.Context, hostID string, pids []int, since time.Time, eventTypes []string) ([]event.Event, error) {
	if len(pids) == 0 {
		return nil, nil
	}

	sinceStr := since.Format(time.RFC3339Nano)

	typeFilter := ""
	if len(eventTypes) > 0 {
		typeFilter = "AND e.type IN $event_types "
	}

	query := fmt.Sprintf(`
		MATCH (e:Event)
		WHERE e.host_id = $host_id
		  AND e.actor_pid IN $pids
		  AND e.timestamp >= datetime($since)
		  %s
		RETURN e.id as id, e.type as type, e.timestamp as ts,
		       e.actor_comm as comm, e.actor_exe_path as exe,
		       e.actor_cmdline as cmdline,
		       e.target_path as target_path,
		       e.target_ip as target_ip, e.target_port as target_port,
		       e.open_flags as open_flags
		ORDER BY e.timestamp DESC
		LIMIT 500
	`, typeFilter)

	params := map[string]any{
		"host_id": hostID,
		"pids":    pids,
		"since":   sinceStr,
	}
	if len(eventTypes) > 0 {
		params["event_types"] = eventTypes
	}

	result, err := q.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("GetRecentEventsMultiPID query failed: %w", err)
	}

	var events []event.Event
	for _, record := range result.Records {
		evt := event.Event{}
		if v, ok := record.Values[0].(string); ok {
			evt.ID = v
		}
		if v, ok := record.Values[1].(string); ok {
			evt.Type = v
		}
		if v, ok := record.Values[2].(time.Time); ok {
			evt.Timestamp = v
		}
		evt.HostID = hostID
		evt.Process = &event.ActorStruct{}
		if v, ok := record.Values[3].(string); ok {
			evt.Process.Comm = v
		}
		if v, ok := record.Values[4].(string); ok {
			evt.Process.ExePath = v
		}
		if v, ok := record.Values[5].(string); ok {
			var cmdline []string
			if err := json.Unmarshal([]byte(v), &cmdline); err != nil {
				cmdline = []string{v} // fallback for pre-JSON data
			}
			evt.Process.Cmdline = cmdline
		}
		evt.Target = &event.TargetStruct{}
		if v, ok := record.Values[6].(string); ok {
			evt.Target.FilePath = v
		}
		if v, ok := record.Values[7].(string); ok {
			evt.Target.IP = v
		}
		if v, ok := record.Values[8].(int64); ok {
			evt.Target.Port = int(v)
		}
		if v, ok := record.Values[9].(int64); ok {
			evt.Context = map[string]any{"open_flags": int(v)}
		}

		events = append(events, evt)
	}

	return events, nil
}

// GetRecentEventsBySession returns events for a session within a time window.
func (q *Neo4jGraphQuerier) GetRecentEventsBySession(ctx context.Context, hostID string, sessionID string, since time.Time, eventTypes []string) ([]event.Event, error) {
	if sessionID == "" || sessionID == "0" {
		return nil, nil
	}

	sinceStr := since.Format(time.RFC3339Nano)

	typeFilter := ""
	if len(eventTypes) > 0 {
		typeFilter = "AND e.type IN $event_types "
	}

	query := fmt.Sprintf(`
		MATCH (e:Event)
		WHERE e.host_id = $host_id
		  AND (e.session_id = $session_id OR e.ai_session_id = $session_id)
		  AND e.timestamp >= datetime($since)
		  %s
		RETURN e.id as id, e.type as type, e.timestamp as ts,
		       e.actor_comm as comm, e.actor_exe_path as exe,
		       e.actor_cmdline as cmdline,
		       e.target_path as target_path,
		       e.target_ip as target_ip, e.target_port as target_port,
		       e.open_flags as open_flags
		ORDER BY e.timestamp DESC
		LIMIT 500
	`, typeFilter)

	params := map[string]any{
		"host_id":    hostID,
		"session_id": sessionID,
		"since":      sinceStr,
	}
	if len(eventTypes) > 0 {
		params["event_types"] = eventTypes
	}

	result, err := q.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("GetRecentEventsBySession query failed: %w", err)
	}

	var events []event.Event
	for _, record := range result.Records {
		evt := event.Event{}
		if v, ok := record.Values[0].(string); ok {
			evt.ID = v
		}
		if v, ok := record.Values[1].(string); ok {
			evt.Type = v
		}
		if v, ok := record.Values[2].(time.Time); ok {
			evt.Timestamp = v
		}
		evt.HostID = hostID
		evt.Process = &event.ActorStruct{SessionID: sessionID}
		if v, ok := record.Values[3].(string); ok {
			evt.Process.Comm = v
		}
		if v, ok := record.Values[4].(string); ok {
			evt.Process.ExePath = v
		}
		if v, ok := record.Values[5].(string); ok {
			var cmdline []string
			if err := json.Unmarshal([]byte(v), &cmdline); err != nil {
				cmdline = []string{v} // fallback for pre-JSON data
			}
			evt.Process.Cmdline = cmdline
		}
		evt.Target = &event.TargetStruct{}
		if v, ok := record.Values[6].(string); ok {
			evt.Target.FilePath = v
		}
		if v, ok := record.Values[7].(string); ok {
			evt.Target.IP = v
		}
		if v, ok := record.Values[8].(int64); ok {
			evt.Target.Port = int(v)
		}
		if v, ok := record.Values[9].(int64); ok {
			evt.Context = map[string]any{"open_flags": int(v)}
		}

		events = append(events, evt)
	}

	return events, nil
}

// GetProcessAncestors returns the ancestor chain for a process by walking PROCESS_PARENT edges.
func (q *Neo4jGraphQuerier) GetProcessAncestors(ctx context.Context, hostID string, pid int, maxDepth int) ([]event.Event, error) {
	query := `
		MATCH (child:Event {type: 'process_exec', host_id: $host_id, actor_pid: $pid})
		MATCH path = (ancestor:Event)-[:PROCESS_PARENT*1..` + fmt.Sprintf("%d", maxDepth) + `]->(child)
		WHERE ancestor.type = 'process_exec'
		UNWIND nodes(path) as n
		WITH DISTINCT n
		RETURN n.id as id, n.actor_pid as pid, n.actor_comm as comm,
		       n.actor_exe_path as exe, n.actor_cmdline as cmdline
		ORDER BY n.timestamp ASC
	`

	result, err := q.client.ExecuteRead(ctx, query, map[string]any{
		"host_id": hostID,
		"pid":     pid,
	})
	if err != nil {
		return nil, fmt.Errorf("GetProcessAncestors query failed: %w", err)
	}

	var events []event.Event
	for _, record := range result.Records {
		evt := event.Event{HostID: hostID, Type: "process_exec"}
		if v, ok := record.Values[0].(string); ok {
			evt.ID = v
		}
		evt.Process = &event.ActorStruct{}
		if v, ok := record.Values[1].(int64); ok {
			evt.Process.PID = int(v)
		}
		if v, ok := record.Values[2].(string); ok {
			evt.Process.Comm = v
		}
		if v, ok := record.Values[3].(string); ok {
			evt.Process.ExePath = v
		}
		if v, ok := record.Values[4].(string); ok {
			var cmdline []string
			if err := json.Unmarshal([]byte(v), &cmdline); err != nil {
				cmdline = []string{v} // fallback for pre-JSON data
			}
			evt.Process.Cmdline = cmdline
		}
		events = append(events, evt)
	}

	return events, nil
}

// IsAIProcess checks if a PID belongs to an AI agent process tree.
func (q *Neo4jGraphQuerier) IsAIProcess(ctx context.Context, hostID string, pid int) (bool, string, error) {
	query := `
		MATCH (e:Event:AIAgent {type: 'process_exec', host_id: $host_id, actor_pid: $pid})
		RETURN e.ai_type as ai_type
		LIMIT 1
	`

	result, err := q.client.ExecuteRead(ctx, query, map[string]any{
		"host_id": hostID,
		"pid":     pid,
	})
	if err != nil {
		return false, "", fmt.Errorf("IsAIProcess query failed: %w", err)
	}

	if len(result.Records) > 0 {
		aiType := ""
		if v, ok := result.Records[0].Values[0].(string); ok {
			aiType = v
		}
		return true, aiType, nil
	}

	// Ancestor walk fallback: handles propagation race where child
	// hasn't been labeled yet but an ancestor has the AIAgent label.
	ancestorQuery := `
		MATCH (child:Event {type: 'process_exec', host_id: $host_id, actor_pid: $pid})
		MATCH (ai:Event:AIAgent {type: 'process_exec'})-[:PROCESS_PARENT*1..10]->(child)
		RETURN ai.ai_type as ai_type
		LIMIT 1
	`
	result2, err := q.client.ExecuteRead(ctx, ancestorQuery, map[string]any{
		"host_id": hostID,
		"pid":     pid,
	})
	if err != nil {
		return false, "", nil // Best-effort, don't fail
	}
	if len(result2.Records) > 0 {
		aiType := ""
		if v, ok := result2.Records[0].Values[0].(string); ok {
			aiType = v
		}
		return true, aiType, nil
	}

	return false, "", nil
}
