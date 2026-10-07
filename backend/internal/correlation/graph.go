package correlation

import (
	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/process"
)

// EventEdge is a typed directed edge between events (by ID).
type EventEdge struct {
	From string
	To   string
	Type string
}

// EventGraph is an in-memory graph: nodes are events by ID, edges are typed (e.g. process_parent, temporal).
type EventGraph struct {
	Nodes map[string]event.Event
	Edges []EventEdge
}

// BuildGraph builds an EventGraph from ordered events: nodes by ID, temporal edges, and process_parent edges
// where an event's Actor.PPID matches another event's Actor.PID (same host/window implied by input).
// Deterministic: first occurrence of each PID in event order wins for parent lookup.
// Phase 18B: process_exit creates a node only when paired (same PID has process_exec in the set).
func BuildGraph(events []event.Event) *EventGraph {
	g := &EventGraph{
		Nodes: make(map[string]event.Event),
		Edges: nil,
	}

	pidHasExec := make(map[int]bool)
	for _, e := range events {
		if e.Type == "process_exec" && e.Process != nil && e.Process.PID != 0 {
			pidHasExec[e.Process.PID] = true
		}
	}
	for _, e := range events {
		if e.Type == "process_exit" && e.Process != nil && e.Process.PID != 0 {
			if !process.ExitTimestampInBounds(e.Timestamp) {
				continue // insane year; already counted in lifecycle via exec_exit_year_out_of_bounds
			}
			if !pidHasExec[e.Process.PID] {
				process.ExecExitNoExec.Add(1)
				continue // unpaired exit: do not create graph node
			}
		}
		g.Nodes[e.ID] = e
	}

	// Temporal adjacency edges (only between nodes that exist in graph; unpaired exits are omitted)
	for i := 0; i < len(events)-1; i++ {
		from, to := events[i].ID, events[i+1].ID
		if _, okFrom := g.Nodes[from]; !okFrom {
			continue
		}
		if _, okTo := g.Nodes[to]; !okTo {
			continue
		}
		g.Edges = append(g.Edges, EventEdge{
			From: from,
			To:   to,
			Type: "temporal",
		})
	}

	// Process parent edges: for each event with Actor.PPID, link to event whose Actor.PID equals that PPID.
	// Same host and same window are implied (events are from one GetRange).
	pidToEventID := make(map[int]string)
	for _, e := range events {
		if e.Process != nil && e.Process.PID != 0 {
			if _, ok := pidToEventID[e.Process.PID]; !ok {
				pidToEventID[e.Process.PID] = e.ID
			}
		}
	}
	for _, e := range events {
		if e.Process == nil || e.Process.PPID == 0 {
			continue
		}
		parentID, ok := pidToEventID[e.Process.PPID]
		if !ok || parentID == e.ID {
			continue
		}
		if _, inGraph := g.Nodes[e.ID]; !inGraph {
			continue
		}
		g.Edges = append(g.Edges, EventEdge{
			From: parentID,
			To:   e.ID,
			Type: "process_parent",
		})
	}

	// Process→network edges: attribute net_connect / net_listen to the process_exec that has the same PID.
	// Canonical network types: net_connect (outbound), net_listen (port opened). First exec wins per PID.
	pidToProcessExecID := make(map[int]string)
	for _, e := range events {
		if e.Type != "process_exec" || e.Process == nil || e.Process.PID == 0 {
			continue
		}
		if _, ok := pidToProcessExecID[e.Process.PID]; !ok {
			pidToProcessExecID[e.Process.PID] = e.ID
		}
	}
	for _, e := range events {
		if e.Process == nil || e.Process.PID == 0 {
			continue
		}
		var edgeType string
		switch e.Type {
		case "net_connect":
			edgeType = "process_net_connect"
		case "net_listen":
			edgeType = "process_net_listen"
		case "net_accept":
			edgeType = "process_net_accept"
		case "net_msg":
			edgeType = "process_net_msg"
		case "net_tls":
			edgeType = "process_net_tls"
		default:
			continue
		}
		execID, ok := pidToProcessExecID[e.Process.PID]
		if !ok || execID == e.ID {
			continue
		}
		g.Edges = append(g.Edges, EventEdge{
			From: execID,
			To:   e.ID,
			Type: edgeType,
		})
	}

	// Process→container edges: attribute container_start to the process_exec with the same PID (e.g. docker, containerd-shim).
	// Same host/window, deterministic (first exec wins). No inference beyond direct PID linkage.
	for _, e := range events {
		if e.Type != "container_start" || e.Process == nil || e.Process.PID == 0 {
			continue
		}
		execID, ok := pidToProcessExecID[e.Process.PID]
		if !ok || execID == e.ID {
			continue
		}
		g.Edges = append(g.Edges, EventEdge{
			From: execID,
			To:   e.ID,
			Type: "process_container_start",
		})
	}

	// Process→file edges: attribute file_open/file_write/file_unlink to the process_exec with the same PID.
	// Enables file tracing for AI agent detection (download → create → execute chains).
	// Same host/window, deterministic (first exec wins per PID).
	for _, e := range events {
		if e.Process == nil || e.Process.PID == 0 {
			continue
		}
		var edgeType string
		switch e.Type {
		case "file_open":
			edgeType = "process_file_open"
		case "file_write":
			edgeType = "process_file_write"
		case "file_unlink":
			edgeType = "process_file_unlink"
		default:
			continue
		}
		execID, ok := pidToProcessExecID[e.Process.PID]
		if !ok || execID == e.ID {
			continue
		}
		g.Edges = append(g.Edges, EventEdge{
			From: execID,
			To:   e.ID,
			Type: edgeType,
		})
	}

	// Process lifecycle exit: process_exec → process_exit (same PID). Yields start→exit DAG.
	for _, e := range events {
		if e.Type != "process_exit" || e.Process == nil || e.Process.PID == 0 {
			continue
		}
		execID, ok := pidToProcessExecID[e.Process.PID]
		if !ok || execID == e.ID {
			continue
		}
		g.Edges = append(g.Edges, EventEdge{
			From: execID,
			To:   e.ID,
			Type: "process_lifecycle_exit",
		})
	}

	return g
}
