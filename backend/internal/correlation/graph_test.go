package correlation

import (
	"testing"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

func TestBuildGraph_ProcessParentEdges(t *testing.T) {
	// Scenario: parent process executes, then child process executes.
	// Timeline should show correct parent-child relationship in graph edges.
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	parent := event.Event{
		ID: "evt-parent", HostID: "host1", Timestamp: base,
		Source: "kernel", Type: "process_exec", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 100, PPID: 1, ExePath: "/usr/bin/bash"},
	}
	child := event.Event{
		ID: "evt-child", HostID: "host1", Timestamp: base.Add(time.Second),
		Source: "kernel", Type: "process_exec", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 101, PPID: 100, ExePath: "/usr/bin/curl"},
	}
	events := []event.Event{parent, child}

	g := BuildGraph(events)

	if g == nil {
		t.Fatal("BuildGraph returned nil")
	}
	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}

	var processParentEdges []EventEdge
	for _, e := range g.Edges {
		if e.Type == "process_parent" {
			processParentEdges = append(processParentEdges, e)
		}
	}
	if len(processParentEdges) != 1 {
		t.Fatalf("expected exactly one process_parent edge, got %d", len(processParentEdges))
	}
	edge := processParentEdges[0]
	if edge.From != parent.ID || edge.To != child.ID {
		t.Errorf("process_parent edge: expected From=%q To=%q, got From=%q To=%q",
			parent.ID, child.ID, edge.From, edge.To)
	}

	// Temporal edge should also exist (parent before child)
	var temporalEdges []EventEdge
	for _, e := range g.Edges {
		if e.Type == "temporal" {
			temporalEdges = append(temporalEdges, e)
		}
	}
	if len(temporalEdges) != 1 {
		t.Errorf("expected one temporal edge, got %d", len(temporalEdges))
	}
}

func TestBuildGraph_ProcessNetConnectEdges(t *testing.T) {
	// Scenario: process_exec occurs, then net_connect with the same PID occurs after.
	// Graph should contain one temporal edge and one process_net_connect edge.
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	execEvt := event.Event{
		ID: "evt-exec", HostID: "host1", Timestamp: base,
		Source: "kernel", Type: "process_exec", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 200, PPID: 1, ExePath: "/usr/bin/curl"},
	}
	netEvt := event.Event{
		ID: "evt-net", HostID: "host1", Timestamp: base.Add(time.Second),
		Source: "net", Type: "net_connect", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 200},
		Target:  &event.TargetStruct{IP: "93.184.216.34", Port: 443, Protocol: "tcp"},
	}
	events := []event.Event{execEvt, netEvt}

	g := BuildGraph(events)

	if g == nil {
		t.Fatal("BuildGraph returned nil")
	}
	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}

	var temporalEdges []EventEdge
	var processNetConnectEdges []EventEdge
	for _, e := range g.Edges {
		switch e.Type {
		case "temporal":
			temporalEdges = append(temporalEdges, e)
		case "process_net_connect":
			processNetConnectEdges = append(processNetConnectEdges, e)
		}
	}
	if len(temporalEdges) != 1 {
		t.Fatalf("expected exactly one temporal edge, got %d", len(temporalEdges))
	}
	if len(processNetConnectEdges) != 1 {
		t.Fatalf("expected exactly one process_net_connect edge, got %d", len(processNetConnectEdges))
	}
	edge := processNetConnectEdges[0]
	if edge.From != execEvt.ID || edge.To != netEvt.ID {
		t.Errorf("process_net_connect edge: expected From=%q To=%q, got From=%q To=%q",
			execEvt.ID, netEvt.ID, edge.From, edge.To)
	}
}

func TestBuildGraph_ProcessContainerStartEdges(t *testing.T) {
	// Scenario: process_exec (e.g. docker, containerd-shim) occurs, then container_start with same PID follows.
	// Graph should include temporal edge and process_container_start edge.
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	execEvt := event.Event{
		ID: "evt-docker", HostID: "host1", Timestamp: base,
		Source: "kernel", Type: "process_exec", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 300, PPID: 1, ExePath: "/usr/bin/docker"},
	}
	containerEvt := event.Event{
		ID: "evt-container", HostID: "host1", Timestamp: base.Add(2 * time.Second),
		Source: "container", Type: "container_start", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 300},
		Target:  &event.TargetStruct{ContainerID: "abc123", ContainerImg: "nginx:alpine"},
	}
	events := []event.Event{execEvt, containerEvt}

	g := BuildGraph(events)

	if g == nil {
		t.Fatal("BuildGraph returned nil")
	}
	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}

	var temporalEdges []EventEdge
	var processContainerStartEdges []EventEdge
	for _, e := range g.Edges {
		switch e.Type {
		case "temporal":
			temporalEdges = append(temporalEdges, e)
		case "process_container_start":
			processContainerStartEdges = append(processContainerStartEdges, e)
		}
	}
	if len(temporalEdges) != 1 {
		t.Fatalf("expected exactly one temporal edge, got %d", len(temporalEdges))
	}
	if len(processContainerStartEdges) != 1 {
		t.Fatalf("expected exactly one process_container_start edge, got %d", len(processContainerStartEdges))
	}
	edge := processContainerStartEdges[0]
	if edge.From != execEvt.ID || edge.To != containerEvt.ID {
		t.Errorf("process_container_start edge: expected From=%q To=%q, got From=%q To=%q",
			execEvt.ID, containerEvt.ID, edge.From, edge.To)
	}
}

func TestBuildGraph_ProcessLifecycleExitEdges(t *testing.T) {
	// Scenario: process_exec then process_exit with same PID. Graph should include process_lifecycle_exit edge.
	base := time.Date(2025, 1, 31, 12, 0, 0, 0, time.UTC)
	execEvt := event.Event{
		ID: "evt-exec", HostID: "host1", Timestamp: base,
		Source: "kernel", Type: "process_exec", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 42, PPID: 1, ExePath: "/usr/bin/sleep"},
	}
	exitEvt := event.Event{
		ID: "evt-exit", HostID: "host1", Timestamp: base.Add(100 * time.Millisecond),
		Source: "kernel", Type: "process_exit", SchemaVersion: 1,
		Process: &event.ActorStruct{PID: 42, PPID: 1, ExePath: "sleep"},
		Context: map[string]any{"exit_code": 0},
	}
	events := []event.Event{execEvt, exitEvt}

	g := BuildGraph(events)

	if g == nil {
		t.Fatal("BuildGraph returned nil")
	}
	if len(g.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(g.Nodes))
	}

	var lifecycleExitEdges []EventEdge
	for _, e := range g.Edges {
		if e.Type == "process_lifecycle_exit" {
			lifecycleExitEdges = append(lifecycleExitEdges, e)
		}
	}
	if len(lifecycleExitEdges) != 1 {
		t.Fatalf("expected exactly one process_lifecycle_exit edge, got %d", len(lifecycleExitEdges))
	}
	edge := lifecycleExitEdges[0]
	if edge.From != execEvt.ID || edge.To != exitEvt.ID {
		t.Errorf("process_lifecycle_exit edge: expected From=%q To=%q, got From=%q To=%q",
			execEvt.ID, exitEvt.ID, edge.From, edge.To)
	}
}
