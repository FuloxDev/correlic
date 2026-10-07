package query

import (
	"context"
	"fmt"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
	"github.com/correlic/correlic-backend/internal/storage/neo4j"
	neo4jdriver "github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// InvestigationService provides specialized investigation queries
type InvestigationService struct {
	client *neo4j.Client
}

// NewInvestigationService creates a new investigation service
func NewInvestigationService(client *neo4j.Client) *InvestigationService {
	return &InvestigationService{client: client}
}

// Container represents a Docker container lifecycle
type Container struct {
	PID         int        `json:"pid"`
	ContainerID string     `json:"container_id"`
	Image       string     `json:"image"`
	StartedAt   time.Time  `json:"started_at"`
	StoppedAt   *time.Time `json:"stopped_at,omitempty"`
	Runtime     string     `json:"runtime"`
}

// FileExecutionChain represents the full chain from file download to execution
type FileExecutionChain struct {
	FilePath       string         `json:"file_path"`
	DownloadEvent  *event.Event   `json:"download_event,omitempty"`
	CreateEvent    *event.Event   `json:"create_event"`
	ExecutionEvent *event.Event   `json:"execution_event"`
	NetworkEvents  []*event.Event `json:"network_events"`
	Timeline       string         `json:"timeline"`
}

// Process represents a process with network activity
type Process struct {
	PID     int          `json:"pid"`
	ExePath string       `json:"exe_path"`
	User    string       `json:"user"`
	Event   *event.Event `json:"event"`
}

// FindDockerContainers finds all Docker containers started since a given time
func (s *InvestigationService) FindDockerContainers(ctx context.Context, since time.Time) ([]Container, error) {
	query := `
		MATCH (start:Event {type: 'process_exec'})
		WHERE (start.actor_exe_path CONTAINS 'docker' OR start.actor_exe_path CONTAINS 'containerd')
		  AND datetime(start.timestamp) >= datetime($since)
		OPTIONAL MATCH (start)-[:LIFECYCLE]->(exit:Event {type: 'process_exit'})
		RETURN 
		  start.actor_pid as pid,
		  start.timestamp as started_at,
		  exit.timestamp as stopped_at,
		  start.actor_exe_path as image
		ORDER BY start.timestamp DESC
	`

	params := map[string]any{
		"since": since.Format(time.RFC3339Nano),
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("docker containers query failed: %w", err)
	}

	var containers []Container
	for _, record := range result.Records {
		container := Container{
			PID:   int(record.Values[0].(int64)),
			Image: record.Values[3].(string),
		}

		if startedAt, ok := record.Values[1].(string); ok {
			if ts, err := time.Parse(time.RFC3339Nano, startedAt); err == nil {
				container.StartedAt = ts
			}
		}

		if stoppedAt, ok := record.Values[2].(string); ok && stoppedAt != "" {
			if ts, err := time.Parse(time.RFC3339Nano, stoppedAt); err == nil {
				container.StoppedAt = &ts
			}
		}

		// Calculate runtime
		if container.StoppedAt != nil {
			container.Runtime = container.StoppedAt.Sub(container.StartedAt).String()
		} else {
			container.Runtime = time.Since(container.StartedAt).String()
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// TraceFileExecution traces a file from download/creation to execution
func (s *InvestigationService) TraceFileExecution(ctx context.Context, filePath string) (*FileExecutionChain, error) {
	query := `
		// Find file execution
		MATCH (exec:Event {type: 'process_exec'})
		WHERE exec.actor_exe_path = $file_path
		
		// Find file creation
		OPTIONAL MATCH (create:Event {type: 'file_open', target_path: $file_path})
		WHERE create.timestamp <= exec.timestamp
		
		// Find network download (if any)
		OPTIONAL MATCH (download:Event {type: 'net_connect'})
		WHERE download.actor_pid = create.actor_pid
		  AND download.timestamp <= create.timestamp
		  AND duration.between(datetime(download.timestamp), datetime(create.timestamp)) < duration('PT1M')
		
		// Find subsequent network activity
		OPTIONAL MATCH (exec)-[:NET_CONNECT]->(net:Event {type: 'net_connect'})
		
		RETURN exec, create, download, collect(net) as network_events
		LIMIT 1
	`

	params := map[string]any{
		"file_path": filePath,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("file execution trace query failed: %w", err)
	}

	if len(result.Records) == 0 {
		return nil, fmt.Errorf("no execution found for file: %s", filePath)
	}

	record := result.Records[0]
	chain := &FileExecutionChain{
		FilePath: filePath,
	}

	// Parse execution event
	if execNode, ok := record.Values[0].(neo4jdriver.Node); ok {
		chain.ExecutionEvent = nodeToEvent(execNode)
	}

	// Parse create event
	if createNode, ok := record.Values[1].(neo4jdriver.Node); ok {
		chain.CreateEvent = nodeToEvent(createNode)
	}

	// Parse download event
	if downloadNode, ok := record.Values[2].(neo4jdriver.Node); ok {
		chain.DownloadEvent = nodeToEvent(downloadNode)
	}

	// Parse network events
	if netEvents, ok := record.Values[3].([]any); ok {
		for _, netNode := range netEvents {
			if node, ok := netNode.(neo4jdriver.Node); ok {
				chain.NetworkEvents = append(chain.NetworkEvents, nodeToEvent(node))
			}
		}
	}

	// Build timeline summary
	if chain.DownloadEvent != nil && chain.CreateEvent != nil && chain.ExecutionEvent != nil {
		downloadTime := chain.DownloadEvent.Timestamp
		createTime := chain.CreateEvent.Timestamp
		execTime := chain.ExecutionEvent.Timestamp

		chain.Timeline = fmt.Sprintf("Downloaded at %s → Created at %s → Executed at %s",
			downloadTime.Format("15:04:05"),
			createTime.Format("15:04:05"),
			execTime.Format("15:04:05"),
		)
	}

	return chain, nil
}

// FindPortListeners finds all processes listening on a specific port
func (s *InvestigationService) FindPortListeners(ctx context.Context, port int) ([]Process, error) {
	query := `
		MATCH (listen:Event {type: 'net_listen'})
		WHERE listen.target_port = $port
		MATCH (process:Event {type: 'process_exec'})
		WHERE process.actor_pid = listen.actor_pid
		  AND process.host_id = listen.host_id
		RETURN DISTINCT process
		ORDER BY process.timestamp DESC
	`

	params := map[string]any{
		"port": port,
	}

	result, err := s.client.ExecuteRead(ctx, query, params)
	if err != nil {
		return nil, fmt.Errorf("port listeners query failed: %w", err)
	}

	var processes []Process
	for _, record := range result.Records {
		node, ok := record.Values[0].(neo4jdriver.Node)
		if !ok {
			continue
		}

		evt := nodeToEvent(node)
		if evt.Process != nil {
			processes = append(processes, Process{
				PID:     evt.Process.PID,
				ExePath: evt.Process.ExePath,
				User:    evt.Process.User,
				Event:   evt,
			})
		}
	}

	return processes, nil
}
