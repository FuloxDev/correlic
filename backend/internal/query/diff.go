package query

import (
	"context"
	"fmt"
	"time"
)

// DiffResult holds the added and removed items when comparing two time windows by stable identity.
type DiffResult[T any] struct {
	Added   []T `json:"added"`
	Removed []T `json:"removed"`
}

// DiffProcessesByExecutable compares process_exec events in two time windows by exe_path.
// Added = executables seen in compare window but not in base. Removed = seen in base but not in compare.
func (s *Service) DiffProcessesByExecutable(
	ctx context.Context,
	hostID string,
	baseSince, baseUntil time.Time,
	compareSince, compareUntil time.Time,
) (DiffResult[ProcessByExecutableRow], error) {
	baseList, _, err := s.ListProcessesByExecutable(ctx, hostID, baseSince, baseUntil, "")
	if err != nil {
		return DiffResult[ProcessByExecutableRow]{}, fmt.Errorf("base window: %w", err)
	}
	compareList, _, err := s.ListProcessesByExecutable(ctx, hostID, compareSince, compareUntil, "")
	if err != nil {
		return DiffResult[ProcessByExecutableRow]{}, fmt.Errorf("compare window: %w", err)
	}
	baseByKey := make(map[string]ProcessByExecutableRow)
	for _, row := range baseList {
		baseByKey[row.ExePath] = row
	}
	compareByKey := make(map[string]ProcessByExecutableRow)
	for _, row := range compareList {
		compareByKey[row.ExePath] = row
	}
	var added, removed []ProcessByExecutableRow
	for k, row := range compareByKey {
		if _, inBase := baseByKey[k]; !inBase {
			added = append(added, row)
		}
	}
	for k, row := range baseByKey {
		if _, inCompare := compareByKey[k]; !inCompare {
			removed = append(removed, row)
		}
	}
	return DiffResult[ProcessByExecutableRow]{Added: added, Removed: removed}, nil
}

// connKey is the stable identity for net_connect: (ip, port).
type connKey struct {
	IP   string
	Port int
}

// DiffExternalConnections compares net_connect events in two time windows by (ip, port).
// Added = connections seen in compare window but not in base. Removed = seen in base but not in compare.
func (s *Service) DiffExternalConnections(
	ctx context.Context,
	hostID string,
	baseSince, baseUntil time.Time,
	compareSince, compareUntil time.Time,
) (DiffResult[ExternalConnectionRow], error) {
	baseList, _, err := s.ListExternalConnections(ctx, hostID, baseSince, baseUntil)
	if err != nil {
		return DiffResult[ExternalConnectionRow]{}, fmt.Errorf("base window: %w", err)
	}
	compareList, _, err := s.ListExternalConnections(ctx, hostID, compareSince, compareUntil)
	if err != nil {
		return DiffResult[ExternalConnectionRow]{}, fmt.Errorf("compare window: %w", err)
	}
	baseByKey := make(map[connKey]ExternalConnectionRow)
	for _, row := range baseList {
		baseByKey[connKey{row.IP, row.Port}] = row
	}
	compareByKey := make(map[connKey]ExternalConnectionRow)
	for _, row := range compareList {
		compareByKey[connKey{row.IP, row.Port}] = row
	}
	var added, removed []ExternalConnectionRow
	for k, row := range compareByKey {
		if _, inBase := baseByKey[k]; !inBase {
			added = append(added, row)
		}
	}
	for k, row := range baseByKey {
		if _, inCompare := compareByKey[k]; !inCompare {
			removed = append(removed, row)
		}
	}
	return DiffResult[ExternalConnectionRow]{Added: added, Removed: removed}, nil
}

// DiffOpenPorts compares net_listen events in two time windows by port.
// Added = ports seen in compare window but not in base. Removed = seen in base but not in compare.
func (s *Service) DiffOpenPorts(
	ctx context.Context,
	hostID string,
	baseSince, baseUntil time.Time,
	compareSince, compareUntil time.Time,
) (DiffResult[OpenPortRow], error) {
	baseList, _, err := s.ListOpenPorts(ctx, hostID, baseSince, baseUntil)
	if err != nil {
		return DiffResult[OpenPortRow]{}, fmt.Errorf("base window: %w", err)
	}
	compareList, _, err := s.ListOpenPorts(ctx, hostID, compareSince, compareUntil)
	if err != nil {
		return DiffResult[OpenPortRow]{}, fmt.Errorf("compare window: %w", err)
	}
	baseByKey := make(map[int]OpenPortRow)
	for _, row := range baseList {
		baseByKey[row.Port] = row
	}
	compareByKey := make(map[int]OpenPortRow)
	for _, row := range compareList {
		compareByKey[row.Port] = row
	}
	var added, removed []OpenPortRow
	for k, row := range compareByKey {
		if _, inBase := baseByKey[k]; !inBase {
			added = append(added, row)
		}
	}
	for k, row := range baseByKey {
		if _, inCompare := compareByKey[k]; !inCompare {
			removed = append(removed, row)
		}
	}
	return DiffResult[OpenPortRow]{Added: added, Removed: removed}, nil
}
