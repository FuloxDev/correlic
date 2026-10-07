package summarizer

import (
	"fmt"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/tools"
	"github.com/correlic/correlic-backend/internal/query"
)

// maxSummaryItems is the max number of items to list in a summary before abbreviating with "… and N more".
const maxSummaryItems = 10

const truncationSuffix = " Showing first 200 results (truncated). Narrow the time window for full details."

// Summarize produces a short factual summary of the tool result. It does not invent data or conclusions.
// If truncated is true, appends a fixed message; no guessing or advice beyond that.
func Summarize(toolName string, result any, truncated bool) (string, error) {
	if result == nil {
		return "No data returned.", nil
	}
	var s string
	var err error
	switch toolName {
	case "list_containers":
		s, err = summarizeContainers(result)
	case "list_open_ports":
		s, err = summarizeOpenPorts(result)
	case "list_external_connections":
		s, err = summarizeExternalConnections(result)
	case "list_processes_by_executable":
		s, err = summarizeProcessesByExecutable(result)
	case "diff_processes", "diff_connections", "diff_ports":
		s, err = summarizeDiff(toolName, result)
	default:
		s = fmt.Sprintf("Tool %q returned data.", toolName)
	}
	if err != nil {
		return "", err
	}
	if truncated {
		s += truncationSuffix
	}
	return s, nil
}

func summarizeContainers(result any) (string, error) {
	rows, ok := result.([]query.ContainerStartRow)
	if !ok || len(rows) == 0 {
		return "No containers started in the given time range.", nil
	}
	if len(rows) == 1 {
		r := rows[0]
		img := r.ContainerImg
		if img == "" {
			img = r.ContainerID
		}
		if img == "" {
			img = "unknown image"
		}
		return fmt.Sprintf("Yes. One container (%s) was started at %s.", img, r.Timestamp.Format(time.RFC3339)), nil
	}
	var parts []string
	show := rows
	if len(rows) > maxSummaryItems {
		show = rows[:maxSummaryItems]
	}
	for _, r := range show {
		img := r.ContainerImg
		if img == "" {
			img = r.ContainerID
		}
		if img == "" {
			img = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s at %s", img, r.Timestamp.Format("15:04")))
	}
	s := strings.Join(parts, "; ")
	if len(rows) > maxSummaryItems {
		s += fmt.Sprintf(" … and %d more.", len(rows)-maxSummaryItems)
	}
	return fmt.Sprintf("Yes. %d container(s) started: %s.", len(rows), s), nil
}

func summarizeOpenPorts(result any) (string, error) {
	rows, ok := result.([]query.OpenPortRow)
	if !ok || len(rows) == 0 {
		return "No ports opened in the given time range.", nil
	}
	if len(rows) == 1 {
		r := rows[0]
		return fmt.Sprintf("Yes. One port opened: %d/%s at %s.", r.Port, r.Protocol, r.Timestamp.Format(time.RFC3339)), nil
	}
	var parts []string
	show := rows
	if len(rows) > maxSummaryItems {
		show = rows[:maxSummaryItems]
	}
	for _, r := range show {
		parts = append(parts, fmt.Sprintf("%d/%s", r.Port, r.Protocol))
	}
	s := strings.Join(parts, ", ")
	if len(rows) > maxSummaryItems {
		s += fmt.Sprintf(" … and %d more.", len(rows)-maxSummaryItems)
	}
	return fmt.Sprintf("Yes. %d port(s) opened: %s.", len(rows), s), nil
}

func summarizeExternalConnections(result any) (string, error) {
	rows, ok := result.([]query.ExternalConnectionRow)
	if !ok || len(rows) == 0 {
		return "No external connections in the given time range.", nil
	}
	if len(rows) == 1 {
		r := rows[0]
		return fmt.Sprintf("Yes. One external connection to %s:%d (%s) at %s.", r.IP, r.Port, r.Protocol, r.Timestamp.Format(time.RFC3339)), nil
	}
	var parts []string
	seen := make(map[string]bool)
	for _, r := range rows {
		k := fmt.Sprintf("%s:%d", r.IP, r.Port)
		if !seen[k] {
			seen[k] = true
			parts = append(parts, k)
			if len(parts) >= maxSummaryItems {
				break
			}
		}
	}
	s := strings.Join(parts, ", ")
	if len(rows) > maxSummaryItems {
		s += fmt.Sprintf(" … and %d more.", len(rows)-len(parts))
	}
	return fmt.Sprintf("Yes. %d external connection(s) to: %s.", len(rows), s), nil
}

func summarizeProcessesByExecutable(result any) (string, error) {
	rows, ok := result.([]query.ProcessByExecutableRow)
	if !ok || len(rows) == 0 {
		return "No matching processes in the given time range.", nil
	}
	primary := 0
	for _, r := range rows {
		if r.ExecClass == "primary" {
			primary++
		}
	}
	other := len(rows) - primary
	if len(rows) == 1 {
		r := rows[0]
		exe := r.ExePath
		if exe == "" {
			exe = "unknown"
		}
		return fmt.Sprintf("Yes. One process: %s (PID %d) at %s.", exe, r.PID, r.Timestamp.Format(time.RFC3339)), nil
	}
	if primary > 0 && other > 0 {
		var parts []string
		show := rows
		if len(rows) > maxSummaryItems {
			show = rows[:maxSummaryItems]
		}
		for _, r := range show {
			if r.ExecClass != "primary" {
				continue
			}
			exe := r.ExePath
			if exe == "" {
				exe = "unknown"
			}
			parts = append(parts, fmt.Sprintf("%s (PID %d)", exe, r.PID))
		}
		s := strings.Join(parts, "; ")
		if primary > maxSummaryItems {
			s += fmt.Sprintf(" … and %d more primary.", primary-maxSummaryItems)
		}
		return fmt.Sprintf("%d primary process(es) ran (%d helper/runtime execs suppressed). %s.", primary, other, s), nil
	}
	var parts []string
	show := rows
	if len(rows) > maxSummaryItems {
		show = rows[:maxSummaryItems]
	}
	for _, r := range show {
		exe := r.ExePath
		if exe == "" {
			exe = "unknown"
		}
		parts = append(parts, fmt.Sprintf("%s (PID %d)", exe, r.PID))
	}
	s := strings.Join(parts, "; ")
	if len(rows) > maxSummaryItems {
		s += fmt.Sprintf(" … and %d more.", len(rows)-maxSummaryItems)
	}
	return fmt.Sprintf("Yes. %d process(es): %s.", len(rows), s), nil
}

func summarizeDiff(toolName string, result any) (string, error) {
	d, ok := result.(tools.DiffData)
	if !ok {
		return "No diff data.", nil
	}
	subject := "items"
	switch toolName {
	case "diff_processes":
		subject = "processes"
	case "diff_connections":
		subject = "connections"
	case "diff_ports":
		subject = "ports"
	}
	if d.LenAdded == 0 && d.LenRemoved == 0 {
		return fmt.Sprintf("No change in %s between the two windows.", subject), nil
	}
	if d.LenAdded > 0 && d.LenRemoved == 0 {
		return fmt.Sprintf("%d new %s in the last hour.", d.LenAdded, subject), nil
	}
	if d.LenAdded == 0 && d.LenRemoved > 0 {
		return fmt.Sprintf("%d %s no longer present.", d.LenRemoved, subject), nil
	}
	return fmt.Sprintf("%d new %s, %d removed.", d.LenAdded, subject, d.LenRemoved), nil
}
