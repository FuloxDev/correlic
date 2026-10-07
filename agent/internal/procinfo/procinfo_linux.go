//go:build linux

// Package procinfo provides platform-specific process information helpers.
package procinfo

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// containerIDPattern matches Docker, containerd, and cri-o container IDs in cgroup paths.
var containerIDPattern = regexp.MustCompile(`(?:docker-|cri-containerd-|cri-o-)?([a-f0-9]{64})(?:\.scope)?`)

// DetectContainerID attempts to detect the container ID for a process.
// Returns empty string if not in a container or container ID cannot be determined.
func DetectContainerID(pid uint32) string {
	cgroupPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cgroup"

	file, err := os.Open(cgroupPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		matches := containerIDPattern.FindStringSubmatch(line)
		if len(matches) > 1 {
			return matches[1]
		}

		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/docker/")
			if len(parts) > 1 {
				containerID := strings.TrimSpace(parts[len(parts)-1])
				if len(containerID) >= 12 {
					return containerID[:min(64, len(containerID))]
				}
			}
		}

		if strings.Contains(line, "/containerd/") {
			parts := strings.Split(line, "/containerd/")
			if len(parts) > 1 {
				containerID := strings.TrimSpace(parts[len(parts)-1])
				if len(containerID) >= 12 {
					return containerID[:min(64, len(containerID))]
				}
			}
		}
	}

	return ""
}

// DetectSessionID attempts to detect the session ID for a process.
// Returns 0 if session ID cannot be determined.
func DetectSessionID(pid uint32) uint32 {
	statPath := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/stat"

	data, err := os.ReadFile(statPath)
	if err != nil {
		return 0
	}

	content := string(data)
	lastParen := strings.LastIndex(content, ")")
	if lastParen == -1 {
		return 0
	}

	fields := strings.Fields(content[lastParen+1:])
	if len(fields) < 4 {
		return 0
	}

	// Field index: 0=state, 1=ppid, 2=pgrp, 3=session
	session, err := strconv.ParseUint(fields[3], 10, 32)
	if err != nil {
		return 0
	}

	return uint32(session)
}

// ReadProcCmdline reads /proc/[pid]/cmdline and returns the argv as a string slice.
func ReadProcCmdline(pid uint32) []string {
	path := "/proc/" + strconv.FormatUint(uint64(pid), 10) + "/cmdline"
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	raw := strings.TrimRight(string(data), "\x00")
	if raw == "" {
		return nil
	}
	return strings.Split(raw, "\x00")
}
