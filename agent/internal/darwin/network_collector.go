//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// ConnectEvent represents a network connection detected via lsof.
type ConnectEvent struct {
	PID      uint32
	Comm     string
	DstIP    string
	DstPort  uint16
	Protocol string // "ipv4" or "ipv6"
}

// NetworkCollector monitors network connections by polling lsof.
type NetworkCollector struct {
	events   chan ConnectEvent
	interval time.Duration
	logger   *slog.Logger

	// Track known connections to avoid duplicates within a cycle.
	lastSeen map[string]bool
}

// NewNetworkCollector creates a new lsof-based network collector.
func NewNetworkCollector(logger *slog.Logger, interval time.Duration) *NetworkCollector {
	if logger == nil {
		logger = slog.Default()
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &NetworkCollector{
		events:   make(chan ConnectEvent, 2048),
		interval: interval,
		logger:   logger,
		lastSeen: make(map[string]bool),
	}
}

// Events returns the channel of connection events.
func (c *NetworkCollector) Events() <-chan ConnectEvent {
	return c.events
}

// Start runs the lsof polling loop. Blocks until ctx is cancelled.
func (c *NetworkCollector) Start(ctx context.Context) {
	c.logger.Info("lsof network collector started", "interval", c.interval)

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("lsof network collector stopping")
			close(c.events)
			return
		case <-ticker.C:
			c.poll()
		}
	}
}

// poll runs lsof and parses network connections.
func (c *NetworkCollector) poll() {
	// lsof -i -n -P +c0 — show all internet connections, no DNS resolution, numeric ports, full command
	cmd := exec.Command("lsof", "-i", "-n", "-P", "+c0")
	out, err := cmd.Output()
	if err != nil {
		// lsof returns exit 1 if no files matched — not an error.
		if len(out) == 0 {
			return
		}
	}

	newSeen := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	// Skip header line
	if scanner.Scan() {
		// consume header
	}

	for scanner.Scan() {
		line := scanner.Text()
		evt, key, ok := parseLsofLine(line)
		if !ok {
			continue
		}

		newSeen[key] = true
		// Only emit if this is a new connection (not seen in previous cycle).
		if !c.lastSeen[key] {
			c.events <- evt
		}
	}

	c.lastSeen = newSeen
}

// parseLsofLine parses a single lsof -i output line.
// Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
// Example: curl 12345 user 5u IPv4 0x123 0t0 TCP 192.168.1.1:54321->93.184.216.34:443 (ESTABLISHED)
func parseLsofLine(line string) (ConnectEvent, string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 9 {
		return ConnectEvent{}, "", false
	}

	comm := fields[0]
	pidStr := fields[1]
	// fields[4] is TYPE (IPv4/IPv6)
	typeField := fields[4]
	// fields[7] is NODE (TCP/UDP)
	nameField := fields[len(fields)-1]

	// Remove state suffix like "(ESTABLISHED)"
	if idx := strings.Index(nameField, "("); idx > 0 {
		nameField = nameField[:idx]
	}

	pid64, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		return ConnectEvent{}, "", false
	}

	// Parse connection: "local->remote"
	parts := strings.SplitN(nameField, "->", 2)
	if len(parts) != 2 {
		return ConnectEvent{}, "", false
	}
	remote := parts[1]

	dstIP, dstPortStr, err := splitHostPort(remote)
	if err != nil {
		return ConnectEvent{}, "", false
	}

	dstPort64, err := strconv.ParseUint(dstPortStr, 10, 16)
	if err != nil {
		return ConnectEvent{}, "", false
	}

	protocol := "ipv4"
	if strings.Contains(typeField, "6") {
		protocol = "ipv6"
	}

	key := pidStr + ":" + dstIP + ":" + dstPortStr

	return ConnectEvent{
		PID:      uint32(pid64),
		Comm:     comm,
		DstIP:    dstIP,
		DstPort:  uint16(dstPort64),
		Protocol: protocol,
	}, key, true
}

// splitHostPort splits "host:port" handling IPv6 bracket notation.
func splitHostPort(s string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(s)
	if err != nil {
		// Try plain "ip:port" if net.SplitHostPort fails
		idx := strings.LastIndex(s, ":")
		if idx < 0 {
			return "", "", err
		}
		host = s[:idx]
		port = s[idx+1:]
		err = nil
	}
	return host, port, err
}
