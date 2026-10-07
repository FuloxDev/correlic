//go:build linux

// Package ebpf provides eBPF-based file open monitoring.
//
// This collector monitors file open operations for sensitive credential paths:
// - ~/.ssh/* (SSH keys)
// - ~/.aws/* (AWS credentials)
// - ~/.kube/* (Kubernetes config)
// - ~/.gnupg/* (GPG keys)
// - Browser credential stores

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// FileOpenEvent represents a file access captured by eBPF.
type FileOpenEvent struct {
	PID         uint32
	PPID        uint32
	UID         uint32
	GID         uint32
	TimestampNs uint64
	Flags       int32  // O_RDONLY, O_WRONLY, etc.
	Comm        string // Command name
	Filename    string // File path being accessed
}

// FileCollector manages the file open eBPF program lifecycle.
type FileCollector struct {
	objs   *fileopenObjects
	link   link.Link
	reader *ringbuf.Reader
	events chan FileOpenEvent
	logger *slog.Logger
}

// NewFileCollector creates a new eBPF-based file open collector.
func NewFileCollector(logger *slog.Logger) (*FileCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &fileopenObjects{}
	if err := loadFileopenObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading fileopen eBPF objects: %w", err)
	}

	// Attach to the openat tracepoint
	l, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.TraceOpenat, nil)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching openat tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.FileEvents)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &FileCollector{
		objs:   objs,
		link:   l,
		reader: reader,
		events: make(chan FileOpenEvent, 1000),
		logger: logger,
	}, nil
}

// Events returns a channel of file open events.
func (c *FileCollector) Events() <-chan FileOpenEvent {
	return c.events
}

// Start begins reading events from the eBPF program.
func (c *FileCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF file open collector started (monitoring credential paths)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF file open collector stopping")
			return
		default:
		}

		// Read the next event
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.logger.Info("file events ring buffer closed, stopping")
				return
			}
			c.logger.Warn("reading from file events ring buffer", "error", err)
			continue
		}

		// Parse the event
		event, err := parseFileOpenEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing file open event", "error", err)
			continue
		}

		// Send to channel
		select {
		case c.events <- event:
		default:
			c.logger.Warn("file event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *FileCollector) Close() error {
	c.reader.Close()
	c.link.Close()
	return c.objs.Close()
}

// parseFileOpenEvent converts raw bytes from the ring buffer to FileOpenEvent.
// Layout: pid(4) + ppid(4) + uid(4) + gid(4) + timestamp(8) + flags(4) + comm(16) + filename(256) = 300 bytes
func parseFileOpenEvent(data []byte) (FileOpenEvent, error) {
	if len(data) < 300 {
		return FileOpenEvent{}, fmt.Errorf("file event too short: %d bytes (expected 300)", len(data))
	}

	event := FileOpenEvent{
		PID:         littleEndian.Uint32(data[0:4]),
		PPID:        littleEndian.Uint32(data[4:8]),
		UID:         littleEndian.Uint32(data[8:12]),
		GID:         littleEndian.Uint32(data[12:16]),
		TimestampNs: littleEndian.Uint64(data[16:24]),
		Flags:       int32(littleEndian.Uint32(data[24:28])),
		Comm:        nullTerminatedString(data[28:44]),  // 16 bytes
		Filename:    nullTerminatedString(data[44:300]), // 256 bytes
	}

	return event, nil
}

// IsFileCollectorAvailable checks if file open monitoring is supported.
func IsFileCollectorAvailable() bool {
	// Same check as process monitoring - requires BTF
	return IsAvailable()
}
