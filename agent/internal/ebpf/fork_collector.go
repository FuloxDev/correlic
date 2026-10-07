//go:build linux

// Package ebpf provides eBPF-based process tree tracking.
package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ForkEvent represents a process fork/exit captured by eBPF.
type ForkEvent struct {
	ParentPID   uint32
	ParentTGID  uint32
	ChildPID    uint32
	ChildTGID   uint32
	UID         uint32
	TimestampNs uint64
	CloneFlags  uint64
	ParentComm  string
	ChildComm   string
}

// IsExit returns true if this is a process exit event.
func (e *ForkEvent) IsExit() bool {
	return e.CloneFlags == 0xFFFFFFFFFFFFFFFF
}

// IsFork returns true if this is a real fork (new process, not thread).
func (e *ForkEvent) IsFork() bool {
	const CLONE_THREAD = 0x00010000
	return !e.IsExit() && (e.CloneFlags&CLONE_THREAD) == 0
}

// IsThread returns true if this created a thread, not a process.
func (e *ForkEvent) IsThread() bool {
	const CLONE_THREAD = 0x00010000
	return (e.CloneFlags & CLONE_THREAD) != 0
}

// ProcessNode represents a process in the tree.
type ProcessNode struct {
	PID       uint32     `json:"pid"`
	PPID      uint32     `json:"ppid"`
	Comm      string     `json:"comm"`
	UID       uint32     `json:"uid"`
	StartTime time.Time  `json:"start_time"`
	EndTime   *time.Time `json:"end_time,omitempty"`
	Children  []uint32   `json:"children,omitempty"`
}

// ForkCollector manages the fork eBPF program and builds process tree.
type ForkCollector struct {
	objs      *forkObjects
	linkFork  link.Link
	linkClone link.Link
	linkExit  link.Link
	reader    *ringbuf.Reader
	events    chan ForkEvent
	logger    *slog.Logger

	// Process tree state
	mu   sync.RWMutex
	tree map[uint32]*ProcessNode
}

// NewForkCollector creates a new eBPF-based fork collector.
func NewForkCollector(logger *slog.Logger) (*ForkCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Remove memory lock limits for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	// Load the eBPF objects
	objs := &forkObjects{}
	if err := loadForkObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading fork eBPF objects: %w", err)
	}

	// Attach to sched_process_fork via raw tracepoint (avoids CO-RE on tracepoint context type)
	lFork, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_fork",
		Program: objs.TraceFork,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching sched_process_fork raw tracepoint: %w", err)
	}

	// Attach to clone syscall (optional, for clone_flags)
	lClone, err := link.Tracepoint("syscalls", "sys_enter_clone", objs.TraceCloneEnter, nil)
	if err != nil {
		// Clone is optional, continue without it
		lClone = nil
		logger.Warn("clone tracepoint not attached (clone flags won't be captured)")
	}

	// Attach to exit tracepoint
	lExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		if lClone != nil {
			lClone.Close()
		}
		lFork.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching sched_process_exit tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.ForkEvents)
	if err != nil {
		lExit.Close()
		if lClone != nil {
			lClone.Close()
		}
		lFork.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &ForkCollector{
		objs:      objs,
		linkFork:  lFork,
		linkClone: lClone,
		linkExit:  lExit,
		reader:    reader,
		// Increased buffer from 1000 to 5000 to handle thread creation bursts from Electron apps (Cursor/VSCode)
		events: make(chan ForkEvent, 5000),
		logger: logger,
		tree:   make(map[uint32]*ProcessNode),
	}, nil
}

// Events returns a channel of fork events.
func (c *ForkCollector) Events() <-chan ForkEvent {
	return c.events
}

// Start begins reading events from the eBPF program.
func (c *ForkCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF fork collector started (building process tree)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF fork collector stopping")
			return
		default:
		}

		// Read the next event
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				c.logger.Info("fork events ring buffer closed, stopping")
				return
			}
			c.logger.Warn("reading from fork events ring buffer", "error", err)
			continue
		}

		// Parse the event
		event, err := parseForkEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing fork event", "error", err)
			continue
		}

		// Update tree state
		c.updateTree(event)

		// Send to channel
		select {
		case c.events <- event:
		default:
			c.logger.Warn("fork event channel full, dropping event")
		}
	}
}

// updateTree maintains the process tree state.
func (c *ForkCollector) updateTree(event ForkEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if event.IsExit() {
		// Mark process as exited
		if node, ok := c.tree[event.ChildPID]; ok {
			now := time.Now()
			node.EndTime = &now
		}
		return
	}

	// New process
	if event.ChildPID != 0 {
		node := &ProcessNode{
			PID:       event.ChildPID,
			PPID:      event.ParentPID,
			Comm:      event.ChildComm,
			UID:       event.UID,
			StartTime: time.Now(),
		}
		c.tree[event.ChildPID] = node

		// Update parent's children list
		if parent, ok := c.tree[event.ParentPID]; ok {
			parent.Children = append(parent.Children, event.ChildPID)
		}
	}
}

// GetTree returns a snapshot of the current process tree.
func (c *ForkCollector) GetTree() map[uint32]*ProcessNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Create a copy
	result := make(map[uint32]*ProcessNode, len(c.tree))
	for k, v := range c.tree {
		cp := *v
		if v.EndTime != nil {
			endCopy := *v.EndTime
			cp.EndTime = &endCopy
		}
		cp.Children = append([]uint32{}, v.Children...)
		result[k] = &cp
	}
	return result
}

// Close releases eBPF resources.
func (c *ForkCollector) Close() error {
	c.reader.Close()
	c.linkExit.Close()
	if c.linkClone != nil {
		c.linkClone.Close()
	}
	c.linkFork.Close()
	return c.objs.Close()
}

// parseForkEvent converts raw bytes from the ring buffer to ForkEvent.
// IMPORTANT: C compiler adds 4 bytes of padding after uid for __u64 alignment
// Layout: parent_pid(4) + parent_tgid(4) + child_pid(4) + child_tgid(4) + uid(4) + PADDING(4) + timestamp(8) + clone_flags(8) + parent_comm(16) + child_comm(16) = 72 bytes
func parseForkEvent(data []byte) (ForkEvent, error) {
	if len(data) < 72 {
		return ForkEvent{}, fmt.Errorf("fork event too short: %d bytes (expected 72)", len(data))
	}

	event := ForkEvent{
		ParentPID:  binary.LittleEndian.Uint32(data[0:4]),
		ParentTGID: binary.LittleEndian.Uint32(data[4:8]),
		ChildPID:   binary.LittleEndian.Uint32(data[8:12]),
		ChildTGID:  binary.LittleEndian.Uint32(data[12:16]),
		UID:        binary.LittleEndian.Uint32(data[16:20]),
		// 4 bytes of padding here (20-23)
		TimestampNs: binary.LittleEndian.Uint64(data[24:32]), // was 20:28
		CloneFlags:  binary.LittleEndian.Uint64(data[32:40]), // was 28:36
		ParentComm:  nullTerminatedString(data[40:56]),       // was 36:52
		ChildComm:   nullTerminatedString(data[56:72]),       // was 52:68
	}

	return event, nil
}
