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

// maxTreeEntries bounds the in-memory process tree. The oldest entries are
// evicted when the limit is reached (exits normally keep it small).
const maxTreeEntries = 20000

// ForkEvent represents a task fork/exit captured by eBPF.
type ForkEvent struct {
	ParentPID   uint32 // forking task id
	ParentTGID  uint32 // forking process id
	ChildPID    uint32 // new task id
	ChildTGID   uint32 // new task's process id; != ChildPID for threads
	UID         uint32
	TimestampNs uint64
	CloneFlags  uint64
	ParentComm  string
	ChildComm   string
}

// IsExit returns true if this is a task exit event.
func (e *ForkEvent) IsExit() bool {
	return e.CloneFlags == 0xFFFFFFFFFFFFFFFF
}

// IsThread returns true if the task is a thread of an existing process
// rather than a new thread group leader.
func (e *ForkEvent) IsThread() bool {
	return e.ChildPID != e.ChildTGID
}

// IsFork returns true if this is a real fork (new process, not a thread or an exit).
func (e *ForkEvent) IsFork() bool {
	return !e.IsExit() && !e.IsThread()
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
	objs     *forkObjects
	linkFork link.Link
	linkExit link.Link
	reader   *ringbuf.Reader
	events   chan ForkEvent
	logger   *slog.Logger

	// Process tree state, keyed by thread group id.
	mu    sync.RWMutex
	tree  map[uint32]*ProcessNode
	order []uint32 // insertion order for bounded eviction
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

	// Attach to exit tracepoint
	lExit, err := link.Tracepoint("sched", "sched_process_exit", objs.TraceExit, nil)
	if err != nil {
		lFork.Close()
		objs.Close()
		return nil, fmt.Errorf("attaching sched_process_exit tracepoint: %w", err)
	}

	// Create ring buffer reader
	reader, err := ringbuf.NewReader(objs.ForkEvents)
	if err != nil {
		lExit.Close()
		lFork.Close()
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &ForkCollector{
		objs:     objs,
		linkFork: lFork,
		linkExit: lExit,
		reader:   reader,
		// Large buffer to handle thread creation bursts from Electron apps (Cursor/VSCode)
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

		// Threads never enter the tree and are not forwarded: lineage is
		// per process (thread group), and thread churn from Electron apps
		// would otherwise flood the channel.
		if event.ChildPID == 0 || event.IsThread() {
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

// updateTree maintains the process tree state (keyed by tgid).
func (c *ForkCollector) updateTree(event ForkEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if event.IsExit() {
		// Thread group leader exited: forget the process so the tree does
		// not grow without bound.
		c.removeLocked(event.ChildTGID)
		return
	}
	if event.ChildTGID == 0 || event.ChildTGID == event.ParentTGID {
		return
	}

	node := &ProcessNode{
		PID:       event.ChildTGID,
		PPID:      event.ParentTGID,
		Comm:      event.ChildComm,
		UID:       event.UID,
		StartTime: time.Now(),
	}
	if _, exists := c.tree[event.ChildTGID]; !exists {
		c.order = append(c.order, event.ChildTGID)
	}
	c.tree[event.ChildTGID] = node

	// Update parent's children list
	if parent, ok := c.tree[event.ParentTGID]; ok {
		parent.Children = append(parent.Children, event.ChildTGID)
	}

	// Bound the tree: evict the oldest entries (skipping ones already removed).
	for len(c.tree) > maxTreeEntries && len(c.order) > 0 {
		oldest := c.order[0]
		c.order = c.order[1:]
		if _, ok := c.tree[oldest]; ok {
			c.removeLocked(oldest)
		}
	}
}

// removeLocked deletes a tgid from the tree and from its parent's children.
func (c *ForkCollector) removeLocked(tgid uint32) {
	node, ok := c.tree[tgid]
	if !ok {
		return
	}
	delete(c.tree, tgid)
	if parent, ok := c.tree[node.PPID]; ok {
		for i, child := range parent.Children {
			if child == tgid {
				parent.Children = append(parent.Children[:i], parent.Children[i+1:]...)
				break
			}
		}
	}
	// Compact the order slice lazily: drop a leading run of removed ids.
	for len(c.order) > 0 {
		if _, ok := c.tree[c.order[0]]; ok {
			break
		}
		c.order = c.order[1:]
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
		TimestampNs: binary.LittleEndian.Uint64(data[24:32]),
		CloneFlags:  binary.LittleEndian.Uint64(data[32:40]),
		ParentComm:  nullTerminatedString(data[40:56]),
		ChildComm:   nullTerminatedString(data[56:72]),
	}

	return event, nil
}
