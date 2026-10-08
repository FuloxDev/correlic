//go:build linux

// Package ebpf provides eBPF-based process exit monitoring (sched_process_exit).
// Phase 20: exec lifecycle modeling.

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// exitEventSize mirrors struct exit_event in bpf/exit.bpf.c:
// pid(4) @0, tid(4) @4, ppid(4) @8, exit_code(4) @12, timestamp_ns(8) @16, comm[16] @24 = 40 bytes.
// Four __u32 fields precede the __u64, so no padding is inserted.
const exitEventSize = 4 + 4 + 4 + 4 + 8 + 16

// ExitEvent is a task exit event from the eBPF ring buffer.
type ExitEvent struct {
	PID       int // thread group id
	TID       int // thread id; equals PID for the thread group leader
	PPID      int
	ExitCode  int
	Timestamp time.Time
	Comm      string
}

// IsProcessExit reports whether this event marks the end of the whole
// process (thread group leader) rather than a single thread.
func (e ExitEvent) IsProcessExit() bool {
	return e.TID == e.PID
}

// ExitCollector manages the exit eBPF program and ring buffer.
type ExitCollector struct {
	objs   *exitObjects
	link   link.Link
	reader *ringbuf.Reader
	events chan ExitEvent
	logger *slog.Logger
}

// NewExitCollector creates and loads the exit eBPF program, attaches to sched_process_exit, and starts reading.
func NewExitCollector(logger *slog.Logger) (*ExitCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	objs := &exitObjects{}
	if err := loadExitObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading exit eBPF objects: %w", err)
	}

	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sched_process_exit",
		Program: objs.HandleExit,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("attaching sched_process_exit: %w", err)
	}

	reader, err := ringbuf.NewReader(objs.ExitEvents)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("creating exit ring buffer reader: %w", err)
	}

	return &ExitCollector{
		objs:   objs,
		link:   l,
		reader: reader,
		events: make(chan ExitEvent, 1024),
		logger: logger,
	}, nil
}

// Events returns the channel of exit events. Never drop; buffer may back up under extreme load.
func (c *ExitCollector) Events() <-chan ExitEvent {
	return c.events
}

// Start reads from the ring buffer and sends ExitEvents. Runs until ctx is done.
func (c *ExitCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF exit collector started (sched_process_exit)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF exit collector stopping")
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.logger.Warn("reading from exit ring buffer", "error", err)
			continue
		}

		ev, err := parseExitEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing exit event", "error", err)
			continue
		}

		// Never drop exit events: block until enqueued (or shutdown).
		select {
		case c.events <- ev:
		case <-ctx.Done():
			return
		}
	}
}

// Close releases eBPF resources.
func (c *ExitCollector) Close() error {
	if c.reader != nil {
		c.reader.Close()
	}
	if c.link != nil {
		c.link.Close()
	}
	if c.objs != nil {
		return c.objs.Close()
	}
	return nil
}

func parseExitEvent(data []byte) (ExitEvent, error) {
	if len(data) < exitEventSize {
		return ExitEvent{}, fmt.Errorf("exit event too short: %d bytes", len(data))
	}
	// Note: tsNano from eBPF is boot time (bpf_ktime_get_ns), not wall-clock time.
	// We use time.Now() for wall-clock timestamp, matching exec handler behavior.
	_ = binary.LittleEndian.Uint64(data[16:24]) // Read but don't use boot time
	return ExitEvent{
		PID:       int(binary.LittleEndian.Uint32(data[0:4])),
		TID:       int(binary.LittleEndian.Uint32(data[4:8])),
		PPID:      int(binary.LittleEndian.Uint32(data[8:12])),
		ExitCode:  int(binary.LittleEndian.Uint32(data[12:16])),
		Timestamp: time.Now(), // Use wall-clock time, not boot time
		Comm:      nullTerminatedString(data[24:40]),
	}, nil
}
