//go:build darwin

// Package darwin provides macOS-specific process, file, and network collectors.
//
// MVP uses kqueue (EVFILT_PROC), FSEvents, and lsof polling.
// Phase 2 will add Endpoint Security Framework (ESF) when Apple entitlement is available.
package darwin

import (
	"context"
	"log/slog"
	"sync"
	"syscall"
	"time"
)

// ProcEventType distinguishes exec vs exit events from kqueue.
type ProcEventType int

const (
	ProcExec ProcEventType = iota
	ProcExit
	ProcFork
)

// ProcEvent is emitted by ProcCollector when a process execs, exits, or forks.
type ProcEvent struct {
	Type ProcEventType
	PID  uint32
	PPID uint32 // populated via sysctl after the event
}

// ProcCollector monitors processes using kqueue EVFILT_PROC.
// It watches registered PIDs for exec/exit/fork events.
type ProcCollector struct {
	kq     int
	events chan ProcEvent
	logger *slog.Logger

	mu         sync.Mutex
	watchedPIDs map[int]bool // PIDs being watched in kqueue
}

// NewProcCollector creates a new kqueue-based process collector.
func NewProcCollector(logger *slog.Logger) (*ProcCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}
	kq, err := syscall.Kqueue()
	if err != nil {
		return nil, err
	}
	return &ProcCollector{
		kq:          kq,
		events:      make(chan ProcEvent, 4096),
		logger:      logger,
		watchedPIDs: make(map[int]bool),
	}, nil
}

// Events returns the channel of process events.
func (c *ProcCollector) Events() <-chan ProcEvent {
	return c.events
}

// WatchPID registers a PID for kqueue monitoring.
// Safe to call from any goroutine.
func (c *ProcCollector) WatchPID(pid int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.watchedPIDs[pid] {
		return nil
	}

	kev := syscall.Kevent_t{
		Ident:  uint64(pid),
		Filter: syscall.EVFILT_PROC,
		Flags:  syscall.EV_ADD | syscall.EV_ENABLE,
		Fflags: syscall.NOTE_EXEC | syscall.NOTE_EXIT | syscall.NOTE_FORK,
	}
	_, err := syscall.Kevent(c.kq, []syscall.Kevent_t{kev}, nil, nil)
	if err != nil {
		return err
	}
	c.watchedPIDs[pid] = true
	c.logger.Debug("watching PID", "pid", pid)
	return nil
}

// UnwatchPID stops monitoring a PID.
func (c *ProcCollector) UnwatchPID(pid int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.watchedPIDs[pid] {
		return
	}
	kev := syscall.Kevent_t{
		Ident:  uint64(pid),
		Filter: syscall.EVFILT_PROC,
		Flags:  syscall.EV_DELETE,
	}
	// Best-effort: process may already be gone.
	syscall.Kevent(c.kq, []syscall.Kevent_t{kev}, nil, nil)
	delete(c.watchedPIDs, pid)
}

// Start runs the kqueue event loop. Blocks until ctx is cancelled.
func (c *ProcCollector) Start(ctx context.Context) {
	defer syscall.Close(c.kq)
	defer close(c.events)

	c.logger.Info("kqueue proc collector started")

	eventBuf := make([]syscall.Kevent_t, 64)
	timeout := syscall.NsecToTimespec(int64(500 * time.Millisecond))

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("kqueue proc collector stopping")
			return
		default:
		}

		n, err := syscall.Kevent(c.kq, nil, eventBuf, &timeout)
		if err != nil {
			if err == syscall.EINTR {
				continue
			}
			c.logger.Error("kqueue error", "error", err)
			continue
		}

		for i := 0; i < n; i++ {
			kev := eventBuf[i]
			pid := uint32(kev.Ident)

			if kev.Fflags&syscall.NOTE_EXEC != 0 {
				c.events <- ProcEvent{
					Type: ProcExec,
					PID:  pid,
				}
			}
			if kev.Fflags&syscall.NOTE_FORK != 0 {
				c.events <- ProcEvent{
					Type: ProcFork,
					PID:  pid,
				}
			}
			if kev.Fflags&syscall.NOTE_EXIT != 0 {
				c.events <- ProcEvent{
					Type: ProcExit,
					PID:  pid,
				}
				// Auto-remove exited PIDs from watch list.
				c.mu.Lock()
				delete(c.watchedPIDs, int(pid))
				c.mu.Unlock()
			}
		}
	}
}

// Close cleans up the kqueue descriptor.
func (c *ProcCollector) Close() error {
	return syscall.Close(c.kq)
}
