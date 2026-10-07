//go:build linux

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"

	ciliumebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type tls_event tls bpf/tls.bpf.c

// TLSCollector monitors SSL/TLS traffic via Uprobes.
type TLSCollector struct {
	objs        tlsObjects
	writeLink   link.Link
	readEntLink link.Link
	readRetLink link.Link
	exitLink    link.Link // tracepoint for ai_pids cleanup on process exit
	reader      *ringbuf.Reader
	events      chan TLSEvent
	logger      *slog.Logger
	libSSLPath  string
}

// TLSEvent represents a plaintext capture event.
type TLSEvent struct {
	PID         uint32
	TGID        uint32
	UID         uint32
	TimestampNs uint64
	Len         uint32
	Direction   uint32 // 0=Write, 1=Read
	Comm        string
	Data        []byte
}

// NewTLSCollector creates a new collector for TLS traffic.
func NewTLSCollector(logger *slog.Logger) (*TLSCollector, error) {
	// Find libssl.so
	libPath, err := findLibSSL()
	if err != nil {
		return nil, fmt.Errorf("failed to find libssl: %w", err)
	}
	logger.Info("files libssl", "path", libPath)

	return &TLSCollector{
		logger:     logger,
		libSSLPath: libPath,
		events:     make(chan TLSEvent, 1000),
	}, nil
}

// Start loads eBPF programs and attaches uprobes.
func (c *TLSCollector) Start(ctx context.Context) error {
	// 1. Remove memory limits
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// 2. Load eBPF objects
	if err := loadTlsObjects(&c.objs, nil); err != nil {
		return fmt.Errorf("failed to load tls objects: %w", err)
	}

	// 3. Attach Uprobes
	// SSL_write
	wl, err := link.OpenExecutable(c.libSSLPath)
	if err != nil {
		return fmt.Errorf("failed to open libssl: %w", err)
	}
	c.writeLink, err = wl.Uprobe("SSL_write", c.objs.ProbeSSL_write, nil)
	if err != nil {
		return fmt.Errorf("failed to attach SSL_write: %w", err)
	}

	// SSL_read (Enter)
	c.readEntLink, err = wl.Uprobe("SSL_read", c.objs.ProbeSSL_readEnter, nil)
	if err != nil {
		return fmt.Errorf("failed to attach SSL_read enter: %w", err)
	}

	// SSL_read (Exit/Return)
	c.readRetLink, err = wl.Uretprobe("SSL_read", c.objs.ProbeSSL_readExit, nil)
	if err != nil {
		return fmt.Errorf("failed to attach SSL_read exit: %w", err)
	}

	// Attach tracepoint for ai_pids cleanup on process exit
	c.exitLink, err = link.Tracepoint("sched", "sched_process_exit", c.objs.HandleSchedProcessExit, nil)
	if err != nil {
		// Non-fatal: Go-side cleanup still works, just log warning
		c.logger.Warn("failed to attach sched_process_exit tracepoint for ai_pids cleanup", "error", err)
	}

	// 4. Open Ringbuffer
	c.reader, err = ringbuf.NewReader(c.objs.TlsEvents)
	if err != nil {
		return fmt.Errorf("failed to open ringbuf: %w", err)
	}

	// 5. Start event loop
	go c.readEvents(ctx)

	// 6. Start PID sync (Push AI PIDs to Kernel)
	go c.syncPIDs(ctx)

	<-ctx.Done()
	return nil
}

// readEvents consumes from the ringbuffer.
func (c *TLSCollector) readEvents(ctx context.Context) {
	var event tlsTlsEvent
	for {
		select {
		case <-ctx.Done():
			return
		default:
			record, err := c.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return
				}
				c.logger.Error("ringbuf read error", "error", err)
				continue
			}

			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
				c.logger.Error("decoding error", "error", err)
				continue
			}

			// Parse Comm (convert [16]int8 to []byte)
			commBytes := make([]byte, len(event.Comm))
			for i, v := range event.Comm {
				commBytes[i] = byte(v)
			}
			comm := string(bytes.TrimRight(commBytes, "\x00"))

			// Copy Data
			data := make([]byte, event.Len)
			copy(data, event.Data[:event.Len])

			c.events <- TLSEvent{
				PID:         event.Pid,
				TGID:        event.Tgid,
				UID:         event.Uid,
				TimestampNs: event.TimestampNs,
				Len:         event.Len,
				Direction:   event.Direction,
				Comm:        comm,
				Data:        data,
			}
		}
	}
}

// syncPIDs ensures the kernel map knows which PIDs are AI.
// In a real implementation, we could hook into LineageTracker updates directly.
// For now, we poll or rely on explicit updates if we refactor LineageTracker to push events.
func (c *TLSCollector) syncPIDs(ctx context.Context) {
	// TODO: Subscribe to LineageTracker changes.
	// For MVP, we presume the Runner will handle calling a method on Collector to update PIDs,
	// or we expose the Map for the Runner to write to.
}

// UpdateAIProcess adds a PID to the kernel filter map.
func (c *TLSCollector) UpdateAIProcess(pid uint32) error {
	if c.objs.AiPids == nil {
		return nil // Map not loaded yet
	}
	var val uint8 = 1
	return c.objs.AiPids.Put(pid, val)
}

// RemoveAIProcess removes a PID from the kernel filter map.
func (c *TLSCollector) RemoveAIProcess(pid uint32) error {
	if c.objs.AiPids == nil {
		return nil // Map not loaded yet
	}
	err := c.objs.AiPids.Delete(pid)
	if errors.Is(err, ciliumebpf.ErrKeyNotExist) {
		return nil // PID was never in the map (e.g., registered before TLS probes attached)
	}
	return err
}

// Events returns the channel of TLS events.
func (c *TLSCollector) Events() <-chan TLSEvent {
	return c.events
}

// Close cleans up resources.
func (c *TLSCollector) Close() error {
	if c.reader != nil {
		c.reader.Close()
	}
	if c.writeLink != nil {
		c.writeLink.Close()
	}
	if c.readEntLink != nil {
		c.readEntLink.Close()
	}
	if c.readRetLink != nil {
		c.readRetLink.Close()
	}
	if c.exitLink != nil {
		c.exitLink.Close()
	}
	return c.objs.Close()
}

// findLibSSL attempts to locate libssl.so on the system.
// Simplified version for MVP.
func findLibSSL() (string, error) {
	candidates := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3",
		"/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		"/lib/x86_64-linux-gnu/libssl.so.3",
		"/lib64/libssl.so.3",
		"/usr/lib64/libssl.so.3",
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("libssl.so not found in standard locations")
}
