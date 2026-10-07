//go:build linux

package ebpf

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// MsgEvent is a sendmsg or recvmsg event (metadata only).
// Size is best-effort from the first iov only; not guaranteed to match bytes sent/received.
type MsgEvent struct {
	PID         uint32
	FD          uint32
	Direction   uint32 // 0 = send, 1 = recv
	Size        uint32 // best-effort first iov; not total
	TimestampNs uint64
	Comm        string
}

// MsgCollector manages the msg eBPF program lifecycle.
type MsgCollector struct {
	objs   *msgObjects
	links  []link.Link
	reader *ringbuf.Reader
	events chan MsgEvent
	logger *slog.Logger
}

// NewMsgCollector creates a new sendmsg/recvmsg eBPF collector.
func NewMsgCollector(logger *slog.Logger) (*MsgCollector, error) {
	if logger == nil {
		logger = slog.Default()
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("removing memlock limit: %w", err)
	}

	objs := &msgObjects{}
	if err := loadMsgObjects(objs, nil); err != nil {
		return nil, fmt.Errorf("loading msg eBPF objects: %w", err)
	}

	tracepoints := []struct {
		cat, name string
		prog      *ebpf.Program
	}{
		{"syscalls", "sys_enter_sendmsg", objs.TraceSendmsg},
		{"syscalls", "sys_enter_recvmsg", objs.TraceRecvmsg},
	}

	var links []link.Link
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.cat, tp.name, tp.prog, nil)
		if err != nil {
			for _, lnk := range links {
				lnk.Close()
			}
			objs.Close()
			return nil, fmt.Errorf("attach %s/%s: %w", tp.cat, tp.name, err)
		}
		links = append(links, l)
	}

	reader, err := ringbuf.NewReader(objs.MsgEvents)
	if err != nil {
		for _, l := range links {
			l.Close()
		}
		objs.Close()
		return nil, fmt.Errorf("creating ring buffer reader: %w", err)
	}

	return &MsgCollector{
		objs:   objs,
		links:  links,
		reader: reader,
		events: make(chan MsgEvent, 1000),
		logger: logger,
	}, nil
}

// Events returns the channel of msg events.
func (c *MsgCollector) Events() <-chan MsgEvent {
	return c.events
}

// Start reads events from the ring buffer.
func (c *MsgCollector) Start(ctx context.Context) {
	c.logger.Info("eBPF msg collector started (sendmsg/recvmsg metadata)")

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("eBPF msg collector stopping")
			return
		default:
		}

		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			c.logger.Warn("reading from msg events ring buffer", "error", err)
			continue
		}

		event, err := parseMsgEvent(record.RawSample)
		if err != nil {
			c.logger.Warn("parsing msg event", "error", err)
			continue
		}

		select {
		case c.events <- event:
		default:
			c.logger.Warn("msg event channel full, dropping event")
		}
	}
}

// Close releases eBPF resources.
func (c *MsgCollector) Close() error {
	c.reader.Close()
	for _, l := range c.links {
		l.Close()
	}
	return c.objs.Close()
}

// parseMsgEvent: pid(4)+fd(4)+direction(4)+size(4)+timestamp_ns(8)+comm(16)=40 bytes
func parseMsgEvent(data []byte) (MsgEvent, error) {
	if len(data) < 40 {
		return MsgEvent{}, fmt.Errorf("msg event too short: %d bytes", len(data))
	}
	return MsgEvent{
		PID:         binary.LittleEndian.Uint32(data[0:4]),
		FD:          binary.LittleEndian.Uint32(data[4:8]),
		Direction:   binary.LittleEndian.Uint32(data[8:12]),
		Size:        binary.LittleEndian.Uint32(data[12:16]),
		TimestampNs: binary.LittleEndian.Uint64(data[16:24]),
		Comm:        nullTerminatedString(data[24:40]),
	}, nil
}
