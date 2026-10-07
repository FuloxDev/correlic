//go:build darwin && esf

package esf

import (
	"context"
	"log/slog"
)

// Collector wraps the ESF Client and fans out events to per-type channels
// consumed by the individual runners (exec, file, network, DNS).
type Collector struct {
	client *Client
	logger *slog.Logger

	exec    chan Event
	exit    chan Event
	open    chan Event
	lookup  chan Event
}

// NewCollector creates a new ESF collector using the provided client.
func NewCollector(client *Client, logger *slog.Logger) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	return &Collector{
		client:  client,
		logger:  logger,
		exec:    make(chan Event, 2048),
		exit:    make(chan Event, 2048),
		open:    make(chan Event, 4096),
		lookup:  make(chan Event, 2048),
	}
}

// Subscribe registers all ESF event types used by Correlic.
func (c *Collector) Subscribe() error {
	return c.client.Subscribe([]EventType{
		EventExec,
		EventExit,
		EventOpen,
		EventLookup,
	})
}

// ExecEvents returns the channel for ES_EVENT_TYPE_NOTIFY_EXEC events.
func (c *Collector) ExecEvents() <-chan Event { return c.exec }

// ExitEvents returns the channel for ES_EVENT_TYPE_NOTIFY_EXIT events.
func (c *Collector) ExitEvents() <-chan Event { return c.exit }

// OpenEvents returns the channel for ES_EVENT_TYPE_NOTIFY_OPEN events.
func (c *Collector) OpenEvents() <-chan Event { return c.open }

// LookupEvents returns the channel for ES_EVENT_TYPE_NOTIFY_LOOKUP events.
func (c *Collector) LookupEvents() <-chan Event { return c.lookup }

// Start fans out events from the ESF client to per-type channels.
// Blocks until ctx is cancelled.
func (c *Collector) Start(ctx context.Context) {
	c.logger.Info("esf collector started")
	defer func() {
		close(c.exec)
		close(c.exit)
		close(c.open)
		close(c.lookup)
		c.logger.Info("esf collector stopped")
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-c.client.Events():
			if !ok {
				return
			}
			c.dispatch(ev)
		}
	}
}

func (c *Collector) dispatch(ev Event) {
	switch ev.Type {
	case EventExec:
		select {
		case c.exec <- ev:
		default:
			c.logger.Debug("esf exec channel full, dropping event", "pid", ev.PID)
		}
	case EventExit:
		select {
		case c.exit <- ev:
		default:
			c.logger.Debug("esf exit channel full, dropping event", "pid", ev.PID)
		}
	case EventOpen:
		select {
		case c.open <- ev:
		default:
			c.logger.Debug("esf open channel full, dropping event", "path", ev.FilePath)
		}
	case EventLookup:
		select {
		case c.lookup <- ev:
		default:
			c.logger.Debug("esf lookup channel full, dropping event", "domain", ev.Domain)
		}
	}
}
