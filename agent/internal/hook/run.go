package hook

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/correlic/correlic-agent/internal/event"
	"github.com/correlic/correlic-agent/internal/transport"
)

// Client is what the runtime needs from the backend (transport.HTTPTransport
// implements it).
type Client interface {
	Sender
	RuleSource
	ReportBlockEvents(ctx context.Context, events []transport.BlockEventReport) error
}

// Default time budget and the per-step slices of it. Hooks run on every tool
// call, so the whole invocation must stay well under a couple of seconds and
// never hold the AI tool up when the backend is slow.
const (
	DefaultBudget      = 2 * time.Second
	rulesFetchTimeout  = 700 * time.Millisecond
	sendTimeout        = 800 * time.Millisecond
	blockReportTimeout = 400 * time.Millisecond
	spoolMinRemaining  = 250 * time.Millisecond
	maxInputBytes      = 1 << 20
)

// Runtime processes one hook invocation.
type Runtime struct {
	Config Config
	Client Client
	HostID string
	Actor  Actor
	Home   string
	Logger *slog.Logger
	Now    func() time.Time
	Budget time.Duration
}

// Result describes what one invocation did (for tests and `test`).
type Result struct {
	Event     *event.Event
	Decision  Decision
	Output    []byte // bytes written to stdout (empty = no decision)
	Delivered bool
	Spooled   bool
	Drained   int
}

// Process reads one hook payload from in, evaluates block rules for blockable
// events, writes the deny document to out when a rule matched, delivers the
// canonical event (spooling it on transient failure), reports a block and
// retries spooled events with whatever budget is left. Every failure is
// logged and swallowed: the hook fails open and the caller exits 0.
func (r *Runtime) Process(parent context.Context, in io.Reader, out io.Writer) (Result, error) {
	if r.Now == nil {
		r.Now = time.Now
	}
	if r.Budget <= 0 {
		r.Budget = DefaultBudget
	}
	if r.Logger == nil {
		r.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	start := r.Now() // event timestamp
	ctx, cancel := context.WithTimeout(parent, r.Budget)
	defer cancel()

	var res Result
	data, err := io.ReadAll(io.LimitReader(in, maxInputBytes))
	if err != nil {
		return res, fmt.Errorf("read stdin: %w", err)
	}
	ev, err := Parse(data)
	if err != nil {
		return res, err
	}
	log := r.Logger.With("tool", ev.Tool, "event", ev.HookEvent, "tool_name", ev.ToolName)

	// 1. Block rules (pre events only).
	if ev.Blockable && r.Config.BlockEnabled {
		rctx, rcancel := context.WithTimeout(ctx, rulesFetchTimeout)
		rules, ok := LoadRules(rctx, r.Client, r.Config.CacheDir, start, log)
		rcancel()
		if ok {
			res.Decision = Evaluate(ev, rules, r.Home)
		}
	}
	if res.Decision.Blocked {
		res.Output = DenyResponse(ev, res.Decision.Reason())
		if _, err := out.Write(res.Output); err != nil {
			log.Warn("write deny response failed", "error", err)
		}
		log.Warn("BLOCKED", "rule_id", res.Decision.RuleID, "signal", res.Decision.SignalType, "candidate", res.Decision.Candidate)
	}

	// 2. The canonical event.
	evt := BuildEvent(ev, r.HostID, r.Actor, start, res.Decision)
	res.Event = &evt
	sctx, scancel := context.WithTimeout(ctx, sendTimeout)
	err = r.Client.SendCanonicalEvents(sctx, []event.Event{evt})
	scancel()
	spool := NewSpool(r.Config.CacheDir, log)
	switch {
	case err == nil:
		res.Delivered = true
	case transport.IsAuthError(err):
		log.Warn("backend rejected the API key; event dropped", "status", transport.StatusOf(err))
	case transport.IsPermanent(err):
		log.Warn("backend rejected the event; dropped", "status", transport.StatusOf(err), "error", err)
	default:
		if serr := spool.Add(evt); serr != nil {
			log.Warn("delivery failed and spooling failed; event lost", "error", err, "spool_error", serr)
		} else {
			res.Spooled = true
			log.Debug("delivery failed; event spooled", "error", err)
		}
	}

	// 3. Block report.
	if res.Decision.Blocked {
		bctx, bcancel := context.WithTimeout(ctx, blockReportTimeout)
		berr := r.Client.ReportBlockEvents(bctx, []transport.BlockEventReport{blockReport(ev, evt, res.Decision, r.Actor, start)})
		bcancel()
		if berr != nil {
			log.Debug("block event report failed", "error", berr)
		}
	}

	// 4. Retry earlier failures with the remaining budget.
	if !res.Spooled {
		if dl, ok := ctx.Deadline(); ok && time.Until(dl) > spoolMinRemaining {
			res.Drained = spool.Drain(ctx, r.Client, start)
			if res.Drained > 0 {
				log.Info("spooled events delivered", "count", res.Drained)
			}
		}
	}
	return res, nil
}

func blockReport(ev *ToolEvent, evt event.Event, d Decision, actor Actor, ts time.Time) transport.BlockEventReport {
	target := d.Candidate
	cmd := ev.Command
	if cmd == "" {
		cmd = ev.FilePath
	}
	return transport.BlockEventReport{
		ID:         evt.ID,
		HostID:     evt.HostID,
		AgentID:    "correlic-hook",
		RuleID:     d.RuleID,
		SignalType: d.SignalType,
		PID:        actor.PID,
		ExePath:    d.Candidate,
		Cmdline:    cmd,
		Target:     target,
		AIType:     ev.Tool,
		Success:    true, // denied before it ran
		LatencyUS:  int(time.Since(ts).Microseconds()),
		BlockedAt:  ts,
	}
}

// NewClient builds the transport from the config (API key + optional mTLS).
func NewClient(cfg Config) (*transport.HTTPTransport, error) {
	t, err := transport.NewHTTPTransportWithTelemetryURLAndTLS(cfg.APIKey, cfg.TelemetryURL, cfg.TelemetryURL,
		cfg.TLSCAFile, cfg.TLSClientCertFile, cfg.TLSClientKeyFile)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return nil, errors.New("transport not created")
	}
	return t, nil
}
