package eslogger

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/correlic/correlic-agent/internal/darwin/esevents"
)

// Binary is the eslogger executable. It is a variable so tests can point it
// at a fake script.
var Binary = "/usr/bin/eslogger"

// DefaultEvents are the eslogger event names the agent subscribes to. "open"
// is the high-volume one and is only requested when file monitoring is on.
var DefaultEvents = []string{"exec", "exit", "fork", "open"}

// Collector runs eslogger as a child process, parses its stdout into events
// and supervises it: an exit right after start is reported as a typed error
// so the caller can fall back to polling, a later exit is restarted with
// backoff until the restart budget is spent, and cancelling the context
// stops the process (SIGTERM, then SIGKILL).
//
// eslogger is deliberately kept in the agent's own process group: Endpoint
// Security mutes events from eslogger's process group, so this mutes the
// agent's own activity the way es_mute_process does for the native client.
// The agent's and eslogger's PIDs are filtered as well.
type Collector struct {
	logger *slog.Logger
	names  []string

	// Tunables, set before Start.

	// StartupGrace is how long eslogger must survive before its start counts
	// as successful; an exit before that is a startup failure.
	StartupGrace time.Duration
	// TermGrace is how long to wait after SIGTERM before SIGKILL.
	TermGrace time.Duration
	// RestartBackoff is the first delay before a restart; it doubles per
	// consecutive restart up to MaxBackoff.
	RestartBackoff time.Duration
	MaxBackoff     time.Duration
	// MaxRestartsPerMinute caps restarts in a sliding minute; one more
	// failure makes the collector give up and close Events.
	MaxRestartsPerMinute int
	// ChannelSize buffers parsed events for the consumer; events are dropped
	// (and counted) when it is full.
	ChannelSize int
	// MaxLineBytes is the longest stdout line that is parsed; longer lines
	// are skipped and counted.
	MaxLineBytes int

	events  chan esevents.Event
	stopped chan struct{}
	selfPID uint32

	parsed      atomic.Uint64
	dropped     atomic.Uint64
	parseErrors atomic.Uint64
	oversized   atomic.Uint64
	restarts    atomic.Uint64
	lastDropLog atomic.Int64

	startOnce sync.Once
	started   bool
}

// New creates a collector for the given eslogger event names (nil means
// DefaultEvents).
func New(logger *slog.Logger, eventNames []string) *Collector {
	if logger == nil {
		logger = slog.Default()
	}
	if len(eventNames) == 0 {
		eventNames = DefaultEvents
	}
	c := &Collector{
		logger:               logger,
		names:                append([]string(nil), eventNames...),
		StartupGrace:         2 * time.Second,
		TermGrace:            2 * time.Second,
		RestartBackoff:       time.Second,
		MaxBackoff:           30 * time.Second,
		MaxRestartsPerMinute: 5,
		ChannelSize:          8192,
		MaxLineBytes:         4 << 20,
		stopped:              make(chan struct{}),
		selfPID:              uint32(os.Getpid()),
	}
	return c
}

// Events returns the parsed events (esevents.EventSource). The channel is
// closed when the collector stops: context cancelled, startup failed, or the
// restart budget was exhausted.
func (c *Collector) Events() <-chan esevents.Event {
	c.startOnce.Do(c.initChannel)
	return c.events
}

func (c *Collector) initChannel() {
	c.events = make(chan esevents.Event, c.ChannelSize)
}

// Wait blocks until the supervisor has stopped and the process is gone. It
// returns immediately when Start returned an error.
func (c *Collector) Wait() { <-c.stopped }

// Parsed, Dropped, ParseErrors, Oversized and Restarts expose counters for
// logs and tests.
func (c *Collector) Parsed() uint64      { return c.parsed.Load() }
func (c *Collector) Dropped() uint64     { return c.dropped.Load() }
func (c *Collector) ParseErrors() uint64 { return c.parseErrors.Load() }
func (c *Collector) Oversized() uint64   { return c.oversized.Load() }
func (c *Collector) Restarts() uint64    { return c.restarts.Load() }

// Start launches eslogger and waits StartupGrace to see whether it stays up.
// It returns ErrNotFound, ErrNotPermitted, ErrNotRoot or ErrStartup when the
// process could not be started or exited within the grace period, with the
// exit status and eslogger's stderr in the message. On success the
// supervisor keeps running in the background until ctx is cancelled.
func (c *Collector) Start(ctx context.Context) error {
	c.startOnce.Do(c.initChannel)
	if c.started {
		return errors.New("eslogger: collector already started")
	}
	c.started = true

	p, err := c.launch()
	if err != nil {
		c.finish()
		return err
	}

	select {
	case res := <-p.done:
		c.finish()
		return c.startupError(p, res)
	case <-ctx.Done():
		c.terminate(p)
		c.finish()
		return ctx.Err()
	case <-time.After(c.StartupGrace):
	}

	c.logger.Info("eslogger running", "pid", p.cmd.Process.Pid, "binary", Binary, "events", c.names)
	go c.supervise(ctx, p)
	return nil
}

// finish closes the output channel and releases Wait. It must only run once
// no reader goroutine can still send, i.e. after the process's done signal.
func (c *Collector) finish() {
	close(c.events)
	close(c.stopped)
}

// proc is one eslogger process and its pipe readers.
type proc struct {
	cmd     *exec.Cmd
	started time.Time
	done    chan exitResult // receives exactly one value after exit and reader shutdown
	stderr  *tail
}

type exitResult struct {
	err  error
	code int
}

// launch starts eslogger with the configured event names and wires the
// stdout/stderr readers. It returns a typed error when the binary cannot be
// started at all.
func (c *Collector) launch() (*proc, error) {
	cmd := exec.Command(Binary, c.names...)
	// No exec.CommandContext and no Setpgid: shutdown is handled by
	// terminate, and a separate process group would stop Endpoint Security
	// from muting the agent (see the type comment).
	cmd.Stdin = nil

	rOut, wOut, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("%w: stdout pipe: %v", ErrStartup, err)
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		rOut.Close()
		wOut.Close()
		return nil, fmt.Errorf("%w: stderr pipe: %v", ErrStartup, err)
	}
	cmd.Stdout = wOut
	cmd.Stderr = wErr

	if err := cmd.Start(); err != nil {
		rOut.Close()
		wOut.Close()
		rErr.Close()
		wErr.Close()
		if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s: %v", ErrNotFound, Binary, err)
		}
		return nil, fmt.Errorf("%w: start %s: %v", ErrStartup, Binary, err)
	}
	// The child holds the write ends now.
	wOut.Close()
	wErr.Close()

	p := &proc{
		cmd:     cmd,
		started: time.Now(),
		done:    make(chan exitResult, 1),
		stderr:  &tail{},
	}
	esPID := uint32(cmd.Process.Pid)

	var readers sync.WaitGroup
	readers.Add(2)
	go func() {
		defer readers.Done()
		c.readStdout(rOut, esPID)
	}()
	go func() {
		defer readers.Done()
		c.readStderr(rErr, p.stderr)
	}()

	go func() {
		werr := cmd.Wait()
		// The readers see EOF once every holder of the write ends is gone.
		// A grandchild that inherited the pipes could keep them open, so
		// unblock the readers after a short grace rather than hang.
		readersDone := make(chan struct{})
		go func() {
			readers.Wait()
			close(readersDone)
		}()
		select {
		case <-readersDone:
		case <-time.After(time.Second):
			rOut.Close()
			rErr.Close()
			<-readersDone
		}
		rOut.Close()
		rErr.Close()
		code := -1
		var ee *exec.ExitError
		if werr == nil {
			code = 0
		} else if errors.As(werr, &ee) {
			code = ee.ExitCode()
		}
		p.done <- exitResult{err: werr, code: code}
	}()
	return p, nil
}

// readStdout parses stdout line by line. Lines longer than MaxLineBytes are
// skipped (eslogger prints a process's whole environment on exec, so lines
// of hundreds of KiB are normal; a 4 MiB line is not).
func (c *Collector) readStdout(r io.Reader, esPID uint32) {
	br := bufio.NewReaderSize(r, 256<<10)
	var acc []byte
	tooLong := false
	for {
		frag, isPrefix, err := br.ReadLine()
		if err != nil {
			return
		}
		if !tooLong {
			if len(acc)+len(frag) > c.MaxLineBytes {
				tooLong = true
				acc = acc[:0]
			} else {
				acc = append(acc, frag...)
			}
		}
		if isPrefix {
			continue
		}
		if tooLong {
			n := c.oversized.Add(1)
			if n == 1 || n%100 == 0 {
				c.logger.Warn("eslogger line exceeded the size limit; skipped", "max_bytes", c.MaxLineBytes, "skipped_total", n)
			}
		} else if len(acc) > 0 {
			c.handleLine(acc, esPID)
		}
		acc = acc[:0]
		tooLong = false
	}
}

func (c *Collector) handleLine(line []byte, esPID uint32) {
	ev, ok, err := Parse(line)
	if err != nil {
		n := c.parseErrors.Add(1)
		if n == 1 {
			c.logger.Warn("eslogger printed a line the agent cannot parse (output format changed?)", "error", err, "line", truncate(line, 200))
		} else {
			c.logger.Debug("eslogger parse error", "error", err, "line", truncate(line, 200))
		}
		return
	}
	if !ok {
		return
	}
	if ev.PID == c.selfPID || ev.PID == esPID {
		return
	}
	c.parsed.Add(1)
	select {
	case c.events <- ev:
	default:
		n := c.dropped.Add(1)
		now := time.Now().UnixNano()
		if last := c.lastDropLog.Load(); now-last > int64(time.Minute) && c.lastDropLog.CompareAndSwap(last, now) {
			c.logger.Warn("event channel full; dropping eslogger events", "dropped_total", n)
		}
	}
}

// readStderr logs eslogger's stderr and keeps the last lines for error
// classification.
func (c *Collector) readStderr(r io.Reader, t *tail) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	lines := 0
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		t.add(line)
		lines++
		if lines <= 20 {
			c.logger.Warn("eslogger stderr", "line", line)
		} else {
			c.logger.Debug("eslogger stderr", "line", line)
		}
	}
}

// startupError classifies an exit during the grace period from the exit
// status and stderr. The markers come from the ES_NEW_CLIENT_RESULT_ERR_*
// names Endpoint Security reports; the exact wording eslogger prints is not
// documented, so plain-English phrases are matched too.
func (c *Collector) startupError(p *proc, res exitResult) error {
	text := p.stderr.String()
	lower := strings.ToLower(text)
	base := ErrStartup
	switch {
	case containsAny(lower, "not_permitted", "not permitted", "full disk access", "tcc"):
		base = ErrNotPermitted
	case containsAny(lower, "not_privileged", "not privileged", "superuser", "as root", "requires root", "must be root"):
		base = ErrNotRoot
	}
	if text == "" {
		text = "(no stderr)"
	}
	return fmt.Errorf("%w: exit status %d after %s: %s", base, res.code, time.Since(p.started).Round(time.Millisecond), text)
}

// supervise restarts eslogger when it dies and stops it when ctx ends.
func (c *Collector) supervise(ctx context.Context, p *proc) {
	defer c.finish()

	var restartTimes []time.Time
	backoff := c.RestartBackoff
	for {
		select {
		case <-ctx.Done():
			c.terminate(p)
			c.logger.Info("eslogger stopped", "parsed", c.Parsed(), "dropped", c.Dropped(),
				"parse_errors", c.ParseErrors(), "oversized", c.Oversized(), "restarts", c.Restarts())
			return

		case res := <-p.done:
			ran := time.Since(p.started)
			c.logger.Warn("eslogger exited", "error", res.err, "exit_status", res.code,
				"ran", ran.Round(time.Millisecond), "stderr", p.stderr.String())
			if ran > time.Minute {
				backoff = c.RestartBackoff
			}

			now := time.Now()
			restartTimes = pruneBefore(restartTimes, now.Add(-time.Minute))
			if len(restartTimes) >= c.MaxRestartsPerMinute {
				c.logger.Error("eslogger restarted too often; giving up. Process and file events stop until the agent is restarted",
					"restarts_last_minute", len(restartTimes), "error", ErrGaveUp, "remediation", Remediation)
				return
			}
			restartTimes = append(restartTimes, now)
			c.restarts.Add(1)

			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			if backoff *= 2; backoff > c.MaxBackoff {
				backoff = c.MaxBackoff
			}

			np, err := c.launch()
			if err != nil {
				c.logger.Error("eslogger restart failed", "error", err)
				// Count it as another immediate death.
				np = &proc{started: time.Now(), done: make(chan exitResult, 1), stderr: &tail{}}
				np.done <- exitResult{err: err, code: -1}
			} else {
				c.logger.Info("eslogger restarted", "pid", np.cmd.Process.Pid, "restarts", c.Restarts())
			}
			p = np
		}
	}
}

// terminate stops the process: SIGTERM, then SIGKILL after TermGrace, and
// waits for the readers to drain.
func (c *Collector) terminate(p *proc) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return
	}
	select {
	case res := <-p.done:
		p.done <- res // keep it observable for the caller
		return
	default:
	}
	// Signal is unsupported on Windows; Kill below covers it.
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.done:
		return
	case <-time.After(c.TermGrace):
	}
	c.logger.Warn("eslogger did not exit after SIGTERM; killing it", "pid", p.cmd.Process.Pid)
	_ = p.cmd.Process.Kill()
	<-p.done
}

// tail keeps the last few stderr lines.
type tail struct {
	mu    sync.Mutex
	lines []string
}

const tailLines = 8

func (t *tail) add(line string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lines = append(t.lines, line)
	if len(t.lines) > tailLines {
		t.lines = t.lines[len(t.lines)-tailLines:]
	}
}

func (t *tail) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.Join(t.lines, " | ")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

func pruneBefore(ts []time.Time, cutoff time.Time) []time.Time {
	kept := ts[:0]
	for _, t := range ts {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	return kept
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
