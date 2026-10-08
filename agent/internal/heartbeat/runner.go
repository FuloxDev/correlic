package heartbeat

import (
	"context"
	"os"
	"runtime"
	"time"

	"log/slog"

	"github.com/correlic/correlic-agent/internal/health"
	"github.com/correlic/correlic-agent/internal/model"
	"github.com/correlic/correlic-agent/internal/transport"
)

const heartbeatComponent = "heartbeat"

// Runner is the heartbeat runner.
type Runner struct {
	AgentID   string
	Profile   string
	Interval  time.Duration
	Version   string
	State     model.AgentState
	Transport transport.Transport
	// Emit is an optional telemetry hook (best-effort, never required).
	Emit func(eventType string, payload any) bool
}

// Start starts the heartbeat runner. The first heartbeat is sent immediately
// (the backend binds the mTLS certificate to the agent id on it), then every
// Interval until ctx is done, when stopping/stopped heartbeats are sent.
func (r *Runner) Start(ctx context.Context) {
	r.State = model.StateStarting
	slog.Info("heartbeat runner starting", "state", r.State, "interval", r.Interval)

	if r.Interval <= 0 {
		r.Interval = 30 * time.Second
	}

	// get the hostname.
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// First heartbeat right away, then on the ticker.
	first := make(chan struct{}, 1)
	first <- struct{}{}

	// create a new ticker for the heartbeat interval.
	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	firstHeartbeat := true

	// loop until the context is done.
	for {
		select {
		// if the context is done, shutdown the runner.
		case <-ctx.Done():
			r.shutdown(ctx, hostname)
			return

		case <-first:
		case <-ticker.C:
		}

		hb := r.heartbeat(hostname)

		// send the heartbeat with retry.
		if err := r.sendWithRetry(ctx, hb); err != nil {
			if ctx.Err() != nil {
				continue
			}
			if transport.IsAuthError(err) {
				health.ReportAuthRejected(heartbeatComponent, transport.StatusOf(err), err)
			} else {
				health.ReportFailure(heartbeatComponent, transport.StatusOf(err), err, 0)
			}
			if r.Emit != nil {
				_ = r.Emit("heartbeat_error", map[string]any{
					"error": err.Error(),
					"state": r.State,
				})
			}
			continue
		}
		health.ReportOK(heartbeatComponent)

		// Transition ONLY after first successful starting heartbeat
		if firstHeartbeat && r.State == model.StateStarting {
			r.State = model.StateRunning
			firstHeartbeat = false
			slog.Info("agent entered running state", "state", r.State)
			if r.Emit != nil {
				_ = r.Emit("agent_state", map[string]any{
					"state": r.State,
				})
			}
		}
	}
}

func (r *Runner) heartbeat(hostname string) model.Heartbeat {
	return model.Heartbeat{
		AgentID:   r.AgentID,
		Hostname:  hostname,
		OS:        runtime.GOOS,
		Version:   r.Version,
		Profile:   r.Profile,
		State:     r.State,
		Timestamp: time.Now().UTC(),
	}
}

// shutdown shuts down the heartbeat runner.
func (r *Runner) shutdown(ctx context.Context, hostname string) {
	// Allow a best-effort shutdown heartbeat even after cancellation.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()

	switch r.State {
	case model.StateRunning:
		// running -> stopping -> stopped (valid server-side transitions)
		r.State = model.StateStopping
		slog.Info("heartbeat runner stopping", "state", r.State)
		_ = r.Transport.SendHeartbeat(shutdownCtx, r.heartbeat(hostname))

		// set the state to stopped.
		r.State = model.StateStopped
		slog.Info("agent stopped", "state", r.State)
		_ = r.Transport.SendHeartbeat(shutdownCtx, r.heartbeat(hostname))
	default:
		// If we are still "starting", the server contract does not allow starting -> stopping.
		// Safer to exit without sending an invalid transition.
		slog.Info("shutdown before running; skipping stop heartbeats", "state", r.State)
	}
}

// sendWithRetry sends a heartbeat with retry. Auth rejections are not retried.
func (r *Runner) sendWithRetry(
	ctx context.Context,
	hb model.Heartbeat,
) error {
	// First attempt
	err := r.Transport.SendHeartbeat(ctx, hb)
	if err == nil {
		slog.Debug("heartbeat sent")
		return nil
	}
	if transport.IsAuthError(err) || transport.IsPermanent(err) {
		return err
	}

	// Bounded backoff retry
	// select on the time after 2 seconds or the context done channel.
	select {
	case <-time.After(2 * time.Second):
		return r.Transport.SendHeartbeat(ctx, hb)
	case <-ctx.Done():
		return ctx.Err()
	}
}
