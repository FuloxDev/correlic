package heartbeat

import (
	"context"
	"os"
	"runtime"
	"time"

	"log/slog"

	"github.com/correlic/correlic-agent/internal/model"
	"github.com/correlic/correlic-agent/internal/transport"
)

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

// Start starts the heartbeat runner.
func (r *Runner) Start(ctx context.Context) {
	r.State = model.StateStarting
	slog.Info("heartbeat runner starting", "state", r.State)

	// create a new ticker for the heartbeat interval.
	ticker := time.NewTicker(r.Interval)

	// defer stopping the ticker.
	defer ticker.Stop()

	// get the hostname.
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	firstHeartbeat := true

	// loop until the context is done.
	for {
		select {
		// if the context is done, shutdown the runner.
		case <-ctx.Done():
			r.shutdown(ctx, hostname)
			return

		// if the ticker fires, send a heartbeat.
		case <-ticker.C:
			hb := model.Heartbeat{
				AgentID:   r.AgentID,
				Hostname:  hostname,
				OS:        runtime.GOOS,
				Version:   r.Version,
				Profile:   r.Profile,
				State:     r.State,
				Timestamp: time.Now().UTC(),
			}

			// send the heartbeat with retry.
			if err := r.sendWithRetry(ctx, hb); err != nil {
				slog.Warn("heartbeat failed after retry", "error", err)
				if r.Emit != nil {
					_ = r.Emit("heartbeat_error", map[string]any{
						"error": err.Error(),
						"state": r.State,
					})
				}
				continue
			}

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
		_ = r.Transport.SendHeartbeat(shutdownCtx, model.Heartbeat{
			AgentID:   r.AgentID,
			Hostname:  hostname,
			OS:        runtime.GOOS,
			Version:   r.Version,
			Profile:   r.Profile,
			State:     r.State,
			Timestamp: time.Now().UTC(),
		})

		// set the state to stopped.
		r.State = model.StateStopped
		slog.Info("agent stopped", "state", r.State)
		_ = r.Transport.SendHeartbeat(shutdownCtx, model.Heartbeat{
			AgentID:   r.AgentID,
			Hostname:  hostname,
			OS:        runtime.GOOS,
			Version:   r.Version,
			Profile:   r.Profile,
			State:     r.State,
			Timestamp: time.Now().UTC(),
		})
	default:
		// If we are still "starting", the server contract does not allow starting -> stopping.
		// Safer to exit without sending an invalid transition.
		slog.Info("shutdown before running; skipping stop heartbeats", "state", r.State)
	}
}

// sendWithRetry sends a heartbeat with retry.
func (r *Runner) sendWithRetry(
	ctx context.Context,
	hb model.Heartbeat,
) error {
	// First attempt
	if err := r.Transport.SendHeartbeat(ctx, hb); err == nil {
		slog.Debug("heartbeat sent")
		return nil
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
