//go:build windows

package main

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
)

// corService implements svc.Handler for running the agent as a Windows Service.
type corService struct {
	logger *slog.Logger
}

// Execute is called by the Windows service manager.
func (s *corService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	changes <- svc.Status{State: svc.StartPending}

	// Run the agent in a background goroutine.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})

	go func() {
		defer close(done)
		if err := runAgent(ctx, s.logger); err != nil {
			s.logger.Error("agent startup failed", "error", err)
			// Write to file since service has no console
			if exe, err2 := os.Executable(); err2 == nil {
				errLog := filepath.Join(filepath.Dir(exe), "..", "logs", "agent-error.log")
				os.WriteFile(errLog, []byte(err.Error()+"\n"), 0644)
			}
			return
		}
		// runAgent starts goroutines and returns — keep alive until context cancelled.
		<-ctx.Done()
	}()

	changes <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	// Wait for service control commands.
	for {
		select {
		case req := <-r:
			switch req.Cmd {
			case svc.Interrogate:
				changes <- req.CurrentStatus
			case svc.Stop, svc.Shutdown:
				changes <- svc.Status{State: svc.StopPending}
				s.logger.Info("service stop requested, draining (10s deadline)...")
				cancel()

				// Wait for agent to finish or timeout.
				select {
				case <-done:
				case <-time.After(10 * time.Second):
					s.logger.Warn("drain timeout exceeded, forcing stop")
				}

				changes <- svc.Status{State: svc.Stopped}
				return false, 0
			}
		case <-done:
			// Agent exited on its own (shouldn't happen in normal operation).
			changes <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
}

// runAsService starts the agent as a Windows service if running under the service manager.
// If not running as a service, returns immediately and main() continues in interactive mode.
func runAsService(logger *slog.Logger) {
	isService, err := svc.IsWindowsService()
	if err != nil {
		logger.Error("failed to detect service mode", "error", err)
		os.Exit(1)
	}

	if !isService {
		// Not a service — fall through to normal interactive mode.
		return
	}

	// Running as Windows service — set up file-based logging since there's no console.
	exePath, _ := os.Executable()
	logDir := filepath.Join(filepath.Dir(exePath), "..", "logs")
	os.MkdirAll(logDir, 0755)
	logFile, err := os.OpenFile(filepath.Join(logDir, "agent.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		handler := slog.NewTextHandler(logFile, &slog.HandlerOptions{Level: slog.LevelDebug})
		logger = slog.New(handler)
		// Set as default so all packages (batcher, dispatch, etc.) also log to file
		slog.SetDefault(logger)
	}

	logger.Info("starting as Windows service", "name", "CorrelicAgent")

	err = svc.Run("CorrelicAgent", &corService{logger: logger})
	if err != nil {
		logger.Error("service run failed", "error", err)
		os.Exit(1)
	}

	os.Exit(0)
}
