package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-agent/internal/collect"
	"github.com/correlic/correlic-agent/internal/config"
	"github.com/correlic/correlic-agent/internal/dispatch"
	"github.com/correlic/correlic-agent/internal/enforcer"
)

// version is the agent version reported in heartbeats. Overridable at build
// time with -ldflags "-X main.version=1.2.3".
var version = "1.0.1"

// agentRuntime tracks the long-running goroutines started by runAgent so
// shutdown can wait for them (bounded) instead of sleeping a fixed time.
type agentRuntime struct {
	wg     sync.WaitGroup
	logger *slog.Logger
}

func newAgentRuntime(logger *slog.Logger) *agentRuntime {
	return &agentRuntime{logger: logger}
}

// spawn starts fn in a goroutine tracked by wait.
func (a *agentRuntime) spawn(name string, fn func()) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		defer func() {
			if r := recover(); r != nil {
				a.logger.Error("component panicked", "component", name, "panic", r)
			}
		}()
		fn()
	}()
}

// wait blocks until every spawned goroutine has returned or timeout elapses.
// Returns false on timeout.
func (a *agentRuntime) wait(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		a.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(timeout):
		return false
	}
}

// platformDeps is what the per-platform collector wiring needs.
type platformDeps struct {
	cfg    config.Config
	logger *slog.Logger
	hostID string
	emit   collect.EventSink
	disp   dispatch.Dispatcher
	// enf is the soft-block enforcer, nil when block_enabled is false or the
	// emergency bypass is set.
	enf *enforcer.Enforcer
	// patternsReady is closed once the initial AI pattern fetch completed;
	// startup scans wait on it so they see the freshest pattern list.
	patternsReady <-chan struct{}
	rt            *agentRuntime
}

// waitPatterns blocks until the pattern list is ready or ctx is done.
func (d platformDeps) waitPatterns(ctx context.Context) {
	if d.patternsReady == nil {
		return
	}
	select {
	case <-d.patternsReady:
	case <-ctx.Done():
	}
}

// startEnforcer builds the soft-block enforcer and starts its rule sync loop
// when block_enabled is set. Returns nil when blocking is off.
func startEnforcer(ctx context.Context, cfg config.Config, rulesURL string, logger *slog.Logger, rt *agentRuntime) *enforcer.Enforcer {
	if cfg.BlockEmergencyBypass {
		logger.Warn("soft-block EMERGENCY BYPASS active — all blocking disabled")
		return nil
	}
	if !cfg.BlockEnabled {
		return nil
	}

	enf := enforcer.New(logger, true)
	// Protect the agent's own PID
	enf.AddProtectedPID(uint32(os.Getpid()))

	syncTLS, err := enforcerTLSConfig(cfg)
	if err != nil {
		logger.Error("failed to load TLS material for block rule sync; using system roots", "error", err)
		syncTLS = nil
	}

	interval := cfg.BlockSyncInterval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	ruleSync := enforcer.NewRuleSync(enf, rulesURL, cfg.APIKey, interval, logger, syncTLS)
	rt.spawn("block_rule_sync", func() { ruleSync.Start(ctx) })
	logger.Info("soft-block enforcer enabled", "sync_interval", interval, "rules_url", rulesURL+"/agent/block-rules")
	return enf
}

// enforcerTLSConfig builds the client TLS config (CA + optional mTLS cert)
// for the block rule sync from the agent config.
func enforcerTLSConfig(cfg config.Config) (*tls.Config, error) {
	if cfg.TLSClientCertFile == "" && cfg.TLSCAFile == "" {
		return nil, nil
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.TLSClientCertFile != "" && cfg.TLSClientKeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSClientCertFile, cfg.TLSClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	if cfg.TLSCAFile != "" {
		pem, err := os.ReadFile(cfg.TLSCAFile)
		if err != nil {
			return nil, fmt.Errorf("read tls_ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tls_ca_file contains no certificates")
		}
		tlsCfg.RootCAs = pool
	}
	return tlsCfg, nil
}

// extractConfigFlag removes --config/-config (with "=value" or a following
// argument) from args and returns the path and the remaining arguments.
func extractConfigFlag(args []string) (string, []string, error) {
	var path string
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--config" || a == "-config":
			if i+1 >= len(args) {
				return "", nil, fmt.Errorf("%s requires a path", a)
			}
			path = args[i+1]
			i++
		case strings.HasPrefix(a, "--config=") || strings.HasPrefix(a, "-config="):
			path = a[strings.Index(a, "=")+1:]
			if path == "" {
				return "", nil, fmt.Errorf("%s requires a path", a[:strings.Index(a, "=")])
			}
		default:
			rest = append(rest, a)
		}
	}
	return path, rest, nil
}
