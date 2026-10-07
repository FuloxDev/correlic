package dispatch

import (
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	DefaultExecRateLimit  = 200 // per second
	DefaultNetAcceptLimit = 100 // per second
	DefaultExitRateLimit  = 100 // per second - exit events are high volume, low value
)

// Env: AGENT_EXEC_RATE_LIMIT (default 200), AGENT_NET_ACCEPT_RATE_LIMIT (default 100),
// AGENT_EXIT_RATE_LIMIT (default 100). 0 = unlimited for that type.

// RateLimiter allows callers to check if an event type is within rate limit.
// When limit is exceeded, Allow returns false and the caller should drop the event.
type RateLimiter interface {
	Allow(eventType string) bool
}

// tokenBucket implements a simple token bucket per event type.
type tokenBucket struct {
	capacity  int
	refill    int
	refillDur time.Duration
	tokens    float64
	last      time.Time
	mu        sync.Mutex
}

func (tb *tokenBucket) allow() bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(tb.last).Seconds()
	tb.last = now
	tb.tokens += elapsed * float64(tb.refill) / tb.refillDur.Seconds()
	if tb.tokens > float64(tb.capacity) {
		tb.tokens = float64(tb.capacity)
	}
	if tb.tokens >= 1 {
		tb.tokens--
		return true
	}
	return false
}

// perTypeLimiter holds a bucket per event type and optional global default.
type perTypeLimiter struct {
	buckets       map[string]*tokenBucket
	defaultBucket *tokenBucket
	mu            sync.Mutex
}

// NewPerTypeRateLimiter returns a RateLimiter that applies per-type limits.
// Limits: process_exec = execPerSec, net_accept = netAcceptPerSec, process_exit = exitPerSec; others unlimited if defaultPerSec <= 0.
func NewPerTypeRateLimiter(execPerSec, netAcceptPerSec, exitPerSec, defaultPerSec int) RateLimiter {
	p := &perTypeLimiter{
		buckets: make(map[string]*tokenBucket),
	}
	if execPerSec > 0 {
		p.buckets["process_exec"] = &tokenBucket{
			capacity:  execPerSec,
			refill:    execPerSec,
			refillDur: time.Second,
			tokens:    float64(execPerSec),
			last:      time.Now(),
		}
	}
	if netAcceptPerSec > 0 {
		p.buckets["net_accept"] = &tokenBucket{
			capacity:  netAcceptPerSec,
			refill:    netAcceptPerSec,
			refillDur: time.Second,
			tokens:    float64(netAcceptPerSec),
			last:      time.Now(),
		}
	}
	if exitPerSec > 0 {
		p.buckets["process_exit"] = &tokenBucket{
			capacity:  exitPerSec,
			refill:    exitPerSec,
			refillDur: time.Second,
			tokens:    float64(exitPerSec),
			last:      time.Now(),
		}
	}
	if defaultPerSec > 0 {
		p.defaultBucket = &tokenBucket{
			capacity:  defaultPerSec,
			refill:    defaultPerSec,
			refillDur: time.Second,
			tokens:    float64(defaultPerSec),
			last:      time.Now(),
		}
	}
	return p
}

// RateLimiterFromEnv returns a RateLimiter using env vars for limits.
// AGENT_EXEC_RATE_LIMIT, AGENT_NET_ACCEPT_RATE_LIMIT, AGENT_EXIT_RATE_LIMIT.
// 0 = disabled (unlimited) for that type.
func RateLimiterFromEnv() RateLimiter {
	exec := DefaultExecRateLimit
	if s := os.Getenv("AGENT_EXEC_RATE_LIMIT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			exec = n
		}
	}
	netAccept := DefaultNetAcceptLimit
	if s := os.Getenv("AGENT_NET_ACCEPT_RATE_LIMIT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			netAccept = n
		}
	}
	exitRate := DefaultExitRateLimit
	if s := os.Getenv("AGENT_EXIT_RATE_LIMIT"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			exitRate = n
		}
	}
	return NewPerTypeRateLimiter(exec, netAccept, exitRate, 0)
}

func (p *perTypeLimiter) Allow(eventType string) bool {
	p.mu.Lock()
	b := p.buckets[eventType]
	if b == nil {
		b = p.defaultBucket
	}
	p.mu.Unlock()
	if b == nil {
		return true
	}
	return b.allow()
}
