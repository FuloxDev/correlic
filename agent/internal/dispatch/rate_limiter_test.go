package dispatch

import (
	"testing"
	"time"
)

func TestPerTypeRateLimiter_Allow(t *testing.T) {
	// 2 per second for process_exec
	limiter := NewPerTypeRateLimiter(2, 0, 0, 0)
	for i := 0; i < 2; i++ {
		if !limiter.Allow("process_exec") {
			t.Errorf("Allow #%d: expected true", i+1)
		}
	}
	if limiter.Allow("process_exec") {
		t.Error("third Allow within same second: expected false")
	}
	// Other types unlimited
	if !limiter.Allow("net_connect") {
		t.Error("other type should be allowed")
	}
	// After refill
	time.Sleep(1100 * time.Millisecond)
	if !limiter.Allow("process_exec") {
		t.Error("after 1s refill: expected true")
	}
}

func TestPerTypeRateLimiter_NetAccept(t *testing.T) {
	limiter := NewPerTypeRateLimiter(0, 1, 0, 0)
	if !limiter.Allow("net_accept") {
		t.Error("first net_accept should be allowed")
	}
	if limiter.Allow("net_accept") {
		t.Error("second net_accept should be rate limited")
	}
}
