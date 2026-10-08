package api

import (
	"strings"
	"sync"
	"time"
)

// Login backoff defaults: after maxFailures failed password attempts for an
// e-mail within window, further attempts for that e-mail are refused with 429
// for lockout. State is in-memory and bounded; it resets on restart.
const (
	loginBackoffMaxFailures = 5
	loginBackoffWindow      = 15 * time.Minute
	loginBackoffLockout     = 15 * time.Minute
	loginBackoffMaxEntries  = 10_000
)

type loginAttempts struct {
	failures     int
	firstFailure time.Time
	lockedUntil  time.Time
}

// loginBackoff tracks failed password logins per account.
type loginBackoff struct {
	mu          sync.Mutex
	entries     map[string]*loginAttempts
	maxFailures int
	window      time.Duration
	lockout     time.Duration
	maxEntries  int
	now         func() time.Time
}

func newLoginBackoff() *loginBackoff {
	return &loginBackoff{
		entries:     make(map[string]*loginAttempts),
		maxFailures: loginBackoffMaxFailures,
		window:      loginBackoffWindow,
		lockout:     loginBackoffLockout,
		maxEntries:  loginBackoffMaxEntries,
		now:         func() time.Time { return time.Now().UTC() },
	}
}

func normalizeLoginKey(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// Blocked reports whether logins for email are currently refused and, if so,
// for how much longer.
func (b *loginBackoff) Blocked(email string) (bool, time.Duration) {
	if b == nil {
		return false, 0
	}
	key := normalizeLoginKey(email)
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()
	e, ok := b.entries[key]
	if !ok {
		return false, 0
	}
	if now.Before(e.lockedUntil) {
		return true, e.lockedUntil.Sub(now)
	}
	return false, 0
}

// RecordFailure counts a failed attempt for email and starts a lockout once
// the threshold is reached inside the window.
func (b *loginBackoff) RecordFailure(email string) {
	if b == nil {
		return
	}
	key := normalizeLoginKey(email)
	now := b.now()

	b.mu.Lock()
	defer b.mu.Unlock()

	e, ok := b.entries[key]
	if !ok {
		if len(b.entries) >= b.maxEntries {
			b.evictLocked(now)
		}
		e = &loginAttempts{}
		b.entries[key] = e
	}

	// Start a new window if the previous one has elapsed and no lockout is active.
	if e.failures == 0 || (now.Sub(e.firstFailure) > b.window && !now.Before(e.lockedUntil)) {
		e.failures = 0
		e.firstFailure = now
		e.lockedUntil = time.Time{}
	}
	e.failures++
	if e.failures >= b.maxFailures {
		e.lockedUntil = now.Add(b.lockout)
	}
}

// Reset clears the state for email after a successful login.
func (b *loginBackoff) Reset(email string) {
	if b == nil {
		return
	}
	key := normalizeLoginKey(email)
	b.mu.Lock()
	delete(b.entries, key)
	b.mu.Unlock()
}

// evictLocked removes entries whose window and lockout have both elapsed and,
// if the map is still full, the single oldest entry. Caller holds mu.
func (b *loginBackoff) evictLocked(now time.Time) {
	for k, e := range b.entries {
		if now.Sub(e.firstFailure) > b.window && !now.Before(e.lockedUntil) {
			delete(b.entries, k)
		}
	}
	if len(b.entries) < b.maxEntries {
		return
	}
	var oldestKey string
	var oldest time.Time
	for k, e := range b.entries {
		if oldestKey == "" || e.firstFailure.Before(oldest) {
			oldestKey, oldest = k, e.firstFailure
		}
	}
	if oldestKey != "" {
		delete(b.entries, oldestKey)
	}
}
