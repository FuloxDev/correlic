package middleware

import (
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// rateBucket is a bucket of tokens that can be used to limit the rate of requests
type rateBucket struct {
	tokens      int
	windowStart time.Time
	lastSeen    time.Time
}

// RateLimiter is a rate limiter that limits the rate of requests to the API
type RateLimiter struct {
	mu           sync.Mutex
	buckets      map[string]*rateBucket
	limit        int
	window       time.Duration
	maxBuckets   int
	cleanupEvery time.Duration
	lastCleanup  time.Time
	// trustProxyHeaders enables X-Forwarded-For for client IP resolution on
	// unauthenticated routes. See TRUST_PROXY_HEADERS below.
	trustProxyHeaders bool
}

// NewRateLimiter creates a new rate limiter.
//
// TRUST_PROXY_HEADERS: when set to "true", the client IP used to key
// unauthenticated routes (see WrapUnauthenticated) is taken from the first
// hop of the X-Forwarded-For header. Only enable this when every request
// reaches the backend through a trusted reverse proxy that sets the header
// from the real peer address; otherwise clients can forge it and evade the
// limit. When unset (the default) the TCP peer address (RemoteAddr) is used.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:           make(map[string]*rateBucket),
		limit:             limit,
		window:            window,
		maxBuckets:        10_000,
		cleanupEvery:      window,
		trustProxyHeaders: strings.EqualFold(strings.TrimSpace(os.Getenv("TRUST_PROXY_HEADERS")), "true"),
	}
}

// Wrap rate-limits authenticated routes, keyed by the presented credential
// (hashed API key or hashed mTLS fingerprint). Requests with no credential at
// all are rejected before reaching the auth middleware.
func (rl *RateLimiter) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Disabled (dev mode): allow all requests through.
		if rl == nil || rl.limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Prefer API key for rate limiting; fall back to mTLS fingerprint if present.
		key := ""
		if apiKey, ok := extractAPIKeyFromAuthorizationHeader(r.Header.Get("Authorization")); ok {
			// Never keep raw keys in memory; hash for rate-limiter indexing.
			key = "cred:" + hashAPIKey(apiKey)
		} else if fp, ok := clientCertFingerprintFromRequest(r); ok {
			// Hash fingerprint as well; keep key format consistent.
			key = "cred:" + hashAPIKey(fp)
		}
		if key == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if !rl.allow(key) {
			log.Printf("rate_limit key=%s path=%s method=%s", key[:13], r.URL.Path, r.Method)
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// WrapUnauthenticated rate-limits routes that have no credential yet (login,
// OAuth, e-mail verification). The bucket is keyed by client IP only: the
// Authorization header is unverified on these routes and must never be used
// as a key, otherwise an attacker could pick a fresh bucket per request.
func (rl *RateLimiter) WrapUnauthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if rl == nil || rl.limit <= 0 {
			next.ServeHTTP(w, r)
			return
		}

		key := "ip:" + ClientIP(r, rl.trustProxyHeaders)
		if !rl.allow(key) {
			log.Printf("rate_limit ip=%s path=%s method=%s", strings.TrimPrefix(key, "ip:"), r.URL.Path, r.Method)
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ClientIP returns the client address to attribute a request to. With
// trustProxyHeaders the first hop of X-Forwarded-For wins when present and
// parseable; otherwise the host part of RemoteAddr is used.
func ClientIP(r *http.Request, trustProxyHeaders bool) string {
	if trustProxyHeaders {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.Split(xff, ",")[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip.String()
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if ip := net.ParseIP(strings.TrimSpace(host)); ip != nil {
		return ip.String()
	}
	if host == "" {
		return "unknown"
	}
	return host
}

// allow consumes one token from the bucket for key and reports whether the
// request may proceed.
func (rl *RateLimiter) allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()

	// Periodic cleanup to avoid unbounded growth.
	if rl.lastCleanup.IsZero() || now.Sub(rl.lastCleanup) >= rl.cleanupEvery {
		// Buckets that haven't been seen in a while are safe to delete.
		ttl := 2 * rl.window
		for k, b := range rl.buckets {
			if now.Sub(b.lastSeen) > ttl {
				delete(rl.buckets, k)
			}
		}
		// If we still have too many (pathological case), opportunistically trim.
		if rl.maxBuckets > 0 && len(rl.buckets) > rl.maxBuckets {
			extra := len(rl.buckets) - rl.maxBuckets
			for k := range rl.buckets {
				delete(rl.buckets, k)
				extra--
				if extra <= 0 {
					break
				}
			}
		}
		rl.lastCleanup = now
	}

	b, ok := rl.buckets[key]
	if !ok {
		b = &rateBucket{
			tokens:      rl.limit,
			windowStart: now,
			lastSeen:    now,
		}
		rl.buckets[key] = b
	}

	// if the window has expired, reset the bucket
	if now.Sub(b.windowStart) > rl.window {
		b.tokens = rl.limit
		b.windowStart = now
	}
	b.lastSeen = now

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}
