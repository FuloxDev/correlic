package middleware

import (
	"log"
	"net/http"
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
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets:      make(map[string]*rateBucket),
		limit:        limit,
		window:       window,
		maxBuckets:   10_000,
		cleanupEvery: window,
	}
}

// Wrap wraps the next handler with the rate limiter
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
			key = hashAPIKey(apiKey)
		} else if fp, ok := clientCertFingerprintFromRequest(r); ok {
			// Hash fingerprint as well; keep key format consistent.
			key = hashAPIKey(fp)
		}
		if key == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		rl.mu.Lock()
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

		// get the bucket for the API key
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

		// if the bucket has no tokens, return a 429
		if b.tokens <= 0 {
			rl.mu.Unlock()
			log.Printf("rate_limit key=%s path=%s method=%s", key[:8], r.URL.Path, r.Method)
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}

		// decrement the number of tokens
		b.tokens--
		// unlock the mutex
		rl.mu.Unlock()

		next.ServeHTTP(w, r)
	})
}
