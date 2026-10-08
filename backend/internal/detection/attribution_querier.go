package detection

import (
	"container/list"
	"context"
	"strings"
	"sync"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

const (
	// defaultAttributionCacheSize bounds the number of (host, pid) entries kept in memory.
	defaultAttributionCacheSize = 20000
	// defaultAttributionCacheTTL is how long a (host, pid) → ai_type mapping stays valid.
	defaultAttributionCacheTTL = 2 * time.Hour
	// defaultAIType is used when an event carries AI attribution but no explicit tool/type.
	defaultAIType = "ai-agent"
)

// AttributionCache remembers which (host, pid) pairs were seen carrying AI attribution
// tags (ai_session_id / is_ai) so later events for the same process resolve as AI even
// when the agent omits the tags. It is bounded (oldest entries are evicted first) and
// entries expire after a TTL. Safe for concurrent use; a nil cache is a no-op.
type AttributionCache struct {
	mu      sync.Mutex
	maxSize int
	ttl     time.Duration
	entries map[string]*list.Element
	order   *list.List // front = oldest
	now     func() time.Time
}

type attributionEntry struct {
	key    string
	aiType string
	seen   time.Time
}

// NewAttributionCache creates a cache bounded to maxSize entries with the given TTL.
// Non-positive values fall back to the defaults (20k entries, 2h).
func NewAttributionCache(maxSize int, ttl time.Duration) *AttributionCache {
	if maxSize <= 0 {
		maxSize = defaultAttributionCacheSize
	}
	if ttl <= 0 {
		ttl = defaultAttributionCacheTTL
	}
	return &AttributionCache{
		maxSize: maxSize,
		ttl:     ttl,
		entries: make(map[string]*list.Element),
		order:   list.New(),
		now:     time.Now,
	}
}

func attributionKey(hostID string, pid int) string {
	return hostID + ":" + itoa(pid)
}

// Put records that pid on hostID belongs to an AI process of the given type.
func (c *AttributionCache) Put(hostID string, pid int, aiType string) {
	if c == nil || hostID == "" || pid <= 0 {
		return
	}
	if aiType == "" {
		aiType = defaultAIType
	}
	key := attributionKey(hostID, pid)
	now := c.now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if el, ok := c.entries[key]; ok {
		e := el.Value.(*attributionEntry)
		e.seen = now
		// Keep the first explicit type; only upgrade from the generic fallback.
		if e.aiType == defaultAIType && aiType != defaultAIType {
			e.aiType = aiType
		}
		c.order.MoveToBack(el)
		return
	}
	for c.order.Len() >= c.maxSize {
		oldest := c.order.Front()
		if oldest == nil {
			break
		}
		c.order.Remove(oldest)
		delete(c.entries, oldest.Value.(*attributionEntry).key)
	}
	el := c.order.PushBack(&attributionEntry{key: key, aiType: aiType, seen: now})
	c.entries[key] = el
}

// Get returns the cached ai_type for (hostID, pid) if present and not expired.
func (c *AttributionCache) Get(hostID string, pid int) (string, bool) {
	if c == nil || hostID == "" || pid <= 0 {
		return "", false
	}
	key := attributionKey(hostID, pid)

	c.mu.Lock()
	defer c.mu.Unlock()

	el, ok := c.entries[key]
	if !ok {
		return "", false
	}
	e := el.Value.(*attributionEntry)
	if c.now().Sub(e.seen) > c.ttl {
		c.order.Remove(el)
		delete(c.entries, key)
		return "", false
	}
	return e.aiType, true
}

// Len returns the number of entries currently held (including not-yet-evicted expired ones).
func (c *AttributionCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}

// AttributionQuerier is a GraphQuerier that resolves AI attribution from the event
// being evaluated (its ai_session_id / is_ai / ai_type context tags) and from the
// AttributionCache, before falling back to an optional inner GraphQuerier (Neo4j).
//
// It lets the detection engine run without Neo4j: every rule gates on
// IsAIProcess(), which previously required a graph query. Construct one per ingest
// batch and call SetCurrentEvent before each Engine.Evaluate.
//
// All other GraphQuerier methods delegate to the inner querier when present and
// otherwise return empty results with a nil error.
type AttributionQuerier struct {
	inner GraphQuerier
	cache *AttributionCache

	mu      sync.Mutex
	current *event.Event
}

// NewAttributionQuerier wraps inner (which may be nil) with local attribution resolution.
// cache may be nil, in which case only the current event's own tags are consulted.
func NewAttributionQuerier(inner GraphQuerier, cache *AttributionCache) *AttributionQuerier {
	return &AttributionQuerier{inner: inner, cache: cache}
}

// SetCurrentEvent sets the event under evaluation and records its attribution (if any)
// in the cache so later untagged events for the same PID still resolve.
func (q *AttributionQuerier) SetCurrentEvent(evt *event.Event) {
	if q == nil {
		return
	}
	q.mu.Lock()
	q.current = evt
	q.mu.Unlock()

	if evt == nil || evt.Process == nil || evt.Process.PID <= 0 {
		return
	}
	if isAI, aiType := EventAIAttribution(evt); isAI {
		q.cache.Put(evt.HostID, evt.Process.PID, aiType)
	}
}

// HasGraph reports whether an inner graph querier is configured.
func (q *AttributionQuerier) HasGraph() bool {
	return q != nil && q.inner != nil
}

// EventAIAttribution inspects an event's context tags and reports whether the event
// was emitted by an AI process, and the AI type to attribute it to.
//
// An event is AI-attributed when Context["ai_session_id"] is a non-empty string or
// Context["is_ai"] == true. The type is Context["ai_type"] if present, else
// Context["ai_tool"], else "ai-agent".
func EventAIAttribution(evt *event.Event) (bool, string) {
	if evt == nil || evt.Context == nil {
		return false, ""
	}
	isAI := false
	if sid, ok := evt.Context["ai_session_id"].(string); ok && strings.TrimSpace(sid) != "" {
		isAI = true
	}
	if !isAI {
		switch v := evt.Context["is_ai"].(type) {
		case bool:
			isAI = v
		case string:
			isAI = strings.EqualFold(v, "true")
		}
	}
	if !isAI {
		return false, ""
	}
	return true, eventAIType(evt)
}

func eventAIType(evt *event.Event) string {
	for _, key := range []string{"ai_type", "ai_tool"} {
		if v, ok := evt.Context[key].(string); ok {
			if t := strings.TrimSpace(v); t != "" {
				return t
			}
		}
	}
	return defaultAIType
}

// IsAIProcess resolves attribution locally first (current event tags, then cache),
// then via the inner graph querier if configured.
func (q *AttributionQuerier) IsAIProcess(ctx context.Context, hostID string, pid int) (bool, string, error) {
	if q == nil {
		return false, "", nil
	}

	q.mu.Lock()
	cur := q.current
	q.mu.Unlock()

	if cur != nil && cur.Process != nil && cur.Process.PID == pid && (hostID == "" || cur.HostID == hostID) {
		if isAI, aiType := EventAIAttribution(cur); isAI {
			return true, aiType, nil
		}
	}
	if aiType, ok := q.cache.Get(hostID, pid); ok {
		return true, aiType, nil
	}
	if q.inner != nil {
		return q.inner.IsAIProcess(ctx, hostID, pid)
	}
	return false, "", nil
}

// GetRecentEvents delegates to the inner querier, or returns nothing without a graph.
func (q *AttributionQuerier) GetRecentEvents(ctx context.Context, hostID string, pid int, since time.Time, eventTypes []string) ([]event.Event, error) {
	if q == nil || q.inner == nil {
		return nil, nil
	}
	return q.inner.GetRecentEvents(ctx, hostID, pid, since, eventTypes)
}

// GetRecentEventsMultiPID delegates to the inner querier, or returns nothing without a graph.
func (q *AttributionQuerier) GetRecentEventsMultiPID(ctx context.Context, hostID string, pids []int, since time.Time, eventTypes []string) ([]event.Event, error) {
	if q == nil || q.inner == nil {
		return nil, nil
	}
	return q.inner.GetRecentEventsMultiPID(ctx, hostID, pids, since, eventTypes)
}

// GetRecentEventsBySession delegates to the inner querier, or returns nothing without a graph.
func (q *AttributionQuerier) GetRecentEventsBySession(ctx context.Context, hostID string, sessionID string, since time.Time, eventTypes []string) ([]event.Event, error) {
	if q == nil || q.inner == nil {
		return nil, nil
	}
	return q.inner.GetRecentEventsBySession(ctx, hostID, sessionID, since, eventTypes)
}

// GetProcessAncestors delegates to the inner querier, or returns nothing without a graph.
func (q *AttributionQuerier) GetProcessAncestors(ctx context.Context, hostID string, pid int, maxDepth int) ([]event.Event, error) {
	if q == nil || q.inner == nil {
		return nil, nil
	}
	return q.inner.GetProcessAncestors(ctx, hostID, pid, maxDepth)
}

// itoa is a tiny allocation-free int → string for cache keys (pids are non-negative).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var _ GraphQuerier = (*AttributionQuerier)(nil)
