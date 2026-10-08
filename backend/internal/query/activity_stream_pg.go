package query

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/event"
)

// AgentActivitySource produces the human-readable AI agent activity stream
// served by GET /agents/activity. The graph-backed TimelineService implements
// it when Neo4j is configured; PostgresActivityStream serves it from the
// canonical events table otherwise.
type AgentActivitySource interface {
	GetAgentActivityStream(ctx context.Context, orgID string, since time.Time, minSignificance int) (*AgentActivityResponse, error)
}

var (
	_ AgentActivitySource = (*TimelineService)(nil)
	_ AgentActivitySource = (*PostgresActivityStream)(nil)
)

// maxActivityEvents bounds one activity query; the newest events win.
const maxActivityEvents = 5000

// defaultActivityAIType labels AI-tagged events that carry no ai_type.
const defaultActivityAIType = "ai-agent"

// PostgresActivityStream builds the activity stream from the canonical events
// table using the lineage tags the agent stamps on every event of an AI
// process tree (context.ai_session_id / is_ai / ai_type). One AI session —
// a root AI process and everything it spawned — becomes one AgentSummary.
type PostgresActivityStream struct {
	db  *sql.DB
	now func() time.Time
}

// NewPostgresActivityStream returns a stream backed by the events table.
func NewPostgresActivityStream(db *sql.DB) *PostgresActivityStream {
	return &PostgresActivityStream{db: db, now: time.Now}
}

// GetAgentActivityStream returns the per-session activity of every AI process
// tree that produced events in [since, now] for orgID. Rows written before
// events carried an org (NULL org_id) stay visible, matching the event store.
func (p *PostgresActivityStream) GetAgentActivityStream(ctx context.Context, orgID string, since time.Time, minSignificance int) (*AgentActivityResponse, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, host_id, ts, type, actor, target, context
		FROM events
		WHERE ts >= $1
		  AND ($2::uuid IS NULL OR org_id IS NULL OR org_id = $2::uuid)
		  AND type IN ('file_open', 'file_write', 'net_connect', 'net_dns', 'net_accept', 'net_listen', 'process_exec')
		  AND (COALESCE(context->>'ai_session_id', '') <> '' OR context->>'is_ai' = 'true')
		ORDER BY ts DESC
		LIMIT $3
	`, since, nullableOrgID(orgID), maxActivityEvents)
	if err != nil {
		return nil, fmt.Errorf("agent activity query failed: %w", err)
	}
	defer rows.Close()

	var events []event.Event
	for rows.Next() {
		var (
			evt                         event.Event
			actorRaw, targetRaw, ctxRaw []byte
		)
		if err := rows.Scan(&evt.ID, &evt.HostID, &evt.Timestamp, &evt.Type, &actorRaw, &targetRaw, &ctxRaw); err != nil {
			return nil, fmt.Errorf("agent activity scan failed: %w", err)
		}
		if len(actorRaw) > 0 {
			_ = json.Unmarshal(actorRaw, &evt.Process)
		}
		if len(targetRaw) > 0 {
			_ = json.Unmarshal(targetRaw, &evt.Target)
		}
		if len(ctxRaw) > 0 {
			_ = json.Unmarshal(ctxRaw, &evt.Context)
		}
		events = append(events, evt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("agent activity rows failed: %w", err)
	}

	roots, err := p.sessionRoots(ctx, orgID, sessionIDs(events))
	if err != nil {
		return nil, err
	}

	return buildActivityStream(events, roots, since, p.now(), minSignificance), nil
}

// sessionRoot is a candidate for the process that opened an AI session: one
// of its earliest process_exec events, looked up without the time window so
// long-running agents report their real start time.
type sessionRoot struct {
	StartedAt time.Time
	PID       int
	Comm      string
	ExePath   string
	Argv0     string
}

// maxRootCandidates bounds the earliest exec events fetched per session.
const maxRootCandidates = 25

func (p *PostgresActivityStream) sessionRoots(ctx context.Context, orgID string, ids []string) (map[string][]sessionRoot, error) {
	roots := make(map[string][]sessionRoot, len(ids))
	if len(ids) == 0 {
		return roots, nil
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT sid, ts, actor FROM (
			SELECT context->>'ai_session_id' AS sid, ts, actor,
			       row_number() OVER (PARTITION BY context->>'ai_session_id' ORDER BY ts ASC) AS rn
			FROM events
			WHERE context->>'ai_session_id' = ANY($1)
			  AND type = 'process_exec'
			  AND ($2::uuid IS NULL OR org_id IS NULL OR org_id = $2::uuid)
		) c
		WHERE rn <= $3
		ORDER BY sid, ts ASC
	`, ids, nullableOrgID(orgID), maxRootCandidates)
	if err != nil {
		return nil, fmt.Errorf("agent activity root query failed: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			sid      string
			ts       time.Time
			actorRaw []byte
		)
		if err := rows.Scan(&sid, &ts, &actorRaw); err != nil {
			return nil, fmt.Errorf("agent activity root scan failed: %w", err)
		}
		root := sessionRoot{StartedAt: ts}
		if len(actorRaw) > 0 {
			var actor event.ActorStruct
			if json.Unmarshal(actorRaw, &actor) == nil {
				root.PID, root.Comm, root.ExePath = actor.PID, actor.Comm, actor.ExePath
				if len(actor.Cmdline) > 0 {
					root.Argv0 = actor.Cmdline[0]
				}
			}
		}
		roots[sid] = append(roots[sid], root)
	}
	return roots, rows.Err()
}

// pickRoot chooses the process that opened a session from its earliest exec
// events: the first whose name matches the session's ai_type (the pattern
// the agent matched), else the earliest. Trees reported by the agent's
// startup /proc scan carry near-identical timestamps, so order alone is not
// reliable.
func pickRoot(candidates []sessionRoot, aiType string) *sessionRoot {
	if len(candidates) == 0 {
		return nil
	}
	for i := range candidates {
		if rootNameMatches(candidates[i], aiType) {
			return &candidates[i]
		}
	}
	return &candidates[0]
}

func rootNameMatches(r sessionRoot, aiType string) bool {
	aiType = strings.ToLower(strings.TrimSpace(aiType))
	if aiType == "" || aiType == defaultActivityAIType {
		return false
	}
	for _, name := range []string{r.Comm, baseName(r.ExePath), baseName(r.Argv0)} {
		name = strings.ToLower(name)
		if name == "" {
			continue
		}
		if name == aiType {
			return true
		}
		if len(name) > len(aiType) && strings.HasPrefix(name, aiType) {
			switch name[len(aiType)] {
			case '-', '.', '_':
				return true
			}
		}
	}
	return false
}

// baseName returns the last path component for both separator styles.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// sessionIDs returns the distinct non-empty ai_session_id tags of events.
func sessionIDs(events []event.Event) []string {
	seen := make(map[string]struct{})
	var ids []string
	for i := range events {
		if sid := activitySessionID(&events[i]); sid != "" {
			if _, dup := seen[sid]; !dup {
				seen[sid] = struct{}{}
				ids = append(ids, sid)
			}
		}
	}
	return ids
}

func nullableOrgID(orgID string) any {
	if strings.TrimSpace(orgID) == "" {
		return nil
	}
	return orgID
}

func activitySessionID(evt *event.Event) string {
	if evt.Context == nil {
		return ""
	}
	sid, _ := evt.Context["ai_session_id"].(string)
	return strings.TrimSpace(sid)
}

func activityAIType(evt *event.Event) string {
	for _, key := range []string{"ai_type", "ai_tool"} {
		if v, ok := evt.Context[key].(string); ok {
			if t := strings.TrimSpace(v); t != "" {
				return t
			}
		}
	}
	return defaultActivityAIType
}

func isSyntheticExec(evt *event.Event) bool {
	switch v := evt.Context["synthetic_exec"].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

// activitySession accumulates one AI session while events are folded in.
type activitySession struct {
	key          string
	hostID       string
	aiType       string
	root         *sessionRoot // chosen root (nil when no process_exec was stored for the session)
	earliest     *event.Event // earliest event in the window
	earliestExec *event.Event // earliest non-synthetic process_exec in the window
	pids         map[int]struct{}
	actions      []AgentAction
	stats        AgentStats
}

// buildActivityStream folds events (any order) into one AgentSummary per AI
// session. Sessions are keyed by ai_session_id, or by host + ai_type for
// events that only carry is_ai. Synthetic exec events (fork-only children the
// agent reports for tree completeness) are not shown as actions. Sessions
// are ordered newest first; actions within a session oldest first.
func buildActivityStream(events []event.Event, roots map[string][]sessionRoot, since, now time.Time, minSignificance int) *AgentActivityResponse {
	sessions := make(map[string]*activitySession)
	var order []string

	for i := range events {
		evt := &events[i]
		sid := activitySessionID(evt)
		key := sid
		if key == "" {
			key = "host:" + evt.HostID + "|type:" + activityAIType(evt)
		}

		s := sessions[key]
		if s == nil {
			s = &activitySession{key: key, hostID: evt.HostID, aiType: activityAIType(evt), pids: make(map[int]struct{})}
			if sid != "" {
				if s.root = pickRoot(roots[sid], s.aiType); s.root != nil && s.root.PID > 0 {
					s.pids[s.root.PID] = struct{}{}
				}
			}
			sessions[key] = s
			order = append(order, key)
		}

		actor := evt.Process
		if actor == nil {
			actor = &event.ActorStruct{}
		}
		if actor.PID > 0 {
			s.pids[actor.PID] = struct{}{}
		}
		if s.earliest == nil || evt.Timestamp.Before(s.earliest.Timestamp) {
			s.earliest = evt
		}

		if isSyntheticExec(evt) {
			continue
		}
		if evt.Type == "process_exec" && (s.earliestExec == nil || evt.Timestamp.Before(s.earliestExec.Timestamp)) {
			s.earliestExec = evt
		}

		target := evt.Target
		if target == nil {
			target = &event.TargetStruct{}
		}
		action := buildAction(evt.Type, target.FilePath, target.IP, target.Port, target.Domain,
			strings.Join(actor.Cmdline, " "), actor.Comm, actor.ExePath)
		if action.Significance < minSignificance {
			continue
		}
		action.Timestamp = evt.Timestamp
		action.EventID = evt.ID
		action.EventType = evt.Type
		action.ProcessPID = actor.PID
		action.ProcessComm = actor.Comm
		s.actions = append(s.actions, action)

		s.stats.TotalEvents++
		switch action.Category {
		case "file":
			if evt.Type == "file_write" {
				s.stats.FilesModified++
			} else {
				s.stats.FilesRead++
			}
		case "network":
			s.stats.Connections++
		case "dns":
			s.stats.DNSLookups++
		case "command":
			s.stats.CommandsRun++
		}
	}

	agents := make([]AgentSummary, 0, len(order))
	for _, key := range order {
		s := sessions[key]
		sortActionsByTime(s.actions)
		if s.actions == nil {
			s.actions = []AgentAction{}
		}

		// Identity: the recorded root, else the earliest exec in the window,
		// else whatever process produced the earliest event.
		var (
			rootPID       int
			comm, exePath string
			started       time.Time
		)
		switch {
		case s.root != nil:
			rootPID, comm, exePath, started = s.root.PID, s.root.Comm, s.root.ExePath, s.root.StartedAt
		case s.earliestExec != nil && s.earliestExec.Process != nil:
			rootPID, comm, exePath = s.earliestExec.Process.PID, s.earliestExec.Process.Comm, s.earliestExec.Process.ExePath
			started = s.earliest.Timestamp
		default:
			if s.earliest.Process != nil {
				comm, exePath = s.earliest.Process.Comm, s.earliest.Process.ExePath
			}
			started = s.earliest.Timestamp
		}
		if comm == "" {
			comm = s.aiType
		}
		childCount := len(s.pids) - 1
		if childCount < 0 {
			childCount = 0
		}
		agents = append(agents, AgentSummary{
			AgentName:  comm,
			AgentPID:   rootPID,
			AIType:     s.aiType,
			HostID:     s.hostID,
			ExePath:    exePath,
			StartedAt:  started,
			Duration:   formatDuration(now.Sub(started)),
			Actions:    s.actions,
			Stats:      s.stats,
			ChildCount: childCount,
		})
	}
	sort.SliceStable(agents, func(i, j int) bool { return agents[i].StartedAt.After(agents[j].StartedAt) })

	return &AgentActivityResponse{
		Agents:      agents,
		WindowStart: since,
		WindowEnd:   now,
	}
}
