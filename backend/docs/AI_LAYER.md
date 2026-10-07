---
name: AI Layer (Phase 5+6)
description: BYOK LLM integration — incident dossier, agentic tool-calling, threaded chat, SSE streaming, summary caching, and AI Intelligence System (3-layer learned context)
type: project
---

# AI Layer (Phase 5+6)

BYOK LLM-powered incident analysis with three tiers: one-shot explanation (cached), threaded Q&A chat with tool-calling, and per-finding explanation. All analysis is grounded in a structured dossier document built from real event data. The AI can autonomously query Neo4j and PostgreSQL via 18 tool calls to answer user questions.

> **Phase 6 — AI Intelligence System**: The AI now has three context layers (system profile, hierarchical context windows, learned patterns) that give it deep system understanding and a 5-step reasoning chain. See [AI_INTELLIGENCE.md](AI_INTELLIGENCE.md) for the full architecture.

## Architecture

```
User clicks "Explain" on incident/finding
  |
  v
Frontend: POST /api/v1/incidents/{id}/explain
  |
  v
Next.js proxy (SSE pass-through for streaming)
  |
  v
IncidentAIHandler.ExplainIncident(w, r)
  |
  ├── Check summary cache (IncidentSummaryStore.GetSummary)
  │     └── If valid cached summary → return immediately (zero LLM cost)
  │
  ├── Get LLM provider (SettingsStore.GetActiveProvider → decrypt API key)
  │     └── uuid.Parse orgID → look up per-org encrypted settings
  │
  ├── Load pre-built dossier (DossierStore.GetText)
  │     └── If cached → use directly (fast path)
  │
  ├── Fall back to on-demand assembly (ContextAssembler.Assemble → DossierBuilder)
  │     └── PostgreSQL (incident + findings) + Neo4j (process tree, events)
  │     └── ProcessDetails built per-PID: cmdline, user, files, network, DNS
  │
  ├── Build system prompt (IncidentExplainPrompt with reasoning chain)
  │     └── 6-step reasoning: evidence inventory → temporal analysis → attack hypothesis
  │         → counter-hypothesis → evidence weighing → risk calibration
  │
  ├── Call LLM (provider.Chat)
  │     └── Provider-specific HTTP call (OpenAI/Anthropic/Gemini/Groq/xAI)
  │
  ├── Parse reasoning block + risk score from response
  │
  ├── Cache summary (IncidentSummaryStore.SaveSummary)
  │     └── Upsert ON CONFLICT (org_id, incident_id)
  │
  └── Return JSON: { content, reasoning, model, cached, risk_score, risk_justification, tokens }

Threaded Chat with Tool-Calling:
  POST /api/v1/incidents/{id}/chat
    |
    v
  ChatAboutIncident
    ├── Load/build dossier (DossierStore → DossierBuilder → ContextAssembler)
    ├── Get/create conversation thread (ConversationStore)
    ├── Load history (last 20 turns)
    ├── Build messages: system prompt + history + user message
    ├── Attach 14 tool definitions if tool registry available
    ├── SSE: emit thread_id → stream response
    ├── Non-streaming: chatWithToolLoop (up to 5 iterations)
    │     └── LLM calls tools → executeToolCall → results fed back → repeat
    ├── Save user + assistant messages to thread
    └── Return: { content, model, thread_id, tokens }

Legacy Q&A:
  POST /api/v1/incidents/{id}/ask/stream
    |
    v
  StreamAskAboutIncident
    ├── Type-assert StreamingProvider (OpenAI/Anthropic)
    │     └── If not streaming → fall back to Chat() + single SSE delta
    ├── SSEWriter: event:delta → event:done
    └── Frontend: ReadableStream parser with try/finally reader.cancel()

Summary Invalidation:
  Incident created/updated (correlator) ──┐
  Incident status changed (API PATCH)  ───┤
  New finding merged into incident     ───┤
                                          v
                                  SummaryInvalidator.InvalidateSummary(incidentID)
                                          |
                                          v
                                  UPDATE incident_ai_summaries
                                  SET invalidated_at = NOW()

Dossier Invalidation:
  DossierInvalidator.InvalidateDossier(incidentID)
    → UPDATE incidents SET dossier_text = NULL, dossier_built_at = NULL
```

## Key Files

| File | Purpose |
|------|---------|
| `internal/ai/provider/provider.go` | `Provider`, `StreamingProvider` interfaces, `ToolDefinition`, `ToolCall`, `ChatRequest`, `ChatResponse` types |
| `internal/ai/provider/openai.go` | OpenAI provider: `Chat()` + `StreamChat()` + function calling (request/response parsing) |
| `internal/ai/provider/anthropic.go` | Anthropic provider: `Chat()` + `StreamChat()` + `tool_use`/`tool_result` content blocks |
| `internal/ai/provider/gemini.go` | Gemini provider: `Chat()` only (no streaming) |
| `internal/ai/provider/groq.go` | Groq provider: `Chat()` only (OpenAI-compatible API) |
| `internal/ai/provider/settings_store.go` | Per-org encrypted API key storage (AES-256-GCM) |
| `internal/ai/provider/incident_prompt.go` | All prompts: `DossierChatSystemPrompt`, `IncidentExplainPrompt`, `IncidentAskSystemPrompt`, `FindingExplainSystemPrompt` |
| `internal/ai/summary_store.go` | `IncidentSummaryStore`: cache + invalidation. Nil-safe. |
| `internal/ai/dossier/builder.go` | `DossierBuilder`: assembles `DossierData` (detail + related incidents + baselines). 25s deadline. |
| `internal/ai/dossier/formatter.go` | `FormatDossier`: renders structured text dossier (10 sections). Nil-safe. |
| `internal/ai/dossier/store.go` | `Store`: reads/writes pre-rendered dossier text on incidents table (migration 073). `ListNeedingBuild` for proactive summarizer. |
| `internal/ai/conversation/store.go` | `Store`: threaded conversation management. `GetOrCreateThread`, `AppendMessage`, `GetHistory`, `PurgeOldThreads`. Nil-safe. Migration 074. |
| `internal/ai/tools/tools.go` | `NewRegistry`: 14 tools (7 PostgreSQL query + 5 Neo4j graph + 2 additional query). Security: host_id forced, time clamped. |
| `internal/api/incident_ai_handler.go` | HTTP handlers + `chatWithToolLoop` (5-iteration agentic loop) + `executeToolCall` (security enforcement) |
| `internal/api/sse.go` | `SSEWriter`: `WriteDelta`, `WriteDone`, `WriteError` |
| `internal/incident/assembler.go` | `ContextAssembler.Assemble`: builds `IncidentDetail` with `ProcessDetails` per-PID. PostgreSQL fallback when Neo4j unavailable. |
| `internal/incident/types.go` | `ProcessDetail` struct: PID, PPID, Exe, Cmdline, User, StartedAt, Files, NetConns, DNSQueries |

## Dossier System

### DossierData Structure
```go
type DossierData struct {
    Detail           *incident.IncidentDetail
    RelatedIncidents []incident.Incident               // same host, last 30 days, max 5
    BaselinesByExe   map[string][]detection.BaselineEntry // exe_path → baselines
    BuiltAt          time.Time
}
```

### ProcessDetail (per-PID enrichment)
```go
type ProcessDetail struct {
    PID        int64     `json:"pid"`
    PPID       int64     `json:"ppid"`
    Exe        string    `json:"exe"`
    Cmdline    string    `json:"cmdline"`
    User       string    `json:"user"`
    StartedAt  time.Time `json:"started_at"`
    Files      []string  `json:"files,omitempty"`      // file paths accessed
    NetConns   []string  `json:"net_conns,omitempty"`   // network destinations
    DNSQueries []string  `json:"dns_queries,omitempty"` // DNS lookups made
}
```

Built from:
- **Neo4j path**: `buildProcessDetailsFromEventNodes()` — groups attack chain `EventNode` results by PID
- **PostgreSQL fallback**: `buildProcessDetailsFromEvents()` — groups raw `event.Event` by PID

### Formatted Dossier Sections (10)
1. **OVERVIEW** — severity, confidence, host, time window, MITRE, detection count
2. **ATTACK SEQUENCE** — 2-4 sentence narrative from timeline (significant events only)
3. **PROCESS CHAIN** — ASCII tree with AI agent labels, finding flags, exe paths
4. **PROCESS DETAILS** — per-process: cmdline, started time, files (max 5), network, DNS
5. **DETECTIONS** — box-formatted findings with evidence keys, sensitive files, MITRE
6. **TIMELINE** — chronological events (max 30), flagged findings marked with ⚠
7. **NETWORK ACTIVITY** — deduplicated destinations with BGP/ASN, connected-by process
8. **SENSITIVE FILES ACCESSED** — categorized: SSH, cloud creds, .env, /etc/, other
9. **BEHAVIORAL CONTEXT** — per-exe baseline status (NEW vs KNOWN behavior)
10. **RELATED INCIDENTS** — same host, last 30 days (max 5)
11. **DATA COMPLETENESS** — availability of process tree, timeline, network, baselines

### Dossier Store (migration 073)
Pre-rendered dossier text stored on `incidents` table (`dossier_text`, `dossier_built_at` columns).
Proactive summarizer fills these for open/investigating incidents.
`ListNeedingBuild(limit)` returns priority-sorted (severity then recency) incidents needing dossier.

## Agentic Tool-Calling System

### Tool Registry (14 tools)

**Graph tools (Neo4j — relationship traversal):**
| Tool | Description | Key Params |
|------|-------------|------------|
| `get_process_tree` | Parent/child process chain (5 up, 10 down) | `pid` |
| `get_attack_chain` | BFS from PID, up to 100 connected events | `pid`, `since`, `until` |
| `find_related_events` | Events matching file path or IP | `pattern` |
| `get_session_activity` | All events in a login session | `pid` (as session_id) |
| `get_lateral_movement` | Network connections followed by child spawns | `since` |

**Query tools (PostgreSQL — time-range searches):**
| Tool | Description | Key Params |
|------|-------------|------------|
| `list_containers` | Container start events | `since`, `until` |
| `list_open_ports` | net_listen events | `since`, `until` |
| `list_external_connections` | Outbound net_connect events | `since`, `until` |
| `list_execs` | All process_exec events | `since`, `until` |
| `list_inbound_connections` | Inbound net_accept events | `since`, `until` |
| `list_processes_by_executable` | process_exec by exe path pattern | `pattern`, `since`, `until` |
| `diff_processes` | Process changes between two windows | `base_since/until`, `compare_since/until` |
| `diff_connections` | Connection changes between two windows | same diff params |
| `diff_ports` | Port changes between two windows | same diff params |

### Security Enforcement (`executeToolCall`)
- **Host locked**: `host_id` forced to incident's `detail.HostID` — AI cannot query other hosts
- **Time clamped**: All time windows clamped to `incident.StartedAt - 30min` through `incident.EndedAt + 30min`
- **Ongoing incidents**: If `EndedAt` is zero, uses `now + 30min` as upper bound
- **Result cap**: 32KB maximum per tool result to prevent context window blowup
- **Nil-safe graph tools**: Return `"graph store unavailable"` when Neo4j is nil

### Tool-Calling Loop (`chatWithToolLoop`)
```
1. If no tools configured → single LLM call (fast path)
2. Copy messages to avoid mutation
3. Loop up to 5 iterations:
   a. Call LLM with tools
   b. If no tool calls → return final response
   c. Append assistant message with tool calls
   d. Execute each tool call → append results as tool messages
   e. Continue loop
4. If max iterations hit and last response was tool call:
   → Make one final call WITHOUT tools to force text output
5. Accumulate total token counts across all iterations
```

### Provider Tool-Use Formats

**OpenAI**: Messages serialized manually to handle `tool` role (with `tool_call_id`) and assistant `tool_calls` array. Tools in `{"type": "function", "function": {...}}` format. `tool_choice` passed through directly.

**Anthropic**: `tool` messages converted to `{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "...", "content": "..."}]}`. Assistant tool calls include `tool_use` content blocks with parsed `input` object. Tools use `input_schema` (not `parameters`). `tool_choice` mapped to Anthropic object format.

## Provider System

### Interface Hierarchy
```go
type Provider interface {
    Name() string
    Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
    AnalyzeEvents(ctx context.Context, events []map[string]any) (*SecurityAnalysis, error)
    ExplainEvent(ctx context.Context, event map[string]any) (*EventExplanation, error)
}

type StreamingProvider interface {
    Provider
    StreamChat(ctx context.Context, req *ChatRequest, onDelta func(delta string)) (*ChatResponse, error)
}

type ToolDefinition struct {
    Name        string         `json:"name"`
    Description string         `json:"description"`
    Parameters  map[string]any `json:"parameters"` // JSON Schema
}

type ToolCall struct {
    ID        string `json:"id"`
    Name      string `json:"name"`
    Arguments string `json:"arguments"` // JSON string
}
```

### Provider Details

| Provider | Streaming | Tool-Use | Auth | Default Model |
|----------|-----------|----------|------|---------------|
| OpenAI | Yes | Yes (function calling) | `Authorization: Bearer` | gpt-4o |
| Anthropic | Yes | Yes (tool_use/tool_result) | `x-api-key` + `anthropic-version` | claude-sonnet-4-20250514 |
| Gemini | No | No | `?key=` query param | gemini-2.0-flash |
| Groq | No | No | `Authorization: Bearer` (OpenAI-compat) | llama-3.1-70b-versatile |
| xAI | - | - | `Authorization: Bearer` | grok-beta |

### Encrypted API Key Storage (AES-256-GCM)
Per-org: each org has its own provider + model + API key.
`LLM_ENCRYPTION_KEY` env var required (logs warning if using default).

## Conversation Threading (migration 074)

### Tables
```sql
ai_conversation_threads (id, org_id, incident_id, message_count, last_active, created_at)
ai_conversation_messages (id, thread_id, org_id, role, content, token_count, compressed, created_at)
```

### Flow
1. Client sends `thread_id` (or empty for new thread)
2. `GetOrCreateThread` returns existing or creates new
3. System prompt + last 20 history messages + new user message
4. After LLM response, both messages saved via `AppendMessage`
5. `PurgeOldThreads` deletes threads inactive > 7 days

## API Endpoints

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| `POST` | `/api/v1/incidents/{id}/explain` | `ExplainIncident` | AI explanation (cached, with reasoning) |
| `POST` | `/api/v1/incidents/{id}/chat` | `ChatAboutIncident` | Threaded chat with tool-calling |
| `POST` | `/api/v1/incidents/{id}/ask` | `AskAboutIncident` | Legacy non-streaming Q&A |
| `POST` | `/api/v1/incidents/{id}/ask/stream` | `StreamAskAboutIncident` | Legacy SSE streaming Q&A |
| `GET` | `/api/v1/incidents/{id}/chat/history` | `GetChatHistory` | Thread message history |
| `DELETE` | `/api/v1/incidents/{id}/chat/thread/{tid}` | `DeleteChatThread` | Delete conversation thread |
| `POST` | `/api/v1/findings/{id}/explain` | `ExplainFinding` | Explain single finding |

### ExplainIncident Response
```json
{
    "content": "### Risk Score: 8/10\n...",
    "reasoning": "Step 1 — Evidence Inventory\n...",
    "model": "claude-sonnet-4-20250514",
    "cached": true,
    "risk_score": 8,
    "risk_justification": "Strong attack indicators...",
    "tokens": { "input": 2340, "output": 856 }
}
```

### Chat Response (SSE)
```
data: {"type":"thread_id","thread_id":"abc-123"}

event: delta
data: "## Analysis\n\n"

event: delta
data: "The process..."

event: done
data: {"model":"gpt-4o","tokens":{"input":3400,"output":1200}}
```

## Explain Prompt — Structured Reasoning

The `IncidentExplainPrompt` includes a mandatory 6-step `<reasoning>` block:
1. **Evidence Inventory** — list each detection with confidence + strongest artifact
2. **Temporal Analysis** — map process causality from timeline/tree
3. **Attack Hypothesis** — most likely explanation (falsifiable)
4. **Counter-Hypothesis** — most plausible benign explanation
5. **Evidence Weighing** — FOR vs AGAINST the attack hypothesis
6. **Risk Calibration** — derive numeric score with adjustment factors

Reasoning is parsed out by `parseReasoning()` and returned separately from clean content.
Risk score is parsed by `parseRiskScore()` (regex: `### Risk Score: X/10`).

## Summary Caching

### Database Schema (migration 058 + 059)
```sql
CREATE TABLE incident_ai_summaries (
    id, org_id, incident_id, summary, model, input_tokens, output_tokens,
    generated_at, invalidated_at
);
CREATE UNIQUE INDEX ON incident_ai_summaries(org_id, incident_id);
```

### Invalidation
All incident mutation paths invalidate via `SummaryInvalidator` interface:
- Chain incident created, finding merged, seed created (correlator)
- Manual status change (PATCH handler)

## Constructor (cmd/api/main.go)

```go
incidentAIHandler := api.NewIncidentAIHandler(
    llmSettingsStore,    // per-org encrypted API keys
    contextAssembler,    // IncidentDetail builder
    findingStore,        // finding CRUD
    summaryStore,        // summary cache
    dossierStore,        // pre-rendered dossier text
    dossierBuilder,      // on-demand dossier assembly
    convStore,           // conversation threading
    queryService,        // PostgreSQL query tools
    graphStore,          // Neo4j graph tools (may be nil)
)
```

## Configuration Defaults

| Parameter | Value | Location |
|-----------|-------|----------|
| Max tool iterations | 5 | incident_ai_handler.go |
| Tool result cap | 32KB | incident_ai_handler.go |
| Time window padding | ±30 minutes | incident_ai_handler.go |
| Conversation history | 20 turns | incident_ai_handler.go |
| Thread purge age | 7 days | conversation/store.go |
| Dossier build timeout | 25 seconds | dossier/builder.go |
| Related incidents | max 5, last 30 days | dossier/builder.go |
| Timeline events | max 30 shown | dossier/formatter.go |
| Files per process | max 5 shown | dossier/formatter.go |
| Default max tokens | 4096 | All providers |
| Default temperature | 0.7 | All providers |
| HTTP timeout | 120s | All providers |
| SSE scanner buffer | 256KB max line | openai.go, anthropic.go |

## Resilience & Edge Cases

- **Nil-safe stores**: All stores (summary, dossier, conversation) have nil-safe receivers
- **Provider not configured**: Returns 400 "no LLM provider configured"
- **Neo4j unavailable**: Assembler degrades — ProcessTree nil, but ProcessDetails still built from PostgreSQL fallback (`buildProcessDetailsFromEvents`)
- **Tool-calling fallback**: If streaming, tools stripped from request (streaming + tools deferred). Non-streaming uses full tool loop.
- **Dossier fallback chain**: pre-built (DossierStore) → on-demand (DossierBuilder) → minimal (ContextAssembler only)
- **Graph tools nil-safe**: Return `"graph store unavailable"` string when Neo4j is nil
- **Max iterations safety**: After 5 tool-call iterations, makes final call without tools to force text output
- **Scanner buffer overflow**: Both streaming providers check `scanner.Err()` after loop
- **Org isolation**: Summary cache, conversation threads, dossier store all keyed on `(org_id, ...)`

## Audit Fixes Applied (15 total from initial audit)

### Critical (5)
- C1: Anthropic `stop_reason` field parsing
- C2: `scanner.Err()` unchecked in both streaming providers
- C3: PATCH status changes didn't invalidate cached summaries
- C4: Summary cache UNIQUE on `incident_id` only → composite `(org_id, incident_id)`
- C5: `marshalIncidentForLLM` nil dereference

### High (6)
- H1-H6: uuid.Parse error handling, stream reader cleanup, SSE error messages, cached field, EOF buffer, createSeed invalidation

### Medium (4)
- M2/M4/M5/L2: Truncation metadata, encryption key warning, streaming fallback race, marshal error logging
