# AI Intelligence System — Learned Security Analyst

## Overview

The AI Intelligence System transforms Correlic's LLM from a passive summarizer into a **security analyst that knows your system**. It maintains three context layers that give the AI deep understanding of what's normal, what's happening now, and what it has learned from past incidents.

**Before**: AI receives a text dump of events, summarizes them, answers from the dump.
**After**: AI has system context, temporal awareness, historical learning, a structured reasoning chain, and AI agent behavioral profiles.

---

## Complete Context Assembly Flow

When a user clicks "Analyze" on an incident, this is the exact data flow:

```
User clicks "Analyze Incident"
    │
    ▼
IncidentAIHandler (incident_ai_handler.go)
    │
    ├── 1. Get/build DOSSIER (pre-built or on-demand)
    │     └── FormatDossier() → structured text with:
    │         Overview, Attack Sequence, Process Chain (tree),
    │         Process Details (grouped), Detections, Timeline,
    │         Network Activity, Sensitive Files, Baselines, Related Incidents
    │
    ├── 2. Build ON-DEMAND MICRO-CONTEXT (5-min + 30-min)
    │     └── GetOnDemandContext(hostID, since) → formatted text:
    │         Activity pattern, process counts, file counts,
    │         network connections, findings, sensitive files
    │
    ├── 3. Assemble SYSTEM PROMPT
    │     └── safetyPreamble + aiAgentBehavioralProfiles
    │         + explainDossierSection (with dossier + microContext)
    │         + explainFormat (6-step reasoning block)
    │
    ├── 4. Send to LLM with TOOL DEFINITIONS (18 tools)
    │     └── LLM may call tools autonomously (up to 5 iterations):
    │         get_system_profile, get_recent_activity,
    │         get_learned_patterns, get_false_positive_rate,
    │         get_process_tree, list_execs, etc.
    │
    └── 5. Return AI response to user
```

---

## What the LLM Receives (Exact Prompt Structure)

The system prompt is assembled from these components in order:

### Component 1: Safety Preamble

```
You are a defensive security analyst assistant for Correlic.

BEHAVIORAL RULES:
1. EVIDENCE-ONLY — cite PIDs, file paths, IPs, timestamps
2. HONEST UNCERTAINTY — use hedging language
3. DEFENSIVE SCOPE ONLY — no offensive techniques
4. DATA GAPS — acknowledge when dossier sections are unavailable
5. SCOPE — focus on this incident and host

DETECTION RULES REFERENCE:
| detection_id | What it detects | MITRE |
| ai.credential_access | SSH keys, cloud creds, tokens | T1552 |
| ai.privilege_escalation | sudo/su/powershell -ExecutionPolicy Bypass | T1548 |
| ai.persistence | cron/systemd/registry Run keys/SSH config | T1546, T1053 |
| ... (13 rules + 11 chain patterns) |

NOTE ON CONFIDENCE SCORES:
Confidence reflects pattern match strength, NOT malicious probability.
95% on ai.privilege_escalation = cmdline matched well, but context
(parent process, dev machine, AI agent) may make it benign. Your job
is contextual judgment on top of pattern confidence.
```

**File**: `internal/ai/provider/incident_prompt.go` — `safetyPreamble` constant

### Component 2: AI Agent Behavioral Profiles

```
AI AGENT BEHAVIORAL PROFILES (known-benign patterns):

Claude Code (VSCode extension — claude.exe):
  - Process chain: claude.exe → conhost.exe → bash.exe → [command]
  - PowerShell temp scripts: %TEMP%\ps-script-<UUID>.ps1
    with -ExecutionPolicy Bypass — NOT privilege escalation
  - Reads source code continuously (hundreds of file_open per session)
  - Network: api.anthropic.com (2607:6bc0::/48)

Cursor (VSCode-based editor — Cursor.exe):
  - Spawns reg.exe at startup for registry queries — NOT persistence
  - Uses WSL (wsl.exe, wslhost.exe)

Common false positive patterns:
  - SSH reading .ssh/config → normal SSH behavior
  - reg.exe with no cmdline → process exited before capture (Low Context)
  - powershell.exe -ExecutionPolicy Bypass from AI agent → temp script, not escalation
```

**File**: `internal/ai/provider/incident_prompt.go` — `aiAgentBehavioralProfiles` constant

### Component 3: Incident Dossier

Formatted text containing all incident data:

```
═══════════════════════════════════════════════════════════
SECURITY INCIDENT DOSSIER — [Title]
═══════════════════════════════════════════════════════════

OVERVIEW
  Severity, confidence, host, time window, MITRE techniques, detection count

ATTACK SEQUENCE
  2-4 sentence narrative derived from event timestamps

PROCESS CHAIN
  ASCII tree: parent → child with [FLAGGED] markers and [AI agent: type] labels

PROCESS DETAILS (N processes, M unique)
  [FLAGGED] powershell.exe PID 34912 — full cmdline + files + network
  bash.exe (42 instances)          ← grouped to reduce noise
  conhost.exe (15 instances)       ← 80 entries → 5 lines
  claude.exe (6 instances)

DETECTIONS
  Box-formatted findings with severity, confidence, MITRE, evidence

TIMELINE (chronological, max 30 entries)

NETWORK ACTIVITY
  IP:port, BGP prefix, ASN, connected by PID

SENSITIVE FILES ACCESSED
  Grouped by category (SSH, cloud creds, tokens, etc.)

BEHAVIORAL CONTEXT
  Per-executable baseline status (KNOWN vs NEW behavior)

RELATED INCIDENTS (same host, last 30 days)

DATA COMPLETENESS
  Process tree, timeline, network events, baselines availability
```

**File**: `internal/ai/dossier/formatter.go` — `FormatDossier()`

### Component 4: On-Demand Micro-Context

Built in real-time from raw events (not from background worker). Two time windows:

```
RECENT ACTIVITY (last 5 minutes):
  Activity: active_development
  Processes: 3 executions (powershell, bash)
  Files: 45 opens (42 exist, 3 not-found)
  Network: 7 connections
  Findings: 2 generated, 0 suppressed

SESSION CONTEXT (last 30 minutes):
  Activity: active_development
  Processes: 48 executions (bash, git, go, psql, powershell)
  Files: 890 opens
  Network: 23 connections
  Findings: 12 generated, 8 suppressed
```

**Why two windows**:
- **5-min**: "What just happened around the incident" — immediate causality
- **30-min**: "What was the session doing" — detects slow recon patterns, gives session type

**Activity pattern classification** (auto-detected from binary mix):
- `active_development` — dev tools (bash, git, go, node, psql) present, >5 execs
- `build_or_ci` — >50 execs (compiler, linker, assembler)
- `idle_with_background_network` — 0 execs but network activity
- `idle` — no activity at all
- `light_activity` — some activity, not clearly dev

**File**: `internal/api/incident_ai_handler.go` — `formatMicroContext()`
**File**: `internal/ai/intelligence/store.go` — `GetOnDemandContext()`, `classifyActivity()`

### Component 5: Explain Format (6-Step Reasoning Block)

For the ExplainIncident endpoint, the LLM is instructed to follow a mandatory reasoning chain:

```
<reasoning>
Step 1 — Evidence Inventory: List each detection with confidence + strongest evidence
Step 2 — Temporal Analysis: Map what triggered what from timeline + process chain
Step 3 — Attack Hypothesis: Most likely malicious explanation (falsifiable)
Step 4 — Counter-Hypothesis: Most plausible benign explanation
Step 5 — Evidence Weighing: FOR attack vs AGAINST (neutral/benign)
Step 6 — Risk Calibration: Derive numeric score with adjustment factors
</reasoning>

Structured output sections:
  Risk Score: X/10
  What Happened
  Network Destinations (table)
  Process Chain
  Sensitive Files Accessed
  Why It Matters (MITRE mapping)
  Confidence Assessment
  Recommended Actions (specific artifacts, not generic)
```

**File**: `internal/ai/provider/incident_prompt.go` — `explainFormat` constant

### Component 6: Tool Definitions (18 tools)

The LLM receives JSON Schema definitions for all tools and can call them autonomously:

```
Intelligence tools:
  get_system_profile    — Layer 1: AI agents, network, baselines
  get_recent_activity   — Layer 2: context windows by granularity
  get_learned_patterns  — Layer 3: verdicts from user feedback
  get_false_positive_rate — per-rule accuracy

Graph tools (Neo4j):
  get_process_tree      — parent/child chain (5 up, 10 down)
  get_attack_chain      — BFS up to 100 connected events
  find_related_events   — file/IP pattern matching
  get_session_activity  — login session events
  get_lateral_movement  — network → child process correlation

Query tools (PostgreSQL):
  list_execs, list_external_connections, list_open_ports,
  list_containers, list_processes_by_executable,
  diff_processes, diff_connections, diff_ports
```

**File**: `internal/ai/tools/tools.go` — `NewRegistry()`

---

## Three Context Layers (Data Generation)

### Layer 1: System Profile

**What it is**: A structured JSON document describing the user's environment.
**Updated**: Hourly by background worker + on baseline/agent changes.
**Storage**: `ai_system_profiles` table, one row per (org_id, host_id).

**Data sources**:
- `ai_agent_sessions` table → AI agents (type, install path, first seen)
- `behavioral_baselines` table → normal network, normal binaries, working directories
- `events` table → installed tools (extracted from exe paths in process_exec events)
- System environment → PATH directories, OS info, username

**AI tool**: `get_system_profile` (no params)
**Code**: `internal/ai/intelligence/profile_builder.go`

### Layer 2: Context Windows (Hierarchical Rollups)

**What it is**: Time-series snapshots of system activity at multiple granularities.
**Purpose**: Summaries are **navigation indexes**, not replacements for raw data.

#### Rollup Pyramid

```
1-MIN snapshots → kept for 1 hour (60 active)
    ↓ rolled up into
1-HR summaries → kept for 24 hours (24 active)
    ↓ rolled up into
24-HR summaries → kept for 30 days (30 active)
    ↓ rolled up into
WEEKLY summaries → kept for 1 year (52 active)

Total steady-state storage: ~750 KB per host
```

#### Summary Structure

```go
type ContextSummary struct {
    // Event counts
    ProcessExecCount  int
    FileOpenCount     int
    NetConnectCount   int
    DNSQueryCount     int

    // Unique values (NEVER truncated)
    UniqueBinaries     []string
    UniqueDestinations []string
    UniqueDomains      []string
    SensitiveFiles     []string

    // Security signals
    FindingsGenerated  int
    FindingsSuppressed int
    ReconCommands      int
    CredentialAccesses int
    NewBinaries        []string
    NewDestinations    []string

    // File access quality (PATHEXT probe detection)
    FileExistsCount   int    // real file accesses
    FileNotFoundCount int    // PATHEXT probes (deduped by basename)

    // Temporal pattern
    EventSlots []int          // event counts per sub-slot

    // Activity classification
    ActivityPattern string    // "active_development", "build_or_ci", "idle", etc.

    // Active processes
    ActivePIDs     []int
    ActiveSessions []SessionSummary
    Notable        []string
}
```

**Key principles**:
- `UniqueBinaries` is NEVER truncated — full list for pattern detection
- `FileNotFoundCount` is deduped by basename (PATHEXT probes: `config.exe`, `config.bat`, `config.cmd` count as ONE probe)
- `ActivityPattern` auto-classifies the session type

**AI tool**: `get_recent_activity(granularity, count)`
**Code**: `internal/ai/intelligence/context_builder.go`, `rollup.go`

### Layer 3: Historical Intelligence (Learned Patterns)

**What it is**: Patterns learned from user actions on findings.
**Updated**: Real-time — immediately when user dismisses/allows/investigates/blocks.

```json
{
  "pattern_key": "command:cursor:reg.exe:low_context",
  "verdict": "always_benign",
  "confidence": 0.99,
  "evidence": { "dismissed": 47, "investigated": 0, "blocked": 0, "total_seen": 47 }
}
```

#### Verdict Calculation

| Evidence | Verdict | Confidence |
|----------|---------|------------|
| Any blocked | `always_malicious` | 0.95 |
| >50% investigated | `suspicious` | 0.7-0.9 |
| All dismissed, 10+ times | `always_benign` | 0.99 |
| All dismissed, 5-10 times | `always_benign` | 0.95 |
| All dismissed, 3-5 times | `likely_benign` | 0.85 |

**AI tool**: `get_learned_patterns` (no params)
**Code**: `internal/ai/intelligence/pattern_learner.go`

### False Positive Rates

Per-detection-rule accuracy from user feedback:

```json
{ "ai.persistence": 0.92, "ai.credential_access": 0.15, "ai.command_activity": 0.78 }
```

**AI tool**: `get_false_positive_rate(since)`

---

## On-Demand Micro-Context (Instant Temporal Context)

**Problem**: Background worker creates context windows every 1 minute. If user clicks "Analyze" within 30 seconds of an incident, no context window exists yet.

**Solution**: `GetOnDemandContext()` queries raw events directly from PostgreSQL for a given time range, builds a summary on the fly, and formats it as readable text.

```
User clicks "Analyze" (incident created 10 seconds ago)
    │
    ├── GetOnDemandContext(hostID, now - 5min)  → 5-min summary
    ├── GetOnDemandContext(hostID, now - 30min) → 30-min summary
    │
    ├── formatMicroContext() → human-readable text (not JSON)
    │     "Activity: active_development"
    │     "Processes: 48 executions (bash, git, go, psql)"
    │     "Files: 890 opens (885 exist, 5 not-found)"
    │
    └── Appended to dossier text before LLM call
```

**Cost**: ~4ms for both queries (2 SQL queries against events table).
**Impact**: AI response quality at 30 seconds = same as at 1 hour.

**File**: `internal/ai/intelligence/store.go` — `GetOnDemandContext()`
**File**: `internal/api/incident_ai_handler.go` — `formatMicroContext()`

---

## AI Response Quality by Time

| When user checks | Data available | AI quality |
|---|---|---|
| < 1 min | Profile + dossier + micro-context (5min+30min) | **90%** |
| 5 min | + 5 x 1-min context windows | **90%** |
| 1 hour | + hourly rollup | **95%** |
| 1 day | + 24-hr rollup + learned patterns | **95%** |

The micro-context eliminates the early-response gap that existed before.

---

## Context Optimizations Applied

### 1. Readable Micro-Context (not raw JSON)
Raw JSON wastes tokens and is harder for LLMs to reason about. Formatted as structured text matching dossier style. ~30% fewer tokens.

### 2. AI Agent Behavioral Profiles
The LLM no longer needs to INFER that "claude→bash→powershell temp script" is normal. The profile explicitly states known-benign patterns, eliminating most false positive reasoning gaps.

### 3. Confidence Calibration Note
Prevents the LLM from anchoring on high pattern-match confidence (95%) as if it means "95% likely malicious." The note explains the distinction between pattern match and actual threat probability.

### 4. Grouped Process Details
80 process entries (mostly bash.exe and conhost.exe) → 5 grouped lines with flagged processes shown in full. Massive token savings + clearer signal-to-noise.

### 5. Activity Pattern Classification
Auto-detects session type from binary mix. The LLM immediately knows "this is an active development session" instead of counting binaries manually.

### 6. Credential Redaction
Command lines are redacted before storage: `PGPASSWORD=secret` → `PGPASSWORD=***`. The AI never sees plaintext credentials in context windows, findings, or tool results.

---

## Background Workers

### Intelligence Worker (`internal/ai/intelligence/worker.go`)

| Interval | Job | Purpose |
|----------|-----|---------|
| Every 1 min | `BuildMinuteSnapshot` | Create 1-min context window |
| Every 1 hr | `RollupMinuteToHourly` | Merge 60 × 1-min → 1 × 1-hr |
| Every 1 hr | `ProfileBuilder.Build` | Rebuild system profile |
| Every 1 hr | `Rollup.Cleanup` | Delete expired windows |
| Every 24 hr | `RollupHourlyToDaily` | Merge 24 × 1-hr → 1 × 24-hr |
| Every Sunday | `RollupDailyToWeekly` | Merge 7 × 24-hr → 1 × weekly |

### Pattern Learning (real-time)

Triggered by `FindingsHandler.ResolveFinding()`:
```
User action → extract pattern key → update evidence → recalculate verdict → upsert
```

---

## Database Schema

```sql
CREATE TABLE ai_system_profiles (
    id SERIAL PRIMARY KEY,
    org_id TEXT NOT NULL, host_id TEXT NOT NULL,
    profile JSONB NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (org_id, host_id)
);

CREATE TABLE ai_context_windows (
    id SERIAL PRIMARY KEY,
    org_id TEXT NOT NULL, host_id TEXT NOT NULL,
    granularity TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL, window_end TIMESTAMPTZ NOT NULL,
    summary JSONB NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE ai_learned_patterns (
    id SERIAL PRIMARY KEY,
    org_id TEXT NOT NULL,
    pattern_key TEXT NOT NULL,
    verdict TEXT DEFAULT 'unknown',
    confidence REAL DEFAULT 0.5,
    evidence JSONB DEFAULT '{}',
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (org_id, pattern_key)
);
```

---

## File Map

```
internal/ai/intelligence/
├── types.go              # SystemProfile, ContextSummary, LearnedPattern, Evidence
├── store.go              # DB access + GetOnDemandContext + classifyActivity
├── profile_builder.go    # Layer 1 — system profile from baselines/events
├── context_builder.go    # Layer 2 — 1-min snapshots from canonical events
├── rollup.go             # Hierarchical rollup + retention cleanup
├── pattern_learner.go    # Layer 3 — real-time learning from finding actions
└── worker.go             # Background worker (1-min tick, hourly/daily jobs)

internal/ai/provider/
└── incident_prompt.go    # System prompt: safety preamble, behavioral profiles,
                          # confidence calibration, reasoning protocol, explain format

internal/ai/dossier/
└── formatter.go          # Dossier formatting: grouped process details, attack
                          # sequence, detections, timeline, network, sensitive files

internal/ai/tools/
└── tools.go              # 18 tool definitions + intelligence tool handlers

internal/api/
├── incident_ai_handler.go  # Prompt assembly, micro-context injection,
│                            # formatMicroContext(), chatWithToolLoop()
├── findings_handler.go     # Pattern learner hook on status change
└── llm_payload.go          # JSON payload builder for Ask endpoints

cmd/telemetry/main.go      # Intelligence worker startup
cmd/api/main.go             # Intelligence store + pattern learner wiring

migrations/084_ai_intelligence_layers.sql  # 3 tables
```

---

## Design Principles

1. **Summaries are navigation, not replacement** — Raw events in PG/Neo4j are never deleted by rollups. AI drills down via tools when needed.

2. **Unique values are never truncated** — Every binary, domain, destination preserved in rollups for pattern detection.

3. **Learning is real-time** — User actions update patterns immediately. No daily batch.

4. **On-demand context fills gaps** — Micro-context from raw events ensures equally good AI responses at 30 seconds as at 1 hour.

5. **Structured text over raw JSON** — Formatted context uses ~30% fewer tokens and produces better LLM reasoning.

6. **Behavioral profiles eliminate inference** — The AI KNOWS Claude Code uses PowerShell temp scripts; it doesn't have to guess.

7. **Confidence calibration prevents anchoring** — The AI understands that 95% confidence ≠ 95% malicious.

8. **Credential redaction at the agent** — Secrets never reach the DB, Neo4j, context windows, or LLM.
