# Correlic Layer Guide

**Understanding each layer's responsibilities and interactions**

This document provides a detailed breakdown of each layer in the Correlic architecture, explaining what each layer does, why it exists, and how to work with it.

---

## Layer Overview

```
┌─────────────────────────────────────────┐
│  Layer 4: Presentation (UI)             │  ← User interaction
├─────────────────────────────────────────┤
│  Layer 3: Application (Backend API)     │  ← Business logic
├─────────────────────────────────────────┤
│  Layer 2: Collection (Agent)            │  ← Data gathering
├─────────────────────────────────────────┤
│  Layer 1: Kernel (eBPF)                 │  ← Event capture
└─────────────────────────────────────────┘
```

---

## Layer 1: Kernel (eBPF Programs)

**Location:** `Correlic-agent/internal/ebpf/bpf/*.bpf.c`

### Purpose
Capture security-relevant events at the kernel level with minimal overhead.

### Responsibilities
- Attach to kernel tracepoints/kprobes
- Capture process, network, and file events
- Filter events in-kernel (reduce data volume)
- Submit events to ring buffers
- Maintain eBPF maps for state tracking

### Key Files
- `execsnoop.bpf.c` - Process execution monitoring
- `fork.bpf.c` - Process tree tracking
- `exit.bpf.c` - Process termination
- `connect.bpf.c` - Network connections
- `fileopen.bpf.c` - File access

### Technology
- **Language:** Restricted C (eBPF subset)
- **Compiler:** clang with `-target bpf`
- **Verifier:** Kernel eBPF verifier ensures safety
- **Runtime:** Kernel eBPF VM (JIT compiled)

### Important Concepts

#### Tracepoints vs. Kprobes
- **Tracepoints:** Stable kernel API, preferred
  - Example: `tp/sched/sched_process_exec`
- **Kprobes:** Dynamic instrumentation, may break across kernel versions
  - Example: `kprobe/sys_connect`

#### Ring Buffers
- Shared memory between kernel and userspace
- Lock-free, high-performance
- Events submitted via `bpf_ringbuf_output()`

#### eBPF Maps
- Key-value stores in kernel
- Used for state tracking, configuration
- Types: hash, array, LRU, ring buffer

### Limitations
- **No loops:** Must be bounded (verifier requirement)
- **Stack size:** 512 bytes max
- **Helper functions:** Only approved BPF helpers allowed
- **Memory access:** Must use `bpf_probe_read_*()` for safety

### When to Modify
- Adding new event types
- Changing event filtering logic
- Performance optimization
- Adding new fields to events

### Common Issues
- **Verifier errors:** Usually stack size or unbounded loops
- **Struct padding:** C compiler adds padding for alignment
- **BTF requirement:** Kernel must have BTF support for CO-RE

---

## Layer 2: Collection (Agent)

**Location:** `Correlic-agent/`

### Purpose
Read events from eBPF programs, parse binary data, enrich with context, and send to backend.

### Responsibilities
- Load and attach eBPF programs
- Read events from ring buffers
- Parse binary event data into Go structs
- Enrich events with /proc filesystem data
- Convert to canonical event format
- Batch and send to backend API
- Handle retries and buffering

### Key Components

#### Collectors (`internal/ebpf/*_collector.go`)
- Read from eBPF ring buffers
- Parse binary data (handle struct padding!)
- Emit Go structs

**Example:**
```go
type ExecCollector struct {
    objs      *execsnoopObjects
    eventChan chan *ExecEvent
}

func (c *ExecCollector) Start(ctx context.Context) error {
    rd, _ := ringbuf.NewReader(c.objs.Events)
    for {
        record, _ := rd.Read()
        event, _ := parseExecEvent(record.RawSample)
        c.eventChan <- event
    }
}
```

#### Runners (`internal/ebpf/*_runner.go`)
- Convert eBPF events to canonical format
- Enrich with additional data
- Send to dispatcher

**Example:**
```go
type ExecRunner struct {
    collector  *ExecCollector
    dispatcher *dispatch.Dispatcher
}

func (r *ExecRunner) Run(ctx context.Context) {
    for rawEvent := range r.collector.Events() {
        event := convertToCanonical(rawEvent)
        enrichEvent(event)
        r.dispatcher.Dispatch(event)
    }
}
```

#### Transport (`internal/transport/http.go`)
- HTTPS client for backend API
- Event batching
- Retry logic with exponential backoff
- Local buffering on network failure

### Technology
- **Language:** Go 1.26+
- **eBPF library:** cilium/ebpf
- **HTTP client:** net/http with TLS

### Important Concepts

#### Struct Padding (CRITICAL!)
C compilers add padding to align fields. Go parsing MUST account for this:

```c
// C struct
struct event {
    __u32 pid;           // 0-3
    __u32 ppid;          // 4-7
    __u32 gppid;         // 8-11
    __u32 uid;           // 12-15
    __u32 gid;           // 16-19
    __u64 timestamp_ns;  // NOT 20-27! Compiler adds 4 bytes padding
                         // Actual: 24-31 (padding at 20-23)
};
```

```go
// Go parsing
TimestampNs: littleEndian.Uint64(data[24:32]), // Skip padding!
```

See [eBPF String Fix Walkthrough](../correlic-backend/docs/ebpf-string-fix-walkthrough.md).

#### Event Enrichment
- Resolve `/proc/<pid>/exe` for full executable path
- Read `/proc/<pid>/cmdline` for command-line arguments
- Lookup `/proc/<pid>/cwd` for working directory

### When to Modify
- Adding new event types
- Changing event format
- Adding enrichment data
- Modifying transport logic

### Common Issues
- **Struct padding:** Always use `pahole` to verify C struct layout
- **Ring buffer overflow:** Increase buffer size or reduce event rate
- **Network errors:** Check TLS certificates, API key, backend availability

---

## Layer 3: Application (Backend API)

**Location:** `correlic-backend/`

### Purpose
Receive events, apply intelligent sampling, run detection rules, store in database, and provide query API.

### Responsibilities
- Authenticate agents (API key validation)
- Parse and validate incoming events
- Apply intelligent sampling (reduce 90% of data)
- Run detection rules (80+ suspicious patterns)
- Store events in PostgreSQL
- Provide query API for UI
- Manage organizations, users, alerts

### Key Components

#### Ingestion Pipeline (`internal/ingest/`)

**Sampler (`sampler.go`):**
```go
func (s *Sampler) ShouldKeep(evt *event.Event) bool {
    // 1. Always keep critical events
    if s.rules.IsAlwaysKeep(evt.Type) {
        return true
    }
    
    // 2. SECURITY: Check suspicious FIRST
    if s.rules.IsSuspicious(evt) {
        return true
    }
    
    // 3. Drop benign (only if not suspicious)
    if s.rules.IsBenignProcess(evt) {
        return false
    }
    
    // 4. Probabilistic sampling
    return rand.Float64() < s.rules.GetSampleRate(evt.Type)
}
```

**Detection Rules (`sampling_rules.go`):**
- 80+ suspicious file patterns
- High-value process monitoring
- User-defined watchlists

#### Storage (`internal/store/postgres/`)
- Event insertion
- Query optimization
- Index management

#### API Handlers (`cmd/api/main.go`)
- `POST /ingest/events` - Agent event ingestion
- `/api/v1/findings` - Detection findings
- `/api/v1/incidents` - Incident management

### Technology
- **Language:** Go 1.26+
- **Database:** PostgreSQL 14+ with JSONB
- **Router:** standard library `net/http` (`http.NewServeMux()`)
- **Driver:** pgx

### Important Concepts

#### Intelligent Sampling
**Goal:** Reduce data volume by 90% while keeping all security-critical events.

**Strategy:**
1. Always keep: privilege escalation, credential access
2. Suspicious patterns: Check BEFORE dropping benign
3. Benign processes: Drop only if not suspicious
4. Probabilistic: Sample remaining events

#### Security-First Sampling
The order matters! Check suspicious BEFORE benign:

```go
// CORRECT (security-first)
if IsSuspicious(evt) { return true }
if IsBenign(evt) { return false }

// WRONG (security hole!)
if IsBenign(evt) { return false }  // cat /etc/shadow would be dropped!
if IsSuspicious(evt) { return true }
```

#### JSONB Storage
Events stored as JSONB for flexibility:
```sql
payload JSONB NOT NULL
```

Allows querying nested fields:
```sql
WHERE payload->>'comm' = 'cat'
AND payload->>'target' LIKE '%/etc/shadow%'
```

### When to Modify
- Adding detection rules
- Changing sampling logic
- Adding API endpoints
- Database schema changes

### Common Issues
- **High database load:** Add indexes, partition tables
- **Sampling too aggressive:** Adjust sample rates
- **False positives:** Refine detection patterns

---

## Layer 4: Presentation (UI)

**Location:** `correlic-ui/`

### Purpose
Provide web interface for security analysts to view events, investigate incidents, and manage detection rules.

### Responsibilities
- Display event timeline
- Visualize process trees
- Show alerts and detections
- Provide search and filtering
- Manage detection rules
- User authentication (planned)

### Key Components
- **Event Timeline:** Chronological event view
- **Process Tree:** Parent-child visualization
- **Alert Dashboard:** Security alerts
- **Search:** Query builder and filters

### Technology
- **Framework:** React 18
- **Language:** TypeScript
- **Styling:** TailwindCSS
- **Data Fetching:** React Query
- **Visualization:** D3.js

### When to Modify
- Adding new visualizations
- Changing UI layout
- Adding features (search, filters)

---

## Cross-Layer Interactions

### Agent → Backend
- **Protocol:** HTTPS
- **Auth:** Bearer token (API key)
- **Format:** JSON
- **Batching:** Up to 100 events per request

### Backend → Database
- **Protocol:** PostgreSQL wire protocol
- **Connection:** Connection pool (pgx)
- **Transactions:** Used for consistency

### UI → Backend
- **Protocol:** HTTPS
- **Auth:** Session token (planned)
- **Format:** JSON
- **Polling:** Every 5 seconds for new events

---

## Development Workflow

### Adding a New Event Type

1. **Layer 1 (eBPF):** Create `newevent.bpf.c`
2. **Layer 2 (Agent):** Create collector and runner
3. **Layer 3 (Backend):** Add to sampling rules
4. **Layer 4 (UI):** Add visualization component

### Modifying Detection Logic

1. **Layer 3 (Backend):** Edit `sampling_rules.go`
2. **Test:** Verify with sample events
3. **Deploy:** Restart backend

### Performance Optimization

1. **Layer 1:** Reduce events submitted to ring buffer
2. **Layer 2:** Batch events, reduce enrichment
3. **Layer 3:** Optimize database queries, add indexes
4. **Layer 4:** Lazy loading, pagination

---

## Related Documentation

- [System Reference](./SYSTEM_REFERENCE.md) - Master AI context doc
- [Architecture](./ARCHITECTURE.md) - System design
- [Detection Engine](./DETECTION_ENGINE.md) - 13 rules + 11 chains
- [API Reference](./API_REFERENCE.md) - Complete endpoint reference
