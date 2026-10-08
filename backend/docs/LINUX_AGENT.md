# Linux Agent — Implementation Reference

## Overview

The Correlic Linux agent provides real-time security observability for AI agent activity using eBPF (extended Berkeley Packet Filter). eBPF programs run inside the kernel, capturing events synchronously at syscall time — PIDs are always correct, events are never lost due to async delivery, and there's zero userspace overhead at capture time.

**Key properties:**
- eBPF tracepoints for process, file, and network events — kernel-level, zero-copy
- Ring buffer delivery with backpressure (no silent drops)
- AI Session tracking via UUID — cross-PID correlation for AI agent process trees
- Shared lineage tracker with Windows/macOS agents
- Docker/container-aware AI process detection

---

## Architecture

```
                    ┌──────────────────────────────────────────┐
                    │            Linux Kernel (eBPF)           │
                    │                                          │
                    │  ┌────────────┐  ┌────────────────────┐  │
                    │  │ execsnoop  │  │ fileopen.bpf.c     │  │
                    │  │ .bpf.c    │  │ tp/syscalls/        │  │
                    │  │ tp/sched/ │  │ sys_enter_openat    │  │
                    │  │ process_  │  └────────┬───────────┘  │
                    │  │ exec      │           │              │
                    │  └─────┬─────┘  ┌────────┴───────────┐  │
                    │        │        │ connect.bpf.c      │  │
                    │  ┌─────┴─────┐  │ kprobe/sys_connect │  │
                    │  │ fork.bpf.c│  └────────┬───────────┘  │
                    │  │ exit.bpf.c│           │              │
                    │  └─────┬─────┘           │              │
                    └────────┼─────────────────┼──────────────┘
                             │ Ring Buffers     │
              ┌──────────────┼─────────────────┼──────────────┐
              │              ▼                 ▼              │
              │  Userspace Go Agent                           │
              │                                               │
              │  ┌──────────────┐  ┌──────────────┐          │
              │  │ ExecRunner   │  │ FileRunner   │          │
              │  │ + ForkRunner │  │ IsAI filter  │          │
              │  │ + ExitRunner │  │ RegisterProc │          │
              │  │ AI lineage   │  │ fallback     │          │
              │  └──────┬───────┘  └──────┬───────┘          │
              │         │                 │                   │
              │  ┌──────┴───────┐  ┌──────┴───────┐          │
              │  │ NetworkRunner│  │ DNSRunner    │          │
              │  │ Port classify│  │ Domain       │          │
              │  │ IPv4/IPv6    │  │ capture      │          │
              │  └──────┬───────┘  └──────┬───────┘          │
              │         │                 │                   │
              │         └────────┬────────┘                   │
              │                  ▼                            │
              │         ┌─────────────────┐                   │
              │         │   Dispatcher     │                   │
              │         │ (50,000 buffer)  │                   │
              │         │ → HTTP sink      │                   │
              │         └─────────────────┘                   │
              └───────────────────────────────────────────────┘
```

---

## eBPF Programs

| Program | Tracepoint/Kprobe | Events Captured | Ring Buffer |
|---------|-------------------|-----------------|-------------|
| `execsnoop.bpf.c` | `tp/sched/sched_process_exec` | Process execution | Exec ring buffer |
| `fork.bpf.c` | `tp/sched/sched_process_fork` | Process tree (parent→child) | Fork ring buffer |
| `exit.bpf.c` | `tp/sched/sched_process_exit` | Process termination | Exit ring buffer |
| `fileopen.bpf.c` | `tp/syscalls/sys_enter_openat` | File access | File ring buffer |
| `connect.bpf.c` | `kprobe/sys_connect` | Network connections | Network ring buffer |

**Key advantage over Windows ETW:** eBPF tracepoints fire **synchronously** in the process context. The PID is always correct at capture time — there's no async delivery race condition.

**BPF `ai_pids` map:** A kernel-side hash map that tracks AI process PIDs. Updated atomically from userspace. Child PIDs inherit AI status via lazy inheritance in-kernel, avoiding the race condition where a child starts before the userspace tracker registers it.

---

## Event Collection Pipelines

### Process Events (`runner.go`, `fork_runner.go`, `exit_runner.go`)

**Exec Runner (`runner.go`):**
1. Read exec event from ring buffer (PID, PPID, UID, comm, args, timestamp)
2. Resolve full executable path via `/proc/[pid]/exe` readlink
3. If readlink fails (process exited), fall back to `comm`
4. Read `/proc/[pid]/cmdline` if eBPF args are incomplete
5. **AI filtering:**
   - `tracker.IsAI(ev.PID)` — fast cached lookup
   - `tracker.RegisterProcess(ev.PID, ev.PPID, ev.Comm)` — pattern match + PPID inheritance
   - Cmdline pattern match: `tracker.CheckPattern(cmdlineStr)` → `tracker.MarkAI(ev.PID)`
   - Docker container pattern match via `DetectContainerID()` + `CheckContainerPatterns()`
6. Detect OS session ID via `/proc/[pid]/stat`
7. Detect container ID via `/proc/[pid]/cgroup`
8. Build `RawExecEvent` with `AISessionID: tracker.GetSessionID(ev.PID)`
9. Dispatch via `exechandler.Handle(raw)` → canonical `process_exec` event

**Fork Runner (`fork_runner.go`):**
1. Read fork event from ring buffer (parent PID/comm, child PID/TGID/comm)
2. `tracker.RegisterProcess(childPID, parentPID, childComm)` — critical for AI lineage inheritance
3. Skip non-AI forks
4. Build canonical event with `ai_session_id` from `tracker.GetSessionID(childPID)`
5. Emit synthetic `process_exec` events for processes that fork-without-exec

**Exit Runner (`exit_runner.go` + `exit_handler.go`):**
1. Read exit event from ring buffer (PID, PPID, comm, exit code)
2. Check `tracker.IsAI(pid)` — skip non-AI exits
3. Build canonical `process_exit` event with `ai_session_id` (BEFORE UnregisterProcess)
4. Call `tracker.UnregisterProcess(pid)` — moves PID to grace period maps

### File Events (`file_runner.go`)

1. Read file_open event from ring buffer (PID, PPID, comm, filename, flags)
2. `os.Stat()` for file size + `IsDir()` check (skip directories)
3. **AI filtering** with `RegisterProcess` fallback (same pattern as Windows)
4. Path categorisation: `.ssh` → `ssh_key`, `.aws` → `aws_credentials`, etc.
5. Build canonical `file_open` event with `ai_session_id`
6. Dispatch via `Dispatcher.Enqueue()`

### Network Events (`network_runner.go`)

1. Read connect event from ring buffer (PID, PPID, comm, dst_ip, dst_port, family)
2. **AI filtering** with `RegisterProcess` fallback
3. Port/connection categorisation (ssh, http, https, dns, etc.)
4. Build canonical `net_connect` event with `ai_session_id`
5. Dispatch via `Dispatcher.Enqueue()`

### DNS Events (`dns_runner.go`)

1. DNS events captured via eBPF or system resolver monitoring
2. AI filtering: `tracker.IsAI(pid)` or `tracker.HasAnyAI()` fallback
3. Build canonical `net_dns` event
4. Dispatch via `Dispatcher.Enqueue()`

---

## AI Session Tracking

When an AI root process is detected (e.g., Cursor, Claude Code), the lineage tracker creates a UUID session that all child processes inherit:

```
Cursor starts (PID 1000)
  → Session: ai_session_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479"
  → pidToSession[1000] = "f47ac10b-..."

  node spawned (PID 2000, PPID=1000)
    → Inherits: pidToSession[2000] = "f47ac10b-..."

    git clone (PID 3000, PPID=2000)
      → Inherits: pidToSession[3000] = "f47ac10b-..."

    curl API call (PID 4000, PPID=2000)
      → Inherits: pidToSession[4000] = "f47ac10b-..."
```

All events from PIDs 1000, 2000, 3000, 4000 share the same `ai_session_id`. The backend can correlate:
- File reads (git clone checking out files)
- Network connections (curl calling an API)
- Process executions (git, curl, npm, etc.)

**Implementation:**
- `RegisterProcess()` creates UUID for AI roots, inherits for children
- `GetSessionID(pid)` returns the session UUID (checks active + grace maps)
- Grace period: 10 seconds after process exit, session mapping preserved for late-arriving events
- All 5 runners tag events with `ai_session_id` in the Context map

**Linux vs Windows:**
- On Linux, eBPF tracepoints are synchronous — PID is always correct, so session tracking adds richer cross-PID correlation (e.g., `ai.data_exfiltration` can correlate file reads + network connections across PIDs in the same AI session)
- On Windows, ETW is asynchronous — session tracking is essential because PIDs may be stale by the time events are processed

---

## Lineage Tracker (Shared Across Platforms)

The `lineage.LineageTracker` is a singleton used by all platforms:

```go
type LineageTracker struct {
    aiPIDs          map[uint32]bool       // Active AI process PIDs
    graceAIPIDs     map[uint32]time.Time  // Recently exited (10s grace)
    pidToSession    map[uint32]string     // PID → AI session UUID
    graceSession    map[uint32]string     // Exited PID → session UUID
    sessionAIType   map[string]string     // Session UUID → ai_type
    patterns        []string              // AI process name patterns
}
```

**Key methods:**
- `RegisterProcess(pid, ppid, comm)` — checks pattern + parent inheritance, creates/inherits session
- `IsAI(pid)` — fast lookup in aiPIDs + grace map
- `GetSessionID(pid)` — returns AI session UUID from active + grace maps
- `UnregisterProcess(pid)` — moves to grace maps (session preserved for 10s)
- `CheckPattern(comm)` — case-insensitive substring match against AI patterns
- `MarkAI(pid)` — explicit marking (cmdline/container pattern match)

---

## Canonical Event Schema

All events are normalised to a common schema before dispatch:

```json
{
  "schema_version": 1,
  "id": "sha256-deterministic-id",
  "host_id": "my-host",
  "timestamp": "2026-03-18T12:00:00Z",
  "source": "kernel",
  "type": "process_exec",
  "actor": {
    "pid": 1234,
    "ppid": 1000,
    "user": "alice",
    "exe_path": "/usr/bin/curl",
    "comm": "curl",
    "cmdline": ["curl", "https://api.openai.com/v1/models"],
    "session_id": "3",
    "role": "tool"
  },
  "target": {
    "file_path": "/home/alice/.ssh/id_rsa",
    "ip": "104.18.32.47",
    "port": 443
  },
  "context": {
    "ai_session_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
    "category": "ssh_key",
    "exec_class": "primary"
  }
}
```

**Event types:** `process_exec`, `process_exit`, `file_open`, `net_connect`, `net_dns`

---

## Backend Detection Rules — Linux

All detection rules work identically on Linux and Windows thanks to path normalisation:

| Rule | Severity | Linux-specific patterns |
|------|----------|----------------------|
| `ai.file_activity` | Low | All file accesses by AI processes |
| `ai.credential_access` | Critical | `/.ssh/`, `/etc/shadow`, `/etc/passwd`, `.aws/credentials`, `.kube/config` |
| `ai.unauthorized_exec` | High | `curl`, `wget`, `nc`, `ncat`, `socat`, `nmap`, `ssh` |
| `ai.command_activity` | Low | Audit trail for all AI commands |
| `ai.data_exfiltration` | Critical | Sensitive file read + network connection correlation |
| `ai.unexpected_network` | Medium/High | Connections to unknown domains (any port) |
| `ai.persistence` | High | `/etc/cron.d/`, `/etc/systemd/`, `.bashrc`, `.profile` |
| `ai.privilege_escalation` | High | `sudo`, `su`, `pkexec`, `chroot`, `nsenter` |
| `ai.discovery` | Low | `whoami`, `uname`, `ifconfig`, `netstat`, `ps` (burst detection) |
| `ai.container_escape` | Critical | `nsenter`, mount namespace manipulation, `/proc/1/root/` access |

---

## Deployment

### Requirements
- Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- x86_64 (amd64) or arm64 (aarch64); see Architectures below
- Root or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN` capabilities
- Go 1.26+ and clang/llvm/libbpf-dev (build time)

### Architectures
The agent is built and released for linux/amd64 and linux/arm64 from the
same sources: Apple Silicon Linux VMs (Lima, OrbStack, UTM), AWS Graviton,
Raspberry Pi 5 and other arm64 hosts work with the same kernel 5.8+ and BTF
requirements (Raspberry Pi OS needs a kernel built with
`CONFIG_DEBUG_INFO_BTF=y`). `go generate ./internal/ebpf/...` emits the eBPF
objects for both architectures (`bpf2go -target amd64,arm64`) and `GOARCH`
selects the embedded set, so `GOOS=linux GOARCH=arm64 go build ./cmd/agent`
cross-compiles from an x86_64 host. CO-RE keeps the kernel-struct accesses
architecture independent; the only arch-specific code is
`bpf/arch_arm64.h`, which declares the arm64 register file for the kprobe
programs (`dns`, `bind`). arm64's generic syscall table has no `unlink(2)`,
so the unlink collector monitors `unlinkat` only there. Details:
`agent/internal/ebpf/BUILD.md`.

### Running
The agent reads one YAML file, located by `CORRELIC_CONFIG` or `--config`
(`correlic-admin bootstrap` writes it next to the certificates):
```bash
sudo CORRELIC_CONFIG=/path/to/agent.yaml ./correlic-agent
```
```yaml
backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"
api_key: "<agent key from correlic-admin create-api-key --type agent>"
tls_ca_file: "/path/certs/ca.crt"
tls_client_cert_file: "/path/certs/client.crt"
tls_client_key_file: "/path/certs/client.key"
heartbeat_interval: 30s
ebpf_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
```

### Service (systemd)
```ini
[Unit]
Description=Correlic Security Agent
After=network.target

[Service]
ExecStart=/usr/bin/correlic-agent
Environment=CORRELIC_CONFIG=/etc/correlic/agent.yaml
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_PERFMON CAP_SYS_RESOURCE
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## File Structure

```
correlic-agent/
├── cmd/agent/
│   └── platform_linux.go              # Wiring: create runners, start collectors
├── internal/
│   ├── ebpf/
│   │   ├── bpf/                       # eBPF C programs (*.bpf.c)
│   │   │   ├── execsnoop.bpf.c        # Process execution tracepoint
│   │   │   ├── fork.bpf.c             # Process fork tracepoint
│   │   │   ├── exit.bpf.c             # Process exit tracepoint
│   │   │   ├── fileopen.bpf.c         # File open tracepoint
│   │   │   └── connect.bpf.c          # Network connect kprobe
│   │   ├── runner.go                  # Exec runner (AI filtering + session tagging)
│   │   ├── fork_runner.go             # Fork runner (lineage inheritance)
│   │   ├── exit_runner.go             # Exit runner (cleanup + grace period)
│   │   ├── exit_handler.go            # Exit event → canonical event
│   │   ├── file_runner.go             # File event runner
│   │   ├── network_runner.go          # Network event runner
│   │   ├── dns_runner.go              # DNS event runner
│   │   ├── collector.go               # Ring buffer reader (exec)
│   │   ├── file_collector.go          # Ring buffer reader (file)
│   │   ├── network_collector.go       # Ring buffer reader (network)
│   │   └── exit_collector.go          # Ring buffer reader (exit)
│   ├── lineage/
│   │   └── tracker.go                 # AI process lineage + session tracking (singleton)
│   ├── exechandler/
│   │   ├── handler.go                 # Canonical event builder (shared across platforms)
│   │   └── types.go                   # RawExecEvent struct (includes AISessionID)
│   ├── event/
│   │   ├── event.go                   # Canonical event schema
│   │   ├── actor.go                   # Process actor struct
│   │   ├── target.go                  # File/network target struct
│   │   └── id.go                      # Deterministic event ID generation
│   └── dispatch/
│       └── dispatcher.go              # Buffered event dispatcher (50,000 default)
```

---

## Comparison: Linux vs Windows

| Aspect | Linux (eBPF) | Windows (ETW + USN) |
|--------|-------------|-------------------|
| Event delivery | Synchronous (in-kernel) | Asynchronous (callback) |
| PID accuracy | Always correct | May be stale (grace period needed) |
| Event loss | Ring buffer backpressure | ETW buffer overflow possible |
| File monitoring | Tracepoint (sys_enter_openat) | ETW Kernel-File + USN Journal catch-up |
| Network PID | From tracepoint context | From UserData offset 0 (not EventRecord header) |
| AI session tracking | Additive (improves correlation) | Essential (required for attribution) |
| Container support | cgroup-based detection | N/A |
| Privileges | root / CAP_BPF | Administrator |
| Path format | `/home/user/...` | `C:/Users/user/...` (normalised) |

---

## CRITICAL: Struct Padding

eBPF C structs have alignment padding that Go parsers must account for:

```c
// C struct — __u64 after 5x __u32 gets 4-byte padding
struct event {
    __u32 pid;           // 0-3
    __u32 ppid;          // 4-7
    __u32 gppid;         // 8-11
    __u32 uid;           // 12-15
    __u32 gid;           // 16-19
    // 4 bytes padding   // 20-23  ← DO NOT SKIP THIS
    __u64 timestamp_ns;  // 24-31
    char  comm[16];      // 32-47
    char  filename[256]; // 64-319
};
```

Use `pahole` to verify layout before parsing. See `docs/ebpf-string-fix-walkthrough.md` for a real-world bug caused by incorrect struct offsets.
