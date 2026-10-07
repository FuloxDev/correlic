# Correlic Agent — Claude Code Context

## Purpose
Runs on monitored Linux hosts. Loads eBPF programs into the kernel, reads events from ring buffers, parses/enriches them, and ships to the backend API over HTTPS.

## Tech Stack
- Go 1.21+, cilium/ebpf, libbpf
- Requires Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`)
- Needs root / CAP_BPF

## Directory Structure
```
Correlic-agent/
├── cmd/agent/              # Entry point
├── internal/
│   ├── ebpf/
│   │   ├── bpf/           # eBPF C programs (*.bpf.c)
│   │   ├── *_collector.go # Read ring buffers, parse binary → Go struct
│   │   └── *_runner.go    # Convert to canonical event, enrich, dispatch
│   ├── collect/           # Collection orchestration
│   ├── dispatch/          # Event dispatcher
│   ├── transport/         # HTTPS client to backend
│   ├── event/             # Canonical event types
│   ├── procmon/           # /proc filesystem monitoring
│   ├── identity/          # Host/agent identity
│   ├── approvals/         # Event approval logic
│   ├── ai/                # AI process tracking
│   ├── scanner/           # Process scanner
│   ├── notify/            # Notifications
│   ├── config/            # Configuration
│   └── ...
└── docs/                  # Agent-specific docs
```

## eBPF Programs (bpf/*.bpf.c)
| File               | Tracepoint                      | Captures              |
|--------------------|---------------------------------|-----------------------|
| execsnoop.bpf.c    | tp/sched/sched_process_exec     | Process execution     |
| fork.bpf.c         | tp/sched/sched_process_fork     | Process tree          |
| exit.bpf.c         | tp/sched/sched_process_exit     | Process termination   |
| connect.bpf.c      | kprobe/sys_connect              | Network connections   |
| fileopen.bpf.c     | tp/syscalls/sys_enter_openat    | File access           |

## CRITICAL: Struct Padding
C compiler adds padding for alignment. Go parsing MUST account for it.

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
    char  pcomm[16];     // 48-63
    char  filename[256]; // 64-319
    __s32 retval;        // 320-323
};
```
Use `pahole` to verify layout before parsing. See `docs/` for eBPF string fix walkthrough.

## AI Process Tracking
The agent has special logic for tracking AI processes (e.g., `cursor`, `python` subprocesses):
- **Kernel side**: BPF `ai_pids` map with lazy inheritance — child PIDs adopted atomically in-kernel
- **Userspace side**: `RegisterProcess(pid)` fallback for race conditions (fork before connect event)
- Documented in `internal/ai/` and the backend `docs/ai_process_tracking.md`

## Running
```bash
export CORRELIC_API_KEY="your-key"
export CORRELIC_API_URL="https://localhost:8080"
sudo -E go run ./cmd/agent

# Tests
go test ./...
```

## Key Files
- Entry: `cmd/agent/main.go`
- Collectors: `internal/ebpf/*_collector.go`
- Runners: `internal/ebpf/*_runner.go`
- Transport: `internal/transport/http.go`
- Event types: `internal/event/`

## Common Issues
- **Verifier error**: stack overflow (512B limit) or unbounded loop in BPF C
- **Struct corruption**: wrong byte offsets in Go parser — use `pahole` to check
- **Ring buffer drops**: increase buffer size or reduce event rate
- **TLS errors**: check cert validity and API key
