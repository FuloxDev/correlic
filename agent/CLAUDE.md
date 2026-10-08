# Correlic Agent — Claude Code Context

## Purpose
Runs on monitored hosts. On Linux it loads eBPF programs into the kernel, reads events from ring buffers, parses/enriches them, attributes them to AI process sessions and ships them to the backend over HTTPS (macOS: kqueue/FSEvents/ESF, Windows: ETW).

## Tech Stack
- Go 1.26+, cilium/ebpf, libbpf headers, clang
- Requires Linux 5.8+ with BTF (`/sys/kernel/btf/vmlinux`), on x86_64 or arm64 (aarch64)
- Needs root / CAP_BPF (+ CAP_PERFMON)

## Directory Structure
```
agent/
├── cmd/agent/              # Entry point (main.go), per-platform wiring (platform_*.go), runtime.go (shutdown, enforcer)
├── internal/
│   ├── ebpf/
│   │   ├── bpf/           # eBPF C programs (*.bpf.c) + vmlinux.h
│   │   ├── *_collector.go # Read ring buffers, parse binary → Go struct
│   │   ├── *_runner.go    # Filter to AI lineage, enrich, dispatch canonical + telemetry events
│   │   └── BUILD.md       # Program table, generate/build instructions
│   ├── lineage/           # AI session tracking (pattern matching + parent inheritance)
│   ├── patterns/          # Fetch/refresh/cache of AI patterns from the backend
│   ├── scanner/           # Startup /proc scan of already-running AI trees
│   ├── exechandler/       # Shared raw exec → canonical event conversion
│   ├── dispatch/          # Buffered dispatcher + HTTP ingest sink (retry/backoff)
│   ├── telemetry/         # Telemetry batcher (/telemetry)
│   ├── heartbeat/         # Heartbeat runner (/heartbeat)
│   ├── health/            # Throttled WARN state for backend/auth failures
│   ├── transport/         # HTTPS client to backend (API key + optional mTLS)
│   ├── enforcer/          # Soft-block rules (kill on match) + rule sync
│   ├── config/            # agent.yaml loading + validation
│   ├── logging/           # slog level handling
│   ├── identity/, hostid/ # Agent id / host id + state dir
│   ├── darwin/, windows/  # Non-Linux collectors
│   └── ...
```

## eBPF Programs (internal/ebpf/bpf/*.bpf.c)
| File             | Attach point                                      | Captures                       | Config key                |
|------------------|---------------------------------------------------|--------------------------------|---------------------------|
| execsnoop.bpf.c  | tp/sched/sched_process_exec (+ execve argv tps)   | Process execution              | process_exec_enabled      |
| exit.bpf.c       | raw_tracepoint/sched_process_exit                 | Task exit (pid, tid, exit code) | always with exec         |
| fork.bpf.c       | raw_tracepoint/sched_process_fork + sched_process_exit | Process tree (tgid-keyed) | fork_monitor_enabled      |
| connect.bpf.c    | tp/syscalls/sys_enter_connect                     | Outbound connections           | network_monitor_enabled   |
| fileopen.bpf.c   | tp/syscalls/sys_enter_openat                      | File access                    | file_monitor_enabled      |
| dns.bpf.c        | kprobe/udp_sendmsg (port 53)                      | DNS queries                    | dns_monitor_enabled       |
| bind.bpf.c       | kprobe/inet_listen                                | Listening sockets              | bind_monitor_enabled      |
| unlink.bpf.c     | tp/syscalls/sys_enter_unlink(at)                  | File deletions                 | unlink_monitor_enabled    |
| setuid.bpf.c     | tp/syscalls/sys_enter_setuid/setgid/setres*       | Privilege changes              | setuid_monitor_enabled    |

Generated `*_x86_bpfel.{go,o}` and `*_arm64_bpfel.{go,o}` (one `go generate`, `bpf2go -target amd64,arm64`; `GOARCH` picks the set) are git-ignored: run `go generate ./internal/ebpf/...` (with `CPATH=<libbpf include dir>` if the headers are not on the default path) before building. See `internal/ebpf/BUILD.md`.

Both linux/amd64 and linux/arm64 are supported from the same sources and the same x86-generated `vmlinux.h` (CO-RE relocates every kernel-struct access by name). The kprobe programs (`dns`, `bind`) include `bpf/arch_arm64.h` after `vmlinux.h` and before `bpf_tracing.h`: it declares `struct user_pt_regs` so `PT_REGS_*` / `BPF_KPROBE` compile for arm64. Never use the `*_CORE` / `*_SYSCALL` register macros. arm64 has no `unlink(2)` syscall, so `unlink_collector.go` skips the missing `sys_enter_unlink` tracepoint and monitors `unlinkat` only.

## CRITICAL: Struct Padding
C compiler adds padding for alignment. Go parsing MUST account for it.

```c
// C struct — __u64 after 5x __u32 gets 4-byte padding
struct fork_event {
    __u32 parent_pid;    // 0-3
    __u32 parent_tgid;   // 4-7
    __u32 child_pid;     // 8-11
    __u32 child_tgid;    // 12-15
    __u32 uid;           // 16-19
    // 4 bytes padding   // 20-23  ← DO NOT SKIP THIS
    __u64 timestamp_ns;  // 24-31
    __u64 clone_flags;   // 32-39
    char  parent_comm[16]; // 40-55
    char  child_comm[16];  // 56-71
};
```
Use `pahole` to verify layout before parsing. `exit_collector_test.go` / `fork_collector_test.go` pin the offsets.

## Exit events are per task
`sched_process_exit` fires for every thread. The exit program emits `pid` (tgid) and `tid`; only `tid == pid` is a process exit (dispatch `process_exit`, unregister from lineage). Never unregister a PID on a thread exit.

## AI Process Tracking (internal/lineage)
- Patterns come from the backend (`GET /api/v1/ai/patterns`), are refreshed every 5 min and cached in the state dir (`/var/lib/correlic/ai_patterns.json`) so detection works at boot without the backend. Patterns shorter than 3 chars or containing a dot are ignored for process matching.
- Matching is **whole-token**. Identity tokens (comm, exe path, argv[0]) match when the token or any of its path components equals the pattern or starts with it followed by `-`, `.` or `_`. Arguments (argv[1..]) match only on their final path component (`aider`, `@anthropic-ai/claude-code`), or on a directory component when the argument is an existing regular file (`node .../claude-code/cli.js`), so `git checkout claude/feature` and `ls /tmp/claude-0/x` are not AI processes. The joined command line is never substring-matched (`cc -o optimized` does not match `zed`).
- **Inheritance first**: a child of a process in an AI session always joins that session, even if its own name matches a pattern. Roots (direct matches without an AI parent) open a new session UUID with `ai_type` = matched pattern.
- Every event of an AI tree carries `context.ai_session_id`, `context.is_ai=true` and `context.ai_type` (use `tracker.Annotate(ctx, pid)`); this includes the startup `/proc` scan.
- Exited PIDs stay matchable for a 10 s grace period for late-arriving events.

## Configuration
`agent.yaml` is found via `--config <path>` (also `-config`), else `$CORRELIC_CONFIG`, else `agent.yaml` next to the executable, else `~/.correlic/agent.yaml`. An explicit path must exist and parse. Unknown keys are rejected; the removed keys (`approvals_*`, `notify_enabled`, `disable_proc_fallback`, `process_exec_interval`, `process_exec_emit_initial`, `esf_enabled`, `service_name`) log a WARN and are ignored.

Keys: `backend_url`, `telemetry_url`, `api_key` (agent-type key), `tls_ca_file`, `tls_client_cert_file`, `tls_client_key_file`, `allow_insecure_http` (https is required otherwise), `profile`, `log_level` (debug|info|warn|error), `heartbeat_interval` (default 30s, min 10s), `ebpf_enabled`, `process_exec_enabled`, `file_monitor_enabled`, `network_monitor_enabled`, `dns_monitor_enabled`, `bind_monitor_enabled`, `unlink_monitor_enabled`, `setuid_monitor_enabled`, `fork_monitor_enabled`, `block_enabled`, `block_sync_interval`, `block_emergency_bypass`, `etw_enabled`, `poll_interval`, `fsevents_watch_paths`, `correlic_api_url`.

Environment variables actually read:
- `CORRELIC_CONFIG` — config path (overridden by `--config`)
- `CORRELIC_AGENT_ID` — fixed agent id (else `.correlic-agent-id` next to the config / in `$HOME`)
- `AGENT_DISPATCH_BUFFER` (alias `DISPATCH_BUFFER_SIZE`), `AGENT_EXEC_RATE_LIMIT`, `AGENT_NET_ACCEPT_RATE_LIMIT`, `AGENT_EXIT_RATE_LIMIT`, `AGENT_EXEC_DEDUPE_WINDOW_MS` — dispatcher volume control (see `.env.example`)

## Backend contract
- API key type `agent`: allowed on API plane `POST /heartbeat`, `POST /telemetry`, `GET /api/v1/ai/patterns`, `/approvals/*`, `/agent/*`; telemetry plane `/ingest/events`, `/telemetry`, `/agent/*`.
- Heartbeats (`model.Heartbeat`) every `heartbeat_interval`; the first one is sent immediately and binds the mTLS cert to the agent id.
- 401/403 from any endpoint are permanent: the batch is dropped and `internal/health` logs one WARN per minute per component ("backend rejected the agent API key"). 5xx/network errors are retried with exponential backoff (1s..30s) from a bounded queue.

## Running
```bash
# config written by the installer (install/, correlic-admin bootstrap)
sudo ./correlic-agent --config /etc/correlic/agent.yaml
sudo CORRELIC_CONFIG=/etc/correlic/agent.yaml go run ./cmd/agent
./correlic-agent check-compat

# Build / tests
CPATH=<libbpf include> go generate ./internal/ebpf/...
go build ./... && go vet ./... && go test -race ./...
GOOS=linux GOARCH=arm64 go build ./... && GOOS=linux GOARCH=arm64 go vet ./...   # arm64 cross build (objects already generated)
GOOS=darwin GOARCH=arm64 go build ./... && GOOS=windows GOARCH=amd64 go build ./...
# macOS with Endpoint Security (compile check only; needs a Mac with Xcode)
SDKROOT=$(xcrun --sdk macosx --show-sdk-path) CGO_ENABLED=1 go build -tags esf ./cmd/agent
```
On macOS an `esf`-tagged binary tries Endpoint Security first (`platform_darwin_esf.go`) and falls back to kqueue/FSEvents/lsof when the entitlement, root or Full Disk Access is missing; builds without the tag always poll. Running the ESF path needs the `com.apple.developer.endpoint-security.client` entitlement, which Apple only grants to a paid Developer Program Organization account, so the project does not ship it: macOS is a best-effort, build-from-source preview (see `backend/docs/MACOS_AGENT.md`).
Shutdown: SIGTERM cancels the context; main waits up to 10 s for runners, the batcher, the ingest sink and the heartbeat (stopping/stopped) to drain.

## Key Files
- Entry: `cmd/agent/main.go` (config, heartbeat, patterns, batcher, sink), `cmd/agent/runtime.go` (goroutine tracking, enforcer wiring, `--config` parsing)
- Collectors: `internal/ebpf/*_collector.go`
- Runners: `internal/ebpf/*_runner.go` (+ `block.go` for soft-block checks)
- Lineage: `internal/lineage/tracker.go`
- Transport: `internal/transport/http.go` (`errors.go`: IsAuthError/IsPermanent)
- Event types: `internal/event/`

## Common Issues
- **Verifier error**: stack overflow (512B limit), unbounded loop, or CO-RE field missing on this kernel — `go test -run TestLoadBPFObjects -v ./internal/ebpf/`
- **Struct corruption**: wrong byte offsets in Go parser — use `pahole` to check
- **Ring buffer drops**: increase buffer size or reduce event rate
- **"backend rejected the agent API key"**: `api_key` in agent.yaml is not an agent-type key for this org — rotate it with correlic-admin
- **TLS errors**: check cert validity; http:// URLs need `allow_insecure_http: true`
