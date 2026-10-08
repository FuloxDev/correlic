# macOS Agent — Platform Expansion

## Architecture

```
                    Linux                              macOS (MVP)                    macOS (Phase 2)
                    ─────                              ───────────                    ───────────────
Process exec    eBPF tracepoint (sched_process_exec)   kqueue EVFILT_PROC NOTE_EXEC   ESF ES_EVENT_TYPE_NOTIFY_EXEC
Process exit    eBPF tracepoint (sched_process_exit)   kqueue EVFILT_PROC NOTE_EXIT   ESF ES_EVENT_TYPE_NOTIFY_EXIT
File open       eBPF tracepoint (sys_enter_openat)     FSEvents polling (2s)          ESF ES_EVENT_TYPE_NOTIFY_OPEN
Network         eBPF kprobe (sys_connect)              lsof -i polling (2s)           lsof -i polling (2s)*
DNS             eBPF (net_dns)                         Deferred                       Deferred
Fork            eBPF tracepoint (sched_process_fork)   kqueue EVFILT_PROC NOTE_FORK   ESF ES_EVENT_TYPE_NOTIFY_FORK

* ESF has no network events — lsof stays even in Phase 2 unless Network Extension added.
```

## Key Design Decisions

- **Go build tags** (`//go:build linux` / `//go:build darwin`) separate platform code in a single repo
- **Shared packages** (`lineage`, `classify`, `exechandler`, `procinfo`, `pathfilter`, `docker`) are platform-agnostic — imported by both eBPF and darwin collectors
- **Backward-compatible shims** in `internal/ebpf/` re-export extracted types via type aliases (`type X = pkg.X`) and variable re-exports (`var F = pkg.F`) — all existing Linux call sites unchanged
- **Single ProcCollector** on macOS handles exec, exit, and fork — single channel consumer (ExecRunner demuxes by event type). Avoids Go channel single-reader problem.
- **FSEvents polling** (not cgo FSEventStream) for MVP — no Apple entitlement needed, pure Go, simpler build
- **lsof polling** for network — deduplicates across poll cycles with `pid:ip:port` keys
- **Backend needs zero changes** — Source field is a plain string ("kqueue", "fsevents", "lsof" all accepted), event types are identical, all 9 detection rules operate on type + actor/target fields
- **macOS file_open has no PID attribution** in MVP (polling can't determine which process accessed a file) — events attributed to "any AI active" heuristic. Phase 2 ESF provides per-event PID.

## Extracted Shared Packages (Step 1)

| Package | Extracted From | Purpose |
|---------|---------------|---------|
| `internal/lineage/` | `ebpf/lineage.go` | LineageTracker singleton, pattern match + parent inheritance + AI session UUID + 10s grace period |
| `internal/classify/` | `ebpf/classification.go` | CheckRole() — agent/shell/tool classification |
| `internal/exechandler/` | `ebpf/exec_handler.go` | ExecHandler + RawExecEvent → canonical event.Event |
| `internal/procinfo/` | `ebpf/context_helpers.go` | DetectContainerID, DetectSessionID, ReadProcCmdline (platform-split) |
| `internal/pathfilter/` | `ebpf/file_runner.go` | ShouldIgnorePath (platform-split), CategorizeCredentialPath |
| `internal/docker/` | `ebpf/docker_resolver.go` | Docker socket resolver (container ID → name/image) |

## macOS-Specific Files

| File | Purpose |
|------|---------|
| `internal/darwin/proc_collector.go` | kqueue EVFILT_PROC — watches registered PIDs for exec/exit/fork |
| `internal/darwin/fsevents_collector.go` | Polls ~/.ssh, ~/.aws, ~/.kube, etc. for mtime changes |
| `internal/darwin/network_collector.go` | `lsof -i -n -P` polling with dedup |
| `internal/darwin/exec_runner.go` | Demuxes ProcCollector events → exec handler + exit dispatch + fork logging |
| `internal/darwin/file_runner.go` | FSEvents → canonical file_open events with pathfilter |
| `internal/darwin/network_runner.go` | lsof → canonical net_connect events with lineage filter |
| `internal/darwin/scanner.go` | `ps -eo pid,ppid,comm,args` + BFS to find AI roots + descendants |
| `internal/compat/compat_common.go` | Shared Check/Result types, FormatReport, LogReport |
| `internal/compat/compat_darwin.go` | macOS version, root, kqueue, FSEvents, lsof, ESF checks |
| `internal/procinfo/procinfo_darwin.go` | getsid(2) for session ID, `ps -p` for cmdline |
| `internal/pathfilter/ignore_darwin.go` | macOS noise paths (/System, /Library/Caches, .DS_Store, etc.) |
| `internal/hostid/path_darwin.go` | `/Library/Application Support/Correlic` |
| `cmd/agent/platform_darwin.go` | macOS startup: scanner, kqueue, FSEvents, lsof runners |
| `cmd/agent/platform_linux.go` | Linux startup: eBPF runners, /proc scanner, Docker resolver |

## Config (macOS-specific fields)

```yaml
# macOS-specific (ignored on Linux)
poll_interval: 2s               # lsof/fsevents polling interval
fsevents_watch_paths:            # Additional directories to watch
  - /custom/secrets
esf_enabled: false               # Phase 2: use ESF when entitlement available
```

## Build Tags Applied

- **43 files in `internal/ebpf/`** — `//go:build linux` (all non-shim files)
- **12 generated `*_x86_bpfel.go`** — changed from `//go:build 386 || amd64` to `//go:build linux && (386 || amd64)`
- **5 shim files** — no build tag (platform-agnostic re-exports)
- **`internal/compat/compat.go`** — `//go:build linux`
- **`internal/scanner/proc.go`** — `//go:build linux`
- **All 5 `internal/procmon/*.go`** — `//go:build linux`

## Detection Rule Coverage (MVP)

| Rule | Linux Source | macOS MVP Source | Works? |
|------|-------------|-----------------|--------|
| ai.credential_access | file_open (eBPF) | file_open (FSEvents) | Yes |
| ai.unauthorized_exec | process_exec (eBPF) | process_exec (kqueue) | Yes |
| ai.excessive_writes | file_open (eBPF) | file_open (FSEvents) | Yes |
| ai.data_exfiltration | net_connect (eBPF) | net_connect (lsof) | Yes |
| ai.unexpected_network | net_connect (eBPF) | net_connect (lsof) | Yes |
| ai.suspicious_dns | net_dns (eBPF) | — | **No (deferred)** |
| ai.persistence | file+exec (eBPF) | file+exec (kqueue+FSEvents) | Yes |
| ai.privilege_escalation | process_exec (eBPF) | process_exec (kqueue) | Yes |
| ai.code_tampering | file_open (eBPF) | file_open (FSEvents) | Yes |

**MVP: 8/9 rules functional.** Only `ai.suspicious_dns` deferred (no DNS hook without ESF or Network Extension).

## Build Commands

```bash
# Linux (unchanged)
GOOS=linux GOARCH=amd64 go build -o correlic-agent-linux ./cmd/agent

# macOS MVP (no cgo needed)
GOOS=darwin GOARCH=arm64 go build -o correlic-agent-darwin ./cmd/agent

# macOS ESF (Phase 2, requires Xcode + cgo)
CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -tags esf -o correlic-agent-darwin-esf ./cmd/agent
```

## Support status

macOS is a best-effort preview, built from source. The project does not
publish macOS binaries: a signed and notarized build, and the Endpoint
Security entitlement below, both require a paid Apple Developer Program
membership (renewed yearly, Organization account for the entitlement) that
the project does not maintain. Contributions that keep the kqueue/FSEvents
path working are welcome, but Linux is the supported platform.

Recommended setup on a Mac:

- Run the backend and dashboard with Docker (`install/docker-compose.yml` or
  the all-in-one image).
- Run the coding agent inside a Linux VM or container (Lima, OrbStack, UTM,
  a devcontainer) and install the Linux agent there. A Docker container
  cannot observe Cursor or Claude Code running on the macOS host.
- Or build the macOS agent from source for the polling collectors above,
  accepting the limitations below.

## Phase 2: ESF (Endpoint Security Framework)

Implemented behind the `esf` build tag (`agent/internal/darwin/esf/`, wired in
`agent/cmd/agent/platform_darwin_esf.go`) and compiled in CI so it does not
rot. An esf-tagged binary opens an Endpoint Security client at startup and
falls back to the kqueue/FSEvents collectors when the entitlement, root or
Full Disk Access is missing. To actually run it you need your own Apple
Developer Program Organization account, Apple's approval of the
`com.apple.developer.endpoint-security.client` entitlement, a Developer ID
certificate and a provisioning profile; then sign the binary with
`agent/build/correlic-agent.entitlements`. None of that is provided or
supported by the project.

## Known Limitations (MVP)

1. **No PID on file events** — FSEvents polling doesn't know which process touched the file. Events attributed to "any AI tracked" heuristic. ESF fixes this.
2. **No PPID on exec events** — kqueue EVFILT_PROC gives PID but not parent PID. We use `ps` or sysctl to look it up, which may race for short-lived processes.
3. **No DNS monitoring** — requires ESF or Network Extension.
4. **Polling latency** — FSEvents and lsof poll every 2s vs eBPF's real-time. Short-lived connections or file accesses may be missed between cycles.
5. **Docker on macOS** — Docker Desktop runs a Linux VM. `DockerResolver` returns nil on macOS (no cgroups). Container name resolution deferred to Phase 2.
