# macOS Agent — Platform Expansion

## Architecture

```
                    Linux                              macOS (polling)                macOS (eslogger, 13+)        macOS (native ESF, esf tag)
                    ─────                              ───────────────                ─────────────────────        ───────────────────────────
Process exec    eBPF tracepoint (sched_process_exec)   kqueue EVFILT_PROC NOTE_EXEC   eslogger exec (real PPID)    ESF ES_EVENT_TYPE_NOTIFY_EXEC
Process exit    eBPF tracepoint (sched_process_exit)   kqueue EVFILT_PROC NOTE_EXIT   eslogger exit                ESF ES_EVENT_TYPE_NOTIFY_EXIT
File open       eBPF tracepoint (sys_enter_openat)     FSEvents polling (2s)          eslogger open (real PID)     ESF ES_EVENT_TYPE_NOTIFY_OPEN
Network         eBPF kprobe (sys_connect)              lsof -i polling (2s)           lsof -i polling (2s)*        lsof -i polling (2s)*
DNS             eBPF (net_dns)                         Deferred                       None                         ESF NOTIFY_LOOKUP (macOS 12+ SDK)
Fork            eBPF tracepoint (sched_process_fork)   kqueue EVFILT_PROC NOTE_FORK   eslogger fork                not subscribed

* Endpoint Security has no network events — lsof stays in every macOS configuration unless a Network Extension is added.
```

At startup the agent tries these in order: native ESF (esf-tagged, entitled
build only), then `/usr/bin/eslogger` (macOS 13+, root, Full Disk Access,
`eslogger_enabled`), then the pollers. The first two feed the same runners
(`internal/darwin/esevents`); see "Endpoint Security via eslogger" below.

## Key Design Decisions

- **Go build tags** (`//go:build linux` / `//go:build darwin`) separate platform code in a single repo
- **Shared packages** (`lineage`, `classify`, `exechandler`, `procinfo`, `pathfilter`, `docker`) are platform-agnostic — imported by both eBPF and darwin collectors
- **Backward-compatible shims** in `internal/ebpf/` re-export extracted types via type aliases (`type X = pkg.X`) and variable re-exports (`var F = pkg.F`) — all existing Linux call sites unchanged
- **Single ProcCollector** on macOS handles exec, exit, and fork — single channel consumer (ExecRunner demuxes by event type). Avoids Go channel single-reader problem.
- **FSEvents polling** (not cgo FSEventStream) for MVP — no Apple entitlement needed, pure Go, simpler build
- **lsof polling** for network — deduplicates across poll cycles with `pid:ip:port` keys
- **Backend needs zero changes** — Source field is a plain string ("kqueue", "fsevents", "lsof" all accepted), event types are identical, all 9 detection rules operate on type + actor/target fields
- **macOS file_open has no PID attribution** on the polling path (FSEvents can't determine which process accessed a file) — events attributed to "any AI active" heuristic. Endpoint Security (eslogger or native ESF) provides per-event PID.
- **Endpoint Security without an entitlement** — `/usr/bin/eslogger` (macOS 13+) is Apple's own entitled Endpoint Security client; the agent runs it as a child process and parses its JSON Lines output. The parser and process supervisor (`internal/darwin/eslogger`) have no build tag, so they are unit-tested on Linux with a fake eslogger script.
- **One set of Endpoint Security runners** (`internal/darwin/esevents`, no build tag) consumes an `EventSource` (`Events() <-chan Event`); the native cgo client and the eslogger collector both implement it, so the exec/file/DNS logic is written and tested once.

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
| `internal/darwin/esevents/` | Shared Endpoint Security event shape, per-runner fanout and the exec/exit/fork, file and DNS runners (no build tag; tested on Linux) |
| `internal/darwin/eslogger/` | `/usr/bin/eslogger` collector: tolerant JSON Lines parser + supervised child process with restart/backoff (no build tag; `Available` is darwin-only) |
| `internal/darwin/esf/` | Native Endpoint Security client (cgo, `esf` build tag) feeding the same runners |
| `internal/compat/compat_common.go` | Shared Check/Result types, FormatReport, LogReport |
| `internal/compat/compat_darwin.go` | macOS version, root, kqueue, FSEvents, lsof, ESF and eslogger checks (`check-compat` says which path will be used) |
| `internal/procinfo/procinfo_darwin.go` | getsid(2) for session ID, `ps -p` for cmdline |
| `internal/pathfilter/ignore_darwin.go` | macOS noise paths (/System, /Library/Caches, .DS_Store, etc.) |
| `internal/hostid/path_darwin.go` | `/Library/Application Support/Correlic` |
| `cmd/agent/platform_darwin.go` | macOS startup: ESF → eslogger → kqueue/FSEvents order, scanner, lsof runner |
| `cmd/agent/platform_linux.go` | Linux startup: eBPF runners, /proc scanner, Docker resolver |

## Config (macOS-specific fields)

```yaml
# macOS-specific (ignored on Linux)
eslogger_enabled: true           # Endpoint Security events via /usr/bin/eslogger on macOS 13+
                                 # (root + Full Disk Access); default true, falls back to polling
poll_interval: 2s                # lsof (always) and FSEvents (polling path) interval
fsevents_watch_paths:            # Additional directories to watch (polling path only)
  - /custom/secrets
```

`esf_enabled` was removed: an esf-tagged build always tries the native client
first and the key is ignored with a warning.

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

**MVP: 8/9 rules functional.** Only `ai.suspicious_dns` deferred (no DNS hook without the native ESF client or a Network Extension; eslogger has no DNS event either).

With eslogger (macOS 13+) the same 8 rules run on `process_exec`/`process_exit`
(`source: kernel`, from the shared exec handler) and `file_open`
(`source: eslogger`) events that carry the real PID and AI session, so file
findings name the process that opened the file instead of "some AI process".

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
publish macOS binaries: a signed and notarized build, and the native
Endpoint Security entitlement below, both require a paid Apple Developer
Program membership (renewed yearly, Organization account for the
entitlement) that the project does not maintain. Since macOS 13 the agent
nevertheless gets Endpoint Security events with real PIDs, in real time,
through Apple's own `eslogger` tool (next section) with no Apple account at
all; only network connections stay on lsof polling. Contributions that keep
the eslogger and kqueue/FSEvents paths working are welcome, but Linux is the
supported platform and the only one with a CI runtime.

Recommended setup on a Mac:

- Run the backend and dashboard with Docker (`install/docker-compose.yml` or
  the all-in-one image).
- Build the macOS agent from source and run it as root with Full Disk Access
  (see below) for Endpoint Security events via eslogger; the polling
  collectors are the automatic fallback.
- Or run the coding agent inside a Linux VM or container (Lima, OrbStack,
  UTM, a devcontainer) and install the Linux agent there for the full eBPF
  feature set (network with PIDs, DNS, block rules). A Docker container
  cannot observe Cursor or Claude Code running on the macOS host.

## Endpoint Security via eslogger (free, macOS 13+)

Since macOS 13 (Ventura) Apple ships `/usr/bin/eslogger`, a command-line
Endpoint Security client that is already entitled and prints one JSON object
per event for the events named on its command line. The agent runs it as a
child process (`sudo eslogger exec exit fork open`, in effect) and parses its
output (`agent/internal/darwin/eslogger`), so a Mac gets Endpoint Security
events without the entitlement, a Developer ID certificate or an Apple
Developer Program account. It is tried after the native ESF client and before
the polling collectors (`agent/cmd/agent/platform_darwin.go`).

### What it gives

- `process_exec` and `process_exit` with the real PID, PPID, UID, executable
  path and argv (`eslogger exec exit`), plus `fork` so a child of an AI
  process joins its session as soon as it exists, before it execs.
- `file_open` with the PID of the process that opened the file
  (`eslogger open`, requested only when `file_monitor_enabled` is true),
  which replaces the FSEvents poller's "any AI process is running" guess.
- Real-time delivery instead of a 2 s poll. The one-shot `ps` scan still
  registers AI trees that were already running when the agent started.
- The same AI lineage filtering, canonical events and telemetry as the
  native ESF client: both feed the runners in `internal/darwin/esevents`.
  File and exit events carry `source: eslogger`; exec events go through the
  shared exec handler (`source: kernel`). The backend does not care.

### What it does not give

- Network: Endpoint Security has no connection events, so `net_connect`
  stays on `lsof` polling (`network_monitor_enabled`, `poll_interval`).
- DNS: none. eslogger's `lookup` event is a file-system path lookup, not a
  DNS query, and is deliberately not mapped; `dns_monitor_enabled` logs that
  it has no effect.
- Block rules: the enforcer is not wired into the macOS runners.
- Apple's performance guarantees: see the caveats below.

### Requirements

- macOS 13 or newer (`/usr/bin/eslogger` exists; checked with
  `kern.osproductversion`).
- The agent runs as root (`sudo ./correlic-agent --config agent.yaml`).
- Full Disk Access for the *responsible process*, which is how macOS (TCC)
  authorizes Endpoint Security clients. The agent is the responsible
  process of the eslogger it starts, but TCC attributes a terminal run to
  the terminal:
  - Terminal run: System Settings > Privacy & Security > Full Disk Access,
    add Terminal.app (or iTerm, VS Code's terminal, ...) and switch it on,
    then `sudo ./correlic-agent --config agent.yaml` from that terminal.
    Over SSH, enable "Allow full disk access for remote users" under
    System Settings > General > Sharing > Remote Login (the "i" button).
  - launchd daemon: the responsible process is the agent binary itself.
    In Full Disk Access click "+", press Cmd-Shift-G, enter the binary's
    path (for example `/usr/local/bin/correlic-agent`) and switch it on,
    then load a `/Library/LaunchDaemons/com.correlic.agent.plist` whose
    `ProgramArguments` are `correlic-agent --config /etc/correlic/agent.yaml`
    with `RunAtLoad` and `KeepAlive` set:
    `sudo launchctl bootstrap system /Library/LaunchDaemons/com.correlic.agent.plist`.
    Re-check the grant after replacing the binary: macOS ties it to the
    file's code identity, and an unsigned rebuild can lose it.
- `eslogger_enabled: true` in `agent.yaml` (the default).

When any of these is missing the agent logs exactly one WARN
(`eslogger unavailable` or `eslogger failed to start`, with
`remediation="run as root; grant correlic-agent Full Disk Access in System
Settings > Privacy & Security; macOS 13 or newer"`) and starts the
kqueue/FSEvents/lsof collectors instead, so monitoring continues at the
polling level.

### Apple's caveats

From the WWDC22 session that introduced eslogger ("What's new in Endpoint
Security", session 110345):

> "eslogger is not intended to be used by applications. Its output is subject
> to change in software updates. It is neither meant to provide the same
> performance characteristics, nor the same feature set, as natively
> interfacing with the Endpoint Security API does."

> "Like all Endpoint Security clients, eslogger must be run as superuser and
> requires the user to have authorized the responsible process for Full Disk
> Access, such as Terminal.app or SSH."

And `man eslogger` adds that there is no formal schema, that the JSON is
modelled after `es_message_t` and carries a `schema_version` with no
stability guarantee across changes, and that eslogger drops events from
every process in its own process group. The agent relies on that last point:
eslogger is kept in the agent's process group, so the agent's own activity
(including the `ps`/`lsof` helpers it spawns) is muted the way
`es_mute_process` does it for a native client; the agent's and eslogger's
PIDs are filtered on top.

The agent takes the rest at face value. The parser reads only `event_type`,
`time`, `process.{audit_token, ppid, parent_audit_token, executable.path}`
and `event.{exec.{target, args}, open.{file.path, fflag}, exit.stat,
fork.child}`, classifies by the key under `event` (the numeric `event_type`
is a secondary hint), ignores unknown events and fields, never fails on a
missing field, counts lines it cannot parse (the first one at WARN) and
skips lines over 4 MiB. The supervisor treats an exit within 2 s of start as
a startup failure (typed from stderr: not permitted / not root / other),
restarts eslogger with backoff when it dies later (up to 5 restarts a
minute, then an ERROR and no more process events until the agent restarts),
and sends SIGTERM then SIGKILL on shutdown. A macOS update that changes the
format therefore degrades to "parse errors in the log" rather than a crash,
and `eslogger_enabled: false` returns to polling.

### How to verify

```bash
# 1. eslogger works for your terminal (root + Full Disk Access granted)
sudo eslogger exec | head -1
#   one JSON line starting with {"schema_version": ... → fine
#   ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED            → grant Full Disk Access
#   ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED           → run with sudo

# 2. the agent picked it
./correlic-agent check-compat
#   [PASS] eslogger   eslogger available: Endpoint Security exec/exit/open events ...
sudo ./correlic-agent --config agent.yaml 2>&1 | grep -E 'eslogger|Endpoint Security'
#   INFO eslogger running pid=... events="[exec exit fork open]"
#   INFO Endpoint Security events via eslogger started events=... file_monitor=true network=lsof
# or, when it is not usable:
#   WARN eslogger failed to start; using kqueue/FSEvents/lsof collectors error="eslogger not permitted (Full Disk Access missing): exit status 1 ..." remediation="run as root; ..."
```

### Manual test recipe

The project has no macOS runtime in CI: the macOS job compiles the agent
(with and without `-tags esf`) and runs the unit tests, which exercise the
parser on recorded fixtures and the supervisor on a fake eslogger script. The
real tool is checked by hand:

1. Build: `cd agent && go build -o correlic-agent ./cmd/agent`.
2. Grant your terminal Full Disk Access and confirm `sudo eslogger exec | head -1`
   prints a line.
3. Start the agent against a backend with `process_exec_enabled`,
   `file_monitor_enabled` and `network_monitor_enabled` set to true and wait
   for `Endpoint Security events via eslogger started`.
4. In another terminal start a tool from the AI pattern list (for example
   `claude -p "list the files here"` or `aider --help`) and have it read a
   credential file, e.g. ask it to `cat ~/.ssh/id_ed25519.pub`.
5. On the dashboard (or `GET /api/v1/events`) check: a `process_exec` for the
   tool with `context.ai_session_id` set and a non-zero `actor.pid`; a
   `file_open` for the `.ssh` path with the same `ai_session_id`, `source:
   eslogger` and the `actor.pid` of the process that read it (the FSEvents
   path reports `pid: 0`); a `process_exit` when the tool ends; `net_connect`
   events from lsof as before.
6. Stop the agent with Ctrl-C: expect `eslogger stopped parsed=... dropped=...`
   in the log and `pgrep -x eslogger` to find nothing.
7. Negative test: remove the Full Disk Access grant (or run without sudo),
   start again and confirm the single WARN with the remediation and that
   kqueue exec events still arrive.
8. Resilience: `sudo pkill -x eslogger` while the agent runs; expect
   `eslogger exited` and, a second later, `eslogger restarted`.
9. Schema drift: on a new macOS release compare one line of
   `sudo eslogger exec | head -1` with `agent/internal/darwin/eslogger/testdata/exec.jsonl`
   and update the fixtures if the key names moved.

## Native ESF client (Endpoint Security Framework, esf build tag)

Implemented behind the `esf` build tag (`agent/internal/darwin/esf/`, wired in
`agent/cmd/agent/platform_darwin_esf.go`) and compiled in CI so it does not
rot. An esf-tagged binary opens an Endpoint Security client at startup and
falls back to eslogger and then the kqueue/FSEvents collectors when the
entitlement, root or Full Disk Access is missing. The client implements the
same `esevents.EventSource` as the eslogger collector and feeds the same
runners; it additionally subscribes to `NOTIFY_LOOKUP` for the DNS runner on
a macOS 12+ SDK. To actually run it you need your own Apple Developer
Program Organization account, Apple's approval of the
`com.apple.developer.endpoint-security.client` entitlement, a Developer ID
certificate and a provisioning profile; then sign the binary with
`agent/build/correlic-agent.entitlements`. None of that is provided or
supported by the project; with eslogger available it buys only DNS lookups
and Apple's native performance.

## Known Limitations

1. **No PID on file events (FSEvents polling path only)** — polling doesn't know which process touched the file. Events attributed to "any AI tracked" heuristic. eslogger and the native ESF client report the real PID.
2. **No PPID on exec events (kqueue path only)** — kqueue EVFILT_PROC gives PID but not parent PID. We use `ps` or sysctl to look it up, which may race for short-lived processes. Endpoint Security events carry the PPID.
3. **No DNS monitoring** — requires the native ESF client (macOS 12+ SDK) or a Network Extension; eslogger has no DNS event.
4. **Polling latency** — lsof polls every 2 s in every configuration, and FSEvents does on the polling path, vs eBPF's real-time. Short-lived connections (or, on the polling path, file accesses) may be missed between cycles.
5. **Docker on macOS** — Docker Desktop runs a Linux VM. `DockerResolver` returns nil on macOS (no cgroups). Container name resolution deferred.
6. **eslogger is not an API** — Apple may change its output or drop it; the agent degrades to parse errors plus polling rather than failing, and the polling collectors remain the floor.
