# Windows Agent — Implementation Reference

## Overview

The Correlic Windows agent provides real-time security observability for AI agent activity on Windows. It uses ETW (Event Tracing for Windows) as the primary telemetry source and NTFS USN Journal as a secondary "never-miss" file monitoring layer.

**Key properties:**
- Pure Go — no CGo, all Windows APIs via `golang.org/x/sys/windows` and `syscall`
- Single ETW session with 4 kernel providers (avoids Windows' 64-session limit)
- All paths normalised to forward slashes before dispatch — 90% of detection rules work cross-platform without changes
- Case-insensitive baseline matching for Windows path semantics
- Graceful degradation — USN Journal optional, agent works ETW-only if unavailable

---

## Architecture

```
                          ┌─────────────────────────────────────────────┐
                          │         ETW Session ("CorrelicAgent")       │
                          │  Buffer: 64KB x 32 (max 2MB)               │
                          │  Mode:   EVENT_TRACE_REALTIME_MODE          │
                          │  Level:  Informational (4)                  │
                          │  Keywords: 0xFFFFFFFFFFFFFFFF (all)         │
                          └──────────────────┬──────────────────────────┘
                                             │ EventRecord callback
              ┌──────────────────┬───────────┼───────────────┬──────────────┐
              ▼                  ▼           ▼               ▼              │
   ┌──────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────┐    │
   │ ProcCollector    │ │FileCollector │ │ NetCollector │ │DNSCollect│    │
   │ (4096 buf)       │ │(8192 buf)    │ │ (4096 buf)   │ │(4096 buf)│    │
   │ Kernel-Process   │ │Kernel-File   │ │Kernel-Network│ │DNS-Client│    │
   └────────┬─────────┘ └──────┬───────┘ └──────┬───────┘ └────┬─────┘    │
            ▼                  ▼                ▼              ▼          │
   ┌──────────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────┐    │
   │ ExecRunner       │ │ FileRunner   │ │ NetRunner    │ │DNSRunner │    │
   │ AI lineage track │ │ IsDir guard  │ │ Port classify│ │ Domain   │    │
   │ PID/PPID resolve │ │ Path filter  │ │ IPv4/IPv6    │ │ capture  │    │
   │ Role classify    │ │ ETW tracker  │ │              │ │          │    │
   └────────┬─────────┘ └──────┬───────┘ └──────┬───────┘ └────┬─────┘    │
            │                  │                │              │          │
            └──────────────────┴────────────────┴──────────────┘          │
                                       │                                  │
                               dispatcher.Enqueue()                       │
                                       │                                  │
                                       ▼                                  │
                              ┌─────────────────┐                         │
                              │   Dispatcher     │     ┌──────────────────┤
                              │ (50,000 buffer)  │     │  ETW Loss Stats  │
                              │ → HTTP sink      │     │  (every 30s)     │
                              └─────────────────┘     └──────────────────┘

   ┌──────────────────────────────────────────────────────────────────────┐
   │                    USN Journal (Secondary)                          │
   │  ┌─────────────┐    ┌────────────────┐    ┌───────────────────┐    │
   │  │ USNReader    │───▶│ USNReconciler  │───▶│ dispatcher.Enqueue│    │
   │  │ Poll 500ms   │    │ Cross-ref ETW  │    │ source=usn_catchup│    │
   │  │ NTFS change  │    │ HasAnyAI check │    └───────────────────┘    │
   │  │ journal      │    │ PathFilter     │                             │
   │  └─────────────┘    └────────────────┘                             │
   │                           ▲                                         │
   │                     ┌─────┴──────┐                                  │
   │                     │ETWFileTrack│                                  │
   │                     │ FNV64 hash │                                  │
   │                     │ 5s dedup   │                                  │
   │                     └────────────┘                                  │
   └──────────────────────────────────────────────────────────────────────┘
```

---

## ETW Providers

| Provider | GUID | Event IDs | Canonical Type | Channel Buffer |
|---|---|---|---|---|
| Microsoft-Windows-Kernel-Process | `{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}` | 1 (start), 2 (stop) | `process_exec`, `process_exit` | 4096 |
| Microsoft-Windows-Kernel-File | `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` | 10, 11 (name create/delete), 12, 30 (create/new) | `file_open` | 8192 |
| Microsoft-Windows-Kernel-Network | `{7DD42A49-5329-4832-8DFD-43D979153A88}` | 12, 26 (connect IPv4/6), 15, 29 (accept IPv4/6) | `net_connect` | 4096 |
| Microsoft-Windows-DNS-Client | `{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}` | 3008, 3009 (query req/complete) | `net_dns` | 4096 |

**ETW Session Configuration** (`etw_session.go`):
- Session name: `CorrelicAgent`
- Buffer size: 64 KB per buffer
- Min/Max buffers: 4 / 32 (256 KB–2 MB total)
- Mode: `EVENT_TRACE_REALTIME_MODE`
- Event level: Informational (4) — captures all levels up to verbose
- Keywords: `0xFFFFFFFFFFFFFFFF` — all event keywords

**Windows APIs Used** (via `advapi32.dll`):

| API | Purpose |
|-----|---------|
| `StartTraceW` | Create ETW trace session |
| `EnableTraceEx2` | Enable each provider on the session |
| `OpenTraceW` | Open session for real-time consumption |
| `ProcessTrace` | Block and receive events via callback |
| `CloseTrace` | Stop consuming events |
| `ControlTraceW` | Query stats / stop session |

**Callback dispatch**: A single global `syscall.NewCallback` function pointer receives all ETW events. A thread-safe map (`cbMap`) routes events to the correct collector based on a registered dispatch ID. Each collector filters by `ProviderID` and `EventID`.

---

## Event Collection Pipelines

### Process Events (`proc_collector.go`, `exec_runner.go`)

**Collection:**
- Event 1 (ProcessStart): Only Event IDs 1 and 2 are processed; all others (3=ThreadStart, 5=ImageLoad, 21=ThreadWorkOnBehalf, etc.) are filtered out at the top of the callback to avoid wasting CPU.
- **UserData layout (Version 4, Windows 11 24H2 Build 26200):**

| Offset | Field | Size | Notes |
|--------|-------|------|-------|
| 0 | ProcessID | u32 | The new process PID |
| 4 | ProcessSequenceNumber | u64 | Unique kernel sequence |
| 12 | CreateTime | u64 | FILETIME |
| 20 | ParentProcessID | u32 | **PPID** — correct offset verified via hex dump |
| 24 | ParentProcessSequenceNumber | u64 | |
| 32 | SessionID | u32 | Terminal Services session |
| 36 | Flags | u32 | |
| 40+ | Variable fields | | |
| ~60+ | ImageName | UTF-16 | Found by scanning for `\Device\` or `C:` pattern |

- **Command line capture**: The ETW Kernel-Process provider does NOT include CommandLine in any version (V0-V4). The agent uses a **hybrid approach**:
  1. **Windows Security Audit Event 4688** (primary) — kernel writes cmdline at process creation. 100% reliable for all processes regardless of exit speed. Enabled via `audit_policy.go` at agent startup.
  2. **PEB read** (fallback) — `NtQueryInformationProcess` + `ReadProcessMemory` for processes that start before the audit subscriber.
  3. **Cmdline cache** (`cmdline_cache.go`) — Event 4688 stores cmdline keyed by PID with 10s TTL. The exec_runner checks the cache with 50ms wait before falling back to PEB.
  4. **Garbled cmdline detection** (`isValidCmdline`) — CJK/Korean characters in cmdline indicate failed PEB read; the cache is preferred.
  5. **Credential redaction** (`redactCmdline`) — `PGPASSWORD=secret` → `PGPASSWORD=***` before dispatch. Covers env var assignments, `--password=` flags, `Authorization: Bearer` headers.
- **No blocking calls in callback**: `lookupPPID` (CreateToolhelp32Snapshot) and `queryImagePath` (OpenProcess) moved to the exec_runner goroutine as fallbacks. The callback only does fast memory reads.
- Event 2 (ProcessStop): PID + ExitCode from UserData

**NT Device Path Translation:**
- ETW reports paths like `/Device/HarddiskVolume3/Windows/System32/cmd.exe`
- `buildVolumeMap()` calls `QueryDosDeviceW` to map volume devices to drive letters
- `ntPathToDOS()` converts: `/Device/HarddiskVolume3/...` → `C:/...`

**Enrichment (ExecRunner):**
1. Get singleton `LineageTracker`
2. Extract `comm` (lowercase binary name, strip `.exe` suffix)
3. `RegisterProcess(PID, PPID, comm)` — checks AI patterns + parent inheritance
4. Classify role via `classify.CheckRole()` (editor, terminal, shell, build tool, etc.)
5. Detect session ID via `procinfo.DetectSessionID()`
6. Dispatch canonical `process_exec` event
7. Call `exechandler.Handle()` for AI-specific enrichment

**AI Process Detection (Lineage Tracker):**
- Singleton `LineageTracker` with `aiPIDs` map
- Pattern matching: case-insensitive substring against configurable patterns (e.g., "claude", "cursor", "copilot")
- Lazy inheritance: if child PID's parent is already AI, child inherits AI status
- Two-layer race mitigation: kernel-side (BPF uprobes on Linux, ETW on Windows) + userspace (RegisterProcess fallback)
- `HasAnyAI()` returns true if any AI process is active (used by DNS runner and USN reconciler)

**AI Session Tracking (Windows-specific):**

On Windows, ETW events are asynchronous — short-lived processes (curl, git, npm) may exit before their file/network events are processed, causing PID-based attribution to fail. AI Sessions solve this:

```
Claude Code starts (PID 5040)
  → Session created: ai_session_id = "a1b2c3d4-..."
  → pidToSession[5040] = "a1b2c3d4-..."

  bash spawned (PID 6000, PPID=5040)
    → Inherits: pidToSession[6000] = "a1b2c3d4-..."

    curl spawned (PID 7000, PPID=6000)
      → Inherits: pidToSession[7000] = "a1b2c3d4-..."
      → Makes HTTPS request to httpbin.org
      → curl exits → PID 7000 moved to graceSession (10s TTL)

    Network event arrives for PID 7000 (after curl exited)
      → graceSession[7000] = "a1b2c3d4-..." → MATCH
      → Event tagged: ai_session_id = "a1b2c3d4-..."
      → Correlated with all other events in this Claude Code session
```

- **Root detection**: When `RegisterProcess` matches an AI pattern directly (not via inheritance), a new UUID session is created
- **Inheritance**: Child processes inherit the parent's session UUID via `pidToSession` map
- **Grace period**: When a PID exits, its session mapping moves to `graceSession` with a 10-second TTL
- **All runners**: File, network, and DNS runners tag events with `ai_session_id` from the tracker
- **Backend storage**: `ai_session_id` stored in Neo4j (indexed) and PostgreSQL `ai_agent_sessions` table
- **Cross-PID correlation**: Detection rules can use `GetRecentEventsBySession(ai_session_id)` to query all events across the entire AI agent process tree

Session tracking is also enabled on Linux for richer cross-PID correlation in detection rules (e.g., `ai.data_exfiltration` can correlate file reads + network connections across different PIDs in the same AI session).

### File Events (`file_collector.go`, `file_runner.go`)

**Collection:**
- Events 10/11 (NameCreate/NameDelete): filename at UserData offset 8
- Events 12/30 (Create/CreateNewFile): filename at offset 32 (v1+) or 36 (v0, ThreadId is pointer-sized)
- UTF-16LE decoding of filenames
- NT device path → DOS path translation
- Backslash → forward slash normalisation
- Mojibake detection: reject paths with >25% non-ASCII characters

**Enrichment (FileRunner):**
1. Path noise filter (`pathfilter.ShouldIgnorePath()`):
   - System dirs: `C:/Windows/WinSxS/`, `C:/Windows/assembly/`, `C:/Windows/servicing/`
   - Temp/cache: `/AppData/Local/Temp/`, `/AppData/Local/Microsoft/Windows/INetCache/`
   - Runtime noise: `__pycache__`, `.pyc`, `/node_modules/`, `/.git/`
   - Windows prefetch/logs: `C:/Windows/Prefetch/`, `C:/Windows/Logs/`
2. AI-only filter: `tracker.IsAI(PID)` — skip non-AI file events
3. Directory guard: `os.Stat()` + `info.IsDir()` → skip directory events
4. File size: `os.Stat()` → `info.Size()` (−1 if stat fails)
5. Credential categorisation: `.ssh` → `ssh_key`, `.aws` → `aws_credentials`, `.kube` → `kubeconfig`, etc.
6. Record in `ETWFileTracker` for USN dedup
7. Dispatch canonical `file_open` event

### Network Events (`network_collector.go`, `network_runner.go`)

**Collection:**
- **PID source**: Read from UserData offset 0 (NOT `EventRecord.ProcessID` which is often 0/SYSTEM for kernel network events)
- IPv4 events (Event 12 connect, 15 accept): UserData layout `[PID u32][size u32][daddr u32][saddr u32][dport u16][sport u16]` at bytes 0–19
- IPv6 events (Event 26 connect, 29 accept): ports at offsets 36–38, IPs parsed where possible (fallback: "ipv6" literal)
- Network byte order → host byte order conversion for IPs and ports

**Enrichment (NetworkRunner):**
- Port classification:

| Ports | Category |
|-------|----------|
| 22 | ssh |
| 53 | dns |
| 80, 8080 | http |
| 443, 8443 | https |
| 25, 465, 587 | smtp |
| 21 | ftp |
| 3389 | rdp |
| 5985, 5986 | winrm |
| 445 | smb |
| >10000 | high_port |

- Session ID tracking via `procinfo.DetectSessionID()`
- Dispatch canonical `net_connect` event

### DNS Events (`dns_collector.go`, `dns_runner.go`)

**Collection:**
- Events 3008/3009 (query request/completion)
- Query name: first UTF-16 null-terminated string in UserData

**Enrichment (DNSRunner):**
- Filter: `tracker.IsAI(PID)` OR `tracker.HasAnyAI()` (some DNS events lack PID attribution)
- Skip empty query names
- Dispatch canonical `net_dns` event with domain stored in `Target.IP` field

### Startup Process Scanner (`scanner.go`)

**Purpose:** Discover AI processes already running before the agent started.

**Algorithm:**
1. `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)` → enumerate all running processes
2. Build `children` map: `PPID → [child PIDs]`
3. Find AI roots: `CheckPattern(comm)` or `CheckPattern(exePath)` against AI patterns
4. BFS from roots: register each PID in lineage tracker, emit `process_exec` events
5. Resolve full image paths via `QueryFullProcessImageName`

---

## USN Journal Integration (Hybrid File Monitoring)

The NTFS USN (Update Sequence Number) Journal provides a persistent, on-disk record of every file system change. It complements ETW as a "never-miss" secondary source.

### Why USN Journal?

| Aspect | ETW Kernel-File | USN Journal |
|--------|----------------|-------------|
| Delivery | Real-time callback | Polling (500ms) |
| Event loss | Possible under load (buffer overflow) | Never (persistent journal) |
| PID attribution | Yes | No |
| Directory filtering | Manual (os.Stat + IsDir) | Native (`FILE_ATTRIBUTE_DIRECTORY`) |
| Latency | <1ms | 500ms (poll interval) |
| Requires | Admin privileges | Admin + NTFS volume |

### USN Reader (`usn_reader.go`)

**Windows APIs:**
- `CreateFileW` on `\\.\C:` — open volume handle
- `FSCTL_QUERY_USN_JOURNAL` — get journal ID and current USN
- `FSCTL_READ_USN_JOURNAL` — read records from last position

**USN_RECORD_V2 parsing:**

| Offset | Field | Size | Purpose |
|--------|-------|------|---------|
| 0 | RecordLength | u32 | Total record size |
| 4 | MajorVersion | u16 | Must be 2 |
| 8 | FileReferenceNumber | u64 | MFT index |
| 16 | ParentFileReferenceNumber | u64 | Parent directory MFT index |
| 24 | Usn | i64 | USN position |
| 32 | TimeStamp | i64 | FILETIME (100ns since 1601) |
| 40 | Reason | u32 | USN_REASON_* flags |
| 52 | FileAttributes | u32 | FILE_ATTRIBUTE_* flags |
| 56 | FileNameLength | u16 | Bytes |
| 58 | FileNameOffset | u16 | Offset from record start |
| 60+ | FileName | UTF-16 | Variable length |

**Reason flags monitored:**

| Flag | Value | Meaning |
|------|-------|---------|
| `USN_REASON_DATA_OVERWRITE` | 0x00000001 | File content modified |
| `USN_REASON_DATA_EXTEND` | 0x00000002 | File grown |
| `USN_REASON_FILE_CREATE` | 0x00000100 | New file created |
| `USN_REASON_FILE_DELETE` | 0x00000200 | File deleted |
| `USN_REASON_RENAME_NEW_NAME` | 0x00002000 | File renamed |

**Path resolution:**
- USN records only contain the filename, not the full path
- `ParentFileReferenceNumber` → cached path lookup (map of MFT ref → path string, 8192 initial capacity)
- Cache miss: `OpenFileById(volumeHandle, fileIdDesc)` + `GetFinalPathNameByHandleW()` → resolve and cache
- Cache invalidation: rename events update the entry
- All resolved paths normalised to forward slashes, `\\?\` prefix stripped

**Directory filtering:** Native — `FileAttributes & FILE_ATTRIBUTE_DIRECTORY` checked before emitting events. No `os.Stat()` race condition.

### USN Reconciler (`usn_reconciler.go`)

The reconciler bridges USN and ETW, emitting catch-up events only when ETW dropped something:

1. Read USN events from channel (populated by USNReader polling every 500ms)
2. Check `lineage.HasAnyAI()` — skip if no AI process active
3. Check `ETWFileTracker.WasSeen(path)` — skip if ETW already reported this file within 5s
4. Apply `pathfilter.ShouldIgnorePath()` — same noise filter as FileRunner
5. Emit canonical `file_open` event with:
   - `Source: "usn_catchup"` (distinguishes from ETW events)
   - `Actor.PID: 0` (PID unknown from USN)
   - `Context.usn_reason: <reason flags>`

### ETW File Tracker (`etw_file_tracker.go`)

Deduplication tracker preventing USN from re-emitting events ETW already captured:

- Hash function: FNV-64a on file path string
- Storage: `map[uint64]time.Time` (hash → last-seen timestamp)
- Max age: 5 seconds (configurable)
- `Record(path)` called by FileRunner on each ETW file event
- `WasSeen(path)` called by USNReconciler before emitting
- `Cleanup()` evicts stale entries every 10 seconds

---

## ETW Loss Monitoring

The ETW session periodically queries loss counters via `ControlTraceW` with `EVENT_TRACE_CONTROL_QUERY` (every 30 seconds and on shutdown):

| Counter | Meaning |
|---------|---------|
| `EventsLost` | Events dropped by the ETW kernel buffer |
| `RealTimeBuffersLost` | Real-time buffers that couldn't be delivered to the consumer |
| `LogBuffersLost` | Buffers lost for log file (N/A for real-time sessions) |
| `BuffersWritten` | Total buffers processed |
| `FreeBuffers` | Currently available buffer slots |
| `NumberOfBuffers` | Current total buffer count |

Logged as structured slog output:
```
ETW session stats events_lost=0 buffers_written=4821 realtime_buffers_lost=0
```

When `events_lost > 0`, the USN Journal reconciler compensates by catching file events that ETW missed.

---

## Canonical Event Schema

All events are normalised to a common schema before dispatch:

```go
type Event struct {
    SchemaVersion int               // 1
    ID            string            // SHA256 deterministic ID
    HostID        string            // Machine identifier
    Timestamp     time.Time
    Source        string            // "etw_kernel_process", "etw_kernel_file", etc.
    Type          string            // "process_exec", "file_open", "net_connect", "net_dns"
    Actor         *Actor            // Process info
    Target        *Target           // File/network info
    Context       map[string]any    // Detection metadata
}
```

**Actor** (process context):
- PID, PPID, User, ExePath, Comm, Cmdline, SessionID, Role

**Target** (resource accessed):
- FilePath (forward-slash normalised), FileSize (−1 = unknown, 0 = empty)
- IP, Port, Protocol, Domain

**Event Sources:**

| Source | Origin |
|--------|--------|
| `etw_kernel_process` | ETW Kernel-Process provider |
| `etw_kernel_file` | ETW Kernel-File provider |
| `etw_kernel_network` | ETW Kernel-Network provider |
| `etw_dns_client` | ETW DNS-Client provider |
| `usn_catchup` | USN Journal reconciler |
| `proc_scanner` | Startup process scan |

**Event ID generation:**
```
SHA256(hostID | timestampNano | source | eventType | pid | targetPath)
```
Deterministic — same event produces same ID for deduplication.

---

## Path Normalisation

All Windows paths are normalised before creating canonical events:

1. **NT device paths** → DOS paths: `/Device/HarddiskVolume3/Users/...` → `C:/Users/...`
2. **Backslash** → forward slash: `C:\Users\admin` → `C:/Users/admin`
3. **`\\?\` prefix** stripped (USN Journal resolved paths)
4. **Mojibake detection**: paths with >25% non-ASCII rejected (malformed ETW data)

This enables Linux-native detection patterns to work on Windows:
- `/.ssh/` matches `C:/Users/admin/.ssh/id_rsa`
- `/.aws/` matches `C:/Users/admin/.aws/credentials`
- `.env` matches `C:/projects/app/.env`

**Case-insensitive baseline matching:** The baseline cache uses `strings.ToLower()` on file-related patterns so `C:/Users/Fulox/.claude/**` matches `C:/users/fulox/.claude/file.json`. This is essential because Windows is case-insensitive but different API calls may return different casings.

---

## Backend Detection Rules — Windows Support

### AI File Activity (`ai.file_activity`)
- Severity: Low
- Fires for all file accesses by AI processes
- Guards: `FileSize <= 0` skipped (catches stat failures + directories), noise files filtered
- Signal type: `file_activity`, pattern = full file path

### AI Credential Access (`ai.credential_access`)
- Severity: Critical
- Windows-specific sensitive paths:
  - `SAM`, `SYSTEM`, `SECURITY` basenames (registry hives)
  - `ntds.dit` (Active Directory database)
  - `/AppData/Roaming/Microsoft/Protect/` (DPAPI master keys)
  - `/AppData/Local/Microsoft/Credentials/` (Credential Manager)
- AI agent config dirs excluded: `/.vscode/`, `/.claude/`, `/.cursor/`, `/.continue/`

### AI Unauthorized Exec (`ai.unauthorized_exec`)
- Severity: High
- Windows LOLBins on blocklist:
  - Download tools: `certutil.exe`, `bitsadmin.exe`
  - Execution proxies: `mshta.exe`, `regsvr32.exe`, `rundll32.exe`, `cscript.exe`, `wscript.exe`
  - System management: `net.exe`, `net1.exe`, `sc.exe`, `schtasks.exe`, `reg.exe`
  - Anti-forensics: `wevtutil.exe`
- Command-line patterns:
  - PowerShell download: `Invoke-WebRequest`, `IWR`, `DownloadString`, `Start-BitsTransfer`
  - PowerShell encoded commands: `-enc` + base64 payload
  - certutil download/decode: `certutil -urlcache`, `certutil -decode`
  - Pipe-to-shell: `curl ... | bash` (guard prevents safe domain bypass)
- Safe domain suppression: curl/wget to known-safe domains (OpenAI, Anthropic, npm, PyPI, etc.) are suppressed unless piped to a shell

### AI Persistence (`ai.persistence`)
- `C:/Windows/System32/Tasks/` (Scheduled Tasks)
- `C:/Windows/System32/GroupPolicy/` (GPO)
- Startup folders (per-user + all-users)
- Binaries: `schtasks.exe`, `sc.exe`, `reg.exe`, `at.exe`

### AI Privilege Escalation (`ai.privilege_escalation`)
- `runas.exe`, `psexec.exe`, `psexec64.exe`
- PowerShell bypass patterns: `-ExecutionPolicy Bypass`
- Windows LOLBins for code execution

### AI Discovery (`ai.discovery`)
- `ipconfig.exe`, `systeminfo.exe`, `tasklist.exe`, `net.exe`, `wmic.exe`
- `query.exe`, `quser.exe`, `qwinsta.exe`, `nltest.exe`, `dsquery.exe`, `cmdkey.exe`

---

## Baseline System — Windows Considerations

### Path normalisation in baselines
All baseline patterns are normalised with `filepath.ToSlash()` before storage:
- `LearnFromFinding()` normalises pattern before DB insert
- `CreateBaseline` API handler normalises incoming pattern
- `AutoResolveByBaseline` SQL query normalises `dirPrefix`
- Directory baseline creation normalises `filePath` before splitting

### Case-insensitive cache keys
The `cacheKey()` function lowercases patterns for file-related signal types:
```
file_pattern, file_activity, credential_file, persistence_path,
code_tamper, file_write_burst, command_file
```

This ensures `C:/Users/Admin/.ssh/**` and `C:/users/admin/.ssh/**` resolve to the same cache entry.

### Directory glob baselines
When a user clicks "Allow Directory" on a finding:
1. `filePath` extracted from finding context, normalised to forward slashes
2. Parent directory extracted via `strings.LastIndex(filePath, "/")`
3. Pattern stored as `parentDir/**` with signal_type `file_pattern`
4. `IsFileBaselined()` walks up directory tree, checking `dir/**` at each level
5. Retroactive suppression: `AutoResolveByBaseline` uses `LIKE dirPrefix%` SQL query

---

## Graceful Degradation

| Component | Failure Mode | Behaviour |
|-----------|-------------|-----------|
| USN Journal | Non-admin, non-NTFS, journal disabled | Log warning, continue ETW-only |
| Process scanner | Snapshot fails | Log error, continue without startup scan |
| PPID lookup | Snapshot miss | Use PID 0, continue |
| Image path query | Access denied | Use ETW-provided partial path |
| Path resolution (USN) | OpenFileById fails | Return filename only, no full path |
| ETW session | Name collision | Stop existing session, start new one |

---

## File Structure

```
correlic-agent/
├── cmd/agent/
│   └── platform_windows.go           # Wiring: create runners, ETW session, USN reader
├── internal/
│   ├── windows/
│   │   ├── etw_session.go             # ETW session lifecycle, providers, loss monitoring
│   │   ├── proc_collector.go          # Process ETW collector (Event 1/2)
│   │   ├── exec_runner.go             # Process enrichment, AI lineage
│   │   ├── file_collector.go          # File ETW collector (Event 10/11/12/30)
│   │   ├── file_runner.go             # File enrichment, IsDir guard, path filter
│   │   ├── network_collector.go       # Network ETW collector (Event 12/15/26/29)
│   │   ├── network_runner.go          # Network enrichment, port classification
│   │   ├── dns_collector.go           # DNS ETW collector (Event 3008/3009)
│   │   ├── dns_runner.go              # DNS enrichment
│   │   ├── scanner.go                 # Startup process scan
│   │   ├── usn_reader.go              # USN Journal reader (NTFS change journal)
│   │   ├── usn_reconciler.go          # USN/ETW cross-reference reconciler
│   │   └── etw_file_tracker.go        # FNV64 dedup tracker for ETW→USN
│   ├── lineage/
│   │   └── tracker.go                 # AI process lineage (singleton)
│   ├── pathfilter/
│   │   ├── filter.go                  # Credential path categorisation
│   │   └── ignore_windows.go          # Windows path noise filter
│   ├── event/
│   │   ├── event.go                   # Canonical event schema
│   │   ├── actor.go                   # Process actor struct
│   │   ├── target.go                  # File/network target struct
│   │   └── id.go                      # Deterministic event ID generation
│   └── dispatch/
│       └── dispatcher.go              # Buffered event dispatcher (50,000 default)
```

---

## Deployment

### Requirements
- Windows 10 1809+ / Server 2019+ (modern ETW kernel providers)
- Administrator privileges (ETW trace session + process inspection)
- NTFS filesystem (optional, for USN Journal — gracefully degrades without it)

### Installation
```
msiexec /i correlic-agent.msi /qn APIKEY=sk-... BACKENDURL=https://api.correlic.com
```

### Service
- Name: `CorrelicAgent`
- Start type: Automatic
- Recovery: Restart on failure (60s delay)
- Config: `C:\ProgramData\Correlic\agent.yaml`
- Identity: `C:\ProgramData\Correlic\.correlic-agent-id`

### Registration
Heartbeat POST with `OS: "windows"` triggers automatic registration. No backend changes needed — same flow as Linux/macOS.

---

## Comparison: Windows vs Linux vs macOS

| Capability | Linux (eBPF) | macOS (kqueue/ESF) | Windows (ETW+USN) |
|---|---|---|---|
| Process monitoring | Tracepoint (sched_process_exec) | kqueue EVFILT_PROC | ETW Kernel-Process |
| File monitoring | Tracepoint (sys_enter_openat) | FSEvents polling (2s) | ETW Kernel-File + USN Journal |
| Network monitoring | Kprobe (sys_connect) | lsof polling | ETW Kernel-Network |
| DNS capture | Not implemented (agent-side) | Not implemented | ETW DNS-Client |
| Event loss detection | Ring buffer drops logged | N/A (polling) | ETW loss counters + USN catch-up |
| Path format | `/home/user/...` | `/Users/user/...` | `C:/Users/user/...` (normalised) |
| Privileges | root / CAP_BPF | root | Administrator |
| Command line | In-kernel (tracepoint) | /proc/PID/cmdline | Event 4688 (Security Audit) |
| Registry monitoring | N/A | N/A | Event 4657 (Security Audit) |
| Privilege tracking | N/A | N/A | Event 4672 (Security Audit) |

---

## Windows Security Audit Integration

The ETW Kernel-Process provider gives PID, PPID, and ImagePath but NOT the command line. The agent supplements ETW with Windows Security Audit events for complete telemetry.

### Audit Policies Enabled at Startup

`audit_policy.go` runs at agent start (requires Administrator):

| Policy | Events | Purpose |
|--------|--------|---------|
| Process Creation | 4688, 4689 | Full command line capture |
| Command Line Logging | Registry key | Include cmdline in Event 4688 |
| File System | 4656, 4663 | Read vs write distinction (access mask) |
| Registry | 4657 | Registry key/value modifications |
| Sensitive Privilege Use | 4672, 4673 | Actual privilege activation |

Resource impact: negligible (<0.1% CPU, ~10-50MB/day event log).

### Architecture: Hybrid ETW + Event Log

```
ETW Kernel Providers (instant, PID/PPID/ImagePath):
  ├── Kernel-Process → exec_runner
  ├── Kernel-File → file_runner
  ├── Kernel-Network → network_runner
  └── DNS-Client → dns_runner

Security Event Log (1-5ms, cmdline/registry/privileges):
  ├── Event 4688 → cmdline_cache (merged into ETW exec events)
  ├── Event 4657 → audit_runner → registry_write events
  ├── Event 4656 → audit_runner → file_access with access_type
  ├── Event 4672 → audit_runner → privilege_use events
  └── Event 4698 → audit_runner → schtask_create events
```

### Cmdline Capture Priority

```
1. Event 4688 cache (100% reliable — kernel writes it)
   → cmdline_cache.GetWithWait(pid, 50ms)
   → If garbled Unicode detected, prefer cache over ETW

2. ETW callback PEB read (fast but unreliable for short-lived processes)
   → isValidCmdline() filters CJK/Korean garbage

3. procinfo.ReadProcCmdline (runner-side fallback)
   → For processes started before audit subscriber
```

### Credential Redaction

Applied in exec_runner BEFORE dispatch — secrets never reach DB, Neo4j, or AI layer:

```
PGPASSWORD=secret psql  →  PGPASSWORD=*** psql
--password=abc123        →  --password=***
--token=sk-xxx           →  --token=***
Authorization: Bearer xx →  Authorization: Bearer ***
AWS_SECRET_ACCESS_KEY=x  →  AWS_SECRET_ACCESS_KEY=***
```

### Key Files

| File | Purpose |
|------|---------|
| `internal/windows/audit_policy.go` | Enable audit policies via auditpol + registry |
| `internal/windows/audit_subscriber.go` | EvtSubscribe to Security event log, parse XML |
| `internal/windows/audit_runner.go` | Convert audit events to canonical Correlic events |
| `internal/windows/cmdline_cache.go` | PID→cmdline cache with TTL + wait-with-backoff |
| `internal/windows/exec_runner.go` | Cmdline priority: 4688 cache → ETW → PEB fallback |
