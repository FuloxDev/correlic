# AI Process Tracking & Race Condition Mitigation

This document details the robust lineage tracking system implemented in the Correlic Agent to ensures zero-drop telemetry for AI processes, even during rapid process creation.

## The Problem: Trace/Fork Race Conditions

In a high-performance system, a race condition often exists between:
1.  **Process Creation (`fork`/`exec`)**: The OS creating a new process.
2.  **Event Parsing (Userspace Agent)**: The agent receiving the `fork` event via eBPF.
3.  **Process Activity**: The new process immediately doing work (e.g., opening a socket).

**Scenario**:
1.  AI Agent `cursor` spawns `python` subprocess.
2.  `python` *immediately* calls `connect()` to an external API.
3.  The `connect()` syscall triggers an eBPF event.
4.  **Race**: If the agent processes the `connect` event *before* the `fork` event (due to ringbuffer scheduling or processing lag), the agent doesn't yet know that `python` is an AI child.
5.  **Result**: The `connect` event is filtered out (dropped) because the PID is unknown.

## The Solution: Two-Layered Protection

We implemented a two-layered defense to eliminate this race condition.

### 1. Kernel-Side Lazy Inheritance (eBPF)

For high-volume, performance-critical events like **TLS/SSL Encryption** (`uprobes`), we filter directly in the kernel to avoid sending garbage to userspace.

**Mechanism**:
*   **Map Check**: When `SSL_write` is called, the BPF program checks `ai_pids` map.
*   **Lazy Inheritance**: If the PID is *not* found, it doesn't give up. It aggressively reads the **Parent PID** (`task->real_parent->tgid`).
*   **Atomic Adoption**: If the *Parent* involves a known AI context, the BPF program:
    1.  **Adopts** the child: Adds the child PID to the `ai_pids` map *immediately* from kernel space.
    2.  **Processes** the event: Captures the payload.

**Benefit**: Zero latency. The child is recognized *before* the syscall even returns.

### 2. Userspace Active Registration (Go)

For other events (`connect`, `file_open`, `dns`), we rely on userspace filtering to keep the BPF programs simple.

**Mechanism**:
*   **Cache Miss Fallback**: When a runner (e.g., `NetworkRunner`) receives an event for an unknown PID, it doesn't drop it immediately.
*   **Active Registration**: It calls `RegisterProcess(pid)`.
*   **Lookup**: This forces a realtime check of the internal `LineageTracker` which verifies:
    *   Is this a known AI pattern?
    *   **Is the parent an AI process?**
*   **Recovery**: If the parent is known (even if the `fork` event for the child hasn't fully propagated), the child is registered, and the event is saved.

### 3. AI Session Tracking (All Platforms)

When an AI root process is detected (e.g., `claude.exe`, `cursor`), a UUID session is created. All child processes inherit the session via PPID:

- **`pidToSession` map**: PID → AI session UUID
- **`graceSession` map**: exited PID → session UUID (10-second TTL)
- **`sessionAIType` map**: session UUID → ai_type (e.g., "claude", "cursor")
- All runners tag events with `ai_session_id` in Context for cross-PID correlation

### 4. Grace Period for Exited Processes

When a process exits, its PID is moved to `graceAIPIDs` and `graceSession` maps with a 10-second TTL. This handles:
- Network events arriving after a short-lived process (curl, wget) exits
- File events from the same race condition
- `RegisterProcess` inheritance checks: also looks in `graceAIPIDs` for parent PID

### 5. Windows-Specific: PEB Command Line Capture

On Windows, the command line is read from the process PEB (`NtQueryInformationProcess` + `ReadProcessMemory`) **inside the ETW callback** — the earliest possible moment. Short-lived processes like `curl` and `cat` exit in <5ms; reading cmdline in the runner goroutine is too late.

## Summary

| Layer | Type | Mechanism | Protection |
| :--- | :--- | :--- | :--- |
| **Kernel** | `uprobes` (TLS) | BPF Map Update on Parent Match | Prevents dropped encrypted payloads |
| **Userspace** | `tracepoints` (Net/File) | Lazy `RegisterProcess` on Miss | Prevents dropped metadata events |
| **Session** | All platforms | UUID per AI root, inherited by children | Cross-PID event correlation |
| **Grace** | All platforms | 10s TTL for exited PIDs | Late-arriving events still attributed |
| **PEB Capture** | Windows only | Read cmdline in ETW callback | Full command args for short-lived processes |

This architecture ensures that "Correlation is Everything" holds true, even for millisecond-scale process lifecycles.
