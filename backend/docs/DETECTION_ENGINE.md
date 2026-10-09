# Detection Engine (Phase 2)

The detection engine evaluates every ingested event against registered detection rules and produces findings — structured security signals. It includes **13 AI-focused detection rules + 11 multi-step chain patterns**, a finding cooldown rate limiter, severity dampening (low-confidence CRITICAL → HIGH), per-org rule exceptions, per-org tunable thresholds, behavioral baseline integration, and block rule enforcement. All detection is AI-gated: rules only fire for processes within an AI agent tree (via Neo4j `IsAIProcess()` check).

### Event Types Supported
- `process_exec` — process creation (from ETW Kernel-Process + Event 4688 cmdline enrichment)
- `file_open` — file access with `file_exists` flag (PATHEXT probe filtering)
- `net_connect` — outbound network connections
- `net_dns` — DNS queries
- `registry_write` — Windows registry modifications (from Security Audit Event 4657)
- `privilege_use` — sensitive privilege activation (from Security Audit Event 4672)
- `schtask_create` — Windows scheduled task creation (from Security Audit Event 4698)

## Architecture

```
Event ingested via POST /ingest/events
  |
  v
Sampling (drop low-value events)
  |
  v
Store in PostgreSQL + Neo4j process tree
  |
  v
Detection Engine evaluates event
  ├── Look up rules indexed by event type
  ├── For each rule: call Evaluate(EvalContext)
  ├── Stamp findings with ID, detection_id, host_id, severity, confidence, status
  └── Deduplicate via deterministic finding IDs (host + detection + pattern key)
  |
  v
Baseline suppression (BaselineCollector.MatchesBaseline)
  ├── If finding matches behavioral baseline → suppress (don't store)
  └── If event triggered zero findings AND not on never-baseline list → observe
  |
  v
Rule exception suppression (RuleExceptionStore.Matches)
  └── If finding matches per-org exception → suppress
  |
  v
Cooldown (FindingCooldown)
  ├── Key = finding ID (detection_id:host_id:pattern_key)
  ├── Default: 10 min (credential_access: 15 min, unexpected_network: 5 min)
  └── First finding always emits; repeats within window suppressed
  |
  v
Store findings in PostgreSQL (with confidence column)
  |
  v
Attack chain correlation (ChainCorrelator)
  ├── Buffer findings per host+session
  ├── Check 11 chain patterns:
  │     credential_theft (credential_access → data_exfiltration)
  │     reverse_shell_setup (unauthorized_exec → unexpected_network)
  │     lateral_movement (unauthorized_exec → unexpected_network internal)
  │     full_compromise (credential_access → unauthorized_exec → exfil/network)
  │     persistence_backdoor (escalation → persistence)
  │     supply_chain_attack (code_tampering → exfil/network)
  │     data_staging (excessive_writes → exfil/network)
  │     credential_persistence (credential_access → persistence)
  │     privesc_credential_exfil (escalation → credential_access → exfil/network)
  │     recon_to_escalation (discovery → escalation)
  │     container_breakout (container_escape → persistence/creds/escalation)
  └── If pattern completes → emit chain finding (bypasses cooldown)
  |
  v
Incident correlation (IncidentCorrelator) → Phase 4
  |
  v
Surface in UI (/alerts page)
```

## Key Files

| File | Purpose |
|------|---------|
| `internal/detection/types.go` | `Detection` interface, `Finding` struct, `GraphQuerier` interface, `EvalContext`, `ExceptionChecker`, `RuleSettingsReader` |
| `internal/detection/engine.go` | Thread-safe engine: routes events to rules, stamps findings, preserves rule-set confidence, panic recovery |
| `internal/detection/graph_querier.go` | `Neo4jGraphQuerier`: implements `GraphQuerier` using Neo4j for process ancestry, recent events, AI process checks |
| `internal/detection/baseline.go` | `BaselineCollector`: detection-gated behavioral learning + in-memory cached baseline matching (30s refresh) |
| `internal/detection/never_baseline.go` | Files/binaries/ports/domains that must never be auto-baselined (Tier 1 sensitive resources) |
| `internal/detection/cooldown.go` | `FindingCooldown`: in-memory rate limiter per finding ID, background cleanup every 5min |
| `internal/detection/chain_correlator.go` | `ChainCorrelator`: buffers findings per host+session, detects multi-step attack patterns, emits chain findings |
| `internal/detection/ai_pack/pack.go` | AI detection pack registration (13 rules) |
| `internal/detection/ai_pack/ai_credential_access.go` | Tier 1/Tier 2 credential file access detection |
| `internal/detection/ai_pack/ai_unauthorized_exec.go` | Binary blocklist + cmdline pattern analysis |
| `internal/detection/ai_pack/ai_excessive_writes.go` | Path diversity scoring for file write bursts |
| `internal/detection/ai_pack/ai_data_exfiltration.go` | Session-first read-then-exfiltrate correlation (15min window) |
| `internal/detection/ai_pack/ai_unexpected_network.go` | External non-standard ports + high-risk internal targets |
| `internal/detection/ai_pack/ai_suspicious_dns.go` | Agent-categorized suspicious DNS queries |
| `internal/detection/ai_pack/ai_persistence.go` | Persistence mechanism detection (cron, systemd, registry, SSH keys) |
| `internal/detection/ai_pack/ai_privilege_escalation.go` | Privilege escalation detection (sudo, su, LOLBins, sensitive privileges) |
| `internal/detection/ai_pack/ai_code_tampering.go` | Write-mode modifications to CI/CD, Dockerfiles, dependency manifests |
| `internal/detection/ai_pack/ai_container_escape.go` | Container escape attempts (runtime sockets, namespace files, host mounts) |
| `internal/detection/ai_pack/ai_discovery.go` | Reconnaissance burst detection (discovery command clustering) |
| `internal/detection/ai_pack/ai_command_activity.go` | Catch-all AI command audit trail |
| `internal/detection/ai_pack/ai_file_activity.go` | Catch-all AI file access audit trail |
| `internal/storage/finding_store.go` | `FindingStore`: PostgreSQL CRUD for findings (org-scoped, incident_id) |
| `internal/storage/rule_exception_store.go` | `RuleExceptionStore`: per-org DB-backed exception suppression (30s cache) |
| `internal/storage/rule_settings_store.go` | `RuleSettingsStore`: per-org tunable rule thresholds (30s cache) |
| `internal/api/findings_handler.go` | HTTP endpoints for findings list + resolve |
| `internal/api/exceptions_handler.go` | HTTP CRUD for rule exceptions |
| `internal/api/rule_settings_handler.go` | HTTP CRUD for rule settings |
| `internal/ingest/live_ingest.go` | Pipeline: sampling → detection → baseline → exception → cooldown → store → chain → incident |

## Core Types

### Detection Interface

```go
type Detection interface {
    Meta() DetectionMeta      // ID, pack, severity, description, tags, MITRE techniques
    Scope() DetectionScope    // Which event types trigger this rule + look-back window
    Evaluate(ctx *EvalContext) []Finding
}

type DetectionMeta struct {
    ID              string   // "ai.credential_access"
    Pack            string   // "ai" | "dev" | "system"
    Name            string
    Severity        string   // "critical" | "high" | "medium" | "low"
    Description     string
    Tags            []string
    MITRETechniques []string // e.g. ["T1552", "T1552.004"]
}

type DetectionScope struct {
    EventTypes []string // triggers on these event types
    WindowSecs int      // look-back window for context queries
}
```

### EvalContext

```go
type EvalContext struct {
    Ctx               context.Context
    Event             *event.Event
    HostID            string
    OrgID             string            // for per-org rule settings lookup
    GraphQuery        GraphQuerier      // Neo4j context queries
    SafeDomainChecker SafeDomainChecker // network allowlisting
    RuleSettings      RuleSettingsReader // nil = use rule defaults
}
```

### Finding

```go
type Finding struct {
    ID            string
    DetectionID   string
    HostID        string
    Severity      string
    Confidence    float64         // 0.0–1.0, set by rules, never overridden by engine
    Title         string
    Summary       string
    AnchorEventID string
    RelatedEvents []string
    Context       map[string]any  // signal_type, pattern, ai_type, mitre_techniques, etc.
    Status        string          // "pending" | "allowed" | "dismissed" | "investigating"
    Resolution    string
    ResolvedBy    string
    ResolvedAt    *time.Time
    Suppressed    bool
    BaselineMatch string
    Timestamp     time.Time
}
```

## Finding Deduplication

Finding IDs are deterministic: `{detection_id}:{host_id}:{pattern_key}`.

Pattern keys by event type:
- `file_open`/`file_write` → file path
- `process_exec` → exe path or comm
- `net_connect` → BGP prefix (or /24 CIDR) + port
- `net_dns` → domain

Same pattern key + same host + same detection = one finding (PostgreSQL `ON CONFLICT DO NOTHING`).

## Severity Model

Two-level severity:
1. **Static** (via `Meta().Severity`): default severity for the rule
2. **Dynamic** (via `Finding.Severity`): per-finding override; engine preserves when set, falls back to meta severity when empty

## GraphQuerier (Neo4j)

| Method | Purpose |
|--------|---------|
| `IsAIProcess(hostID, pid)` | Check if PID has `:AIAgent` label or has ancestor with it (10-level walk) |
| `GetRecentEvents(hostID, pid, since, eventTypes)` | Recent events for single PID (limit 100) |
| `GetRecentEventsMultiPID(hostID, pids, since, eventTypes)` | Recent events for multiple PIDs (limit 500) |
| `GetRecentEventsBySession(hostID, sessionID, since, eventTypes)` | Recent events by session (limit 500) |
| `GetProcessAncestors(hostID, pid, maxDepth)` | Walk PROCESS_PARENT edges (ancestor chain) |

All methods populate `evt.Process.Cmdline` from Neo4j index position 5 (JSON array or fallback string).

## AI Tool Recognition

Rules fire only for processes inside an AI agent tree. The agent decides
membership with the pattern list it fetches from `GET /api/v1/ai/patterns`
(table `ai_agent_patterns`, seeded by migrations 002/003/006; org-specific
rows come from `POST /api/v1/ai/agent-patterns` or the Settings page).
Matching is whole-token on the process name, executable path, `argv[0]` and
argument basenames (`agent/internal/lineage/tracker.go`); patterns shorter
than 3 characters or containing a dot are ignored for process matching.

Seeded tools (46 rows covering 43 tools; `cursor`/`Cursor` and the legacy aliases count once):

| Group | Patterns (`agent_type`) |
|-------|-------------------------|
| CLI agents | `claude`, `aider`, `cline`, `codex`, `gemini`, `goose`, `devin`, `opencode`, `amp`, `jules`, `roo`, `crush`, `droid`, `qwen`, `auggie` (augment), `kimi`, `codebuff`, `plandex` |
| IDEs / forks / plugins | `cursor`, `windsurf`, `antigravity`, `zed`, `trae`, `pearai`, `void`, `kiro`, `junie` |
| Editor extensions / language servers | `copilot`, `codeium`, `tabnine`, `continue`, `supermaven` |
| Python agent frameworks | `langchain`, `langgraph`, `llamaindex`, `autogpt`, `autogen`, `crewai`, `openhands` (+ `opendevin`), `smolagents`, `agno` (+ `phidata`), `metagpt`, `babyagi` |

The vendor API domains of these tools are seeded into `safe_domains_list`
so model traffic is not reported by `ai.data_exfiltration`. Short or
generic names (`amp`, `roo`, `crush`, `jules`) can match unrelated
binaries or directories; migration `006_ai_patterns_2026q4.sql` documents
each risk, and a pattern can be removed per org through
`DELETE /api/v1/ai/agent-patterns/{id}`.

## AI Detection Rules (13 rules + 11 chain patterns)

All rules gate on `IsAIProcess()` first — only fire for processes within an AI agent tree.

### Severity Dampening

The engine automatically dampens severity when confidence is low:
- Finding with `confidence < 0.60` and `severity = "critical"` → downgraded to `"high"`
- Finding with `confidence < 0.60` and `severity = "high"` → downgraded to `"medium"`

This prevents high-confidence pattern matches from alarming users when contextual confidence is low (e.g., `reg.exe` matched by binary name but cmdline shows read-only `query` operation).

### Finding Status: `blocked`

When the agent's soft-block enforcer matches a block rule, the finding is created with `status = "blocked"` instead of `"pending"`. Blocked findings appear in the UI's "Blocked" tab and are excluded from the pending count. The block status is set when `evt.Context["action"] == "blocked"`.

### Windows-Specific Detection

Detection rules now handle Windows Security Audit event types:
- `registry_write` (Event 4657): `ai.persistence` detects Run key additions, service modifications, Winlogon changes, AppInit_DLLs, IFEO debugger hijacks, Defender exclusions
- `privilege_use` (Event 4672): `ai.privilege_escalation` fires on actual sensitive privilege activation (SeDebugPrivilege, SeImpersonatePrivilege, etc.) rather than just binary name matching
- `reg query` vs `reg add`: `ai.unauthorized_exec` distinguishes read-only registry queries (LOW, T1012) from modifications (HIGH, T1112)

### ai.credential_access (critical)

**Triggers on:** `file_open` | **Window:** none | **MITRE:** T1552, T1552.004

Two-tier sensitivity model:
- **Tier 1 (fires standalone):** SSH keys, `/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, container secrets (`/run/secrets/*`), crypto material (`.pem`, `.key`, `.p12`, `.pfx`, `.jks`, `.keystore`), key name patterns (`_rsa`, `_ecdsa`, `_ed25519`)
- **Tier 2 (handled by ai.data_exfiltration only):** `.env`, `.aws/credentials`, `.aws/config`, `.kube/config`, `.npmrc`, `.pypirc`, `.docker/config.json`, `.netrc`

Zero-byte suppression: FileSize == 0 → drop entirely.
Keyword heuristics: files with `token`, `secret`, `apikey`, `password` in basename → confidence 0.60.

Ignored dirs: `.vscode/`, `.claude/`, `.cursor/`, `.continue/`, `.copilot/`, `.codeium/`, `.aider/`, `.config/Code/`, `.config/cursor/`, `.config/Claude/`.

Context: `signal_type="file_pattern"`, `pattern="{dir}/**"`.

| Signal | Confidence |
|--------|------------|
| Crypto extension + 100B–10KB | 0.95 |
| SSH/path pattern + 100B–10KB | 0.90 |
| SSH/path pattern + unknown size (-1) | 0.80 |
| SSH/path pattern + size > 100KB | 0.50 |
| Keyword match | 0.60 |

### ai.unauthorized_exec (high)

**Triggers on:** `process_exec` | **Window:** none | **MITRE:** T1059, T1059.004

Two-layer detection:
1. **Binary blocklist** (exact basename match): curl, wget, nc, ncat, socat, ssh, nmap, chmod, chown, useradd, crontab, systemctl, base64, nsenter, mount, etc.
2. **Cmdline pattern analysis** (regex on joined cmdline):
   - Shell with network primitives: `(bash|sh|zsh|dash) -c/-i` containing `/dev/tcp`, IP literals, `nc`, `curl`, `wget`
   - Interpreter with inline network code: `(python3|node|ruby|perl) -c/-e` containing `socket`, `http.request`, `fetch(`
   - Interactive shell: `(bash|sh) -i` (reverse shell indicator)

Safe domain suppression for curl/wget/fetch — checks cmdline URL against `SafeDomainChecker`.

Context: `match_type` ("binary" or "cmdline_pattern"), `matched_pattern`.

| Signal | Confidence |
|--------|------------|
| Binary blocklist | 0.85 |
| Cmdline pattern | 0.70 |

### ai.excessive_writes (dynamic severity)

**Triggers on:** `file_open` (scope fixed from dead `file_write`) | **Window:** 30s | **MITRE:** T1485, T1486

Path diversity scoring — classifies paths into project vs system scopes:
- **Project scope:** `/home/*/`, `/tmp/`, relative paths
- **System scope:** `/etc/`, `/usr/`, `/var/`, `/opt/`, etc.
- **Critical system paths:** `/etc/`, `/usr/bin/`, `/usr/local/bin/`

Rate gate: project-only tier requires BOTH count AND rate >= threshold (`fileRate = files/sec`).

Context: `signal_type="file_write_burst"`, `pattern="pid:NNN:reason"`, `path_diversity`, `system_scopes`, `system_file_count`, `critical_system_files`, `reason`.

| Condition | Severity | Confidence |
|-----------|----------|------------|
| 5+ files in critical system paths | critical | 0.90 |
| 10+ system files across 2+ system scopes | high | 0.75 |
| 3+ system files alongside project writes | medium | 0.60 |
| 20+ files all within single project scope | low | 0.35 |

Thresholds are per-org tunable via `RuleSettingsStore`.

### ai.data_exfiltration (critical)

**Triggers on:** `net_connect` | **Window:** 15 min | **MITRE:** T1041, T1567

Detects read-then-exfiltrate: AI reads sensitive file → outbound connection.

**Session-first correlation:** If `Actor.SessionID` available → correlate by `(host_id, session_id)` via `GetRecentEventsBySession` (cross-tree behavior). Otherwise → PID-tree fallback: walk up to 5 ancestors via `GetProcessAncestors`, query with `GetRecentEventsMultiPID`.

Uses `isSensitiveFile()` (BOTH Tier 1 + Tier 2). Safe domain allowlist applied.

Context: `signal_type="network_dest"`, `pattern="bgp:port"`, `correlation_scope` ("session" or "pid_tree"), `session_id`, `tree_pids`, `sensitive_files`.

| Signal | Confidence |
|--------|------------|
| Session scope + 3+ sensitive files | 0.90 |
| Session scope + 1–2 sensitive files | 0.75 |
| PID-tree fallback | 0.65 |

### ai.unexpected_network (dynamic severity)

**Triggers on:** `net_connect` | **Window:** none | **MITRE:** T1071, T1571

Three detection paths:

**External connections (non-private IPs):**
- Skip standard web ports (80, 443, 8080, 8443)
- Skip safe-domain-allowlisted destinations
- All other external + non-standard ports → high

**High-risk internal connections (private IPs):**

| Target | Severity | Confidence |
|--------|----------|------------|
| `169.254.169.254` (cloud metadata/IMDS) | critical | 0.95 |
| SSH/RDP (port 22, 3389) on non-loopback | high | 0.85 |
| Database ports (5432, 3306, 27017, 6379, 9200) on non-loopback | medium | 0.70 |
| External non-standard port + ASN enrichment | high | 0.80 |
| External non-standard port, no enrichment | high | 0.65 |

Localhost connections always skipped for SSH/RDP and database checks.
Context: `internal_threat` field for internal findings.

### ai.suspicious_dns (dynamic severity)

**Triggers on:** `net_dns` | **Window:** none | **MITRE:** T1568, T1071.004

Fires on agent-categorized domains:

| Category | Severity | Confidence |
|----------|----------|------------|
| `tor` | critical | 0.95 |
| `suspicious_tld` | high | 0.85 |
| `paste_service` | medium | 0.75 |
| `file_share` | medium | 0.70 |

Safe domain allowlist applied. Context: `signal_type="dns_domain"`, `pattern=domain`.

### ai.persistence (critical)

**Triggers on:** `file_open`, `process_exec`, `registry_write` | **Window:** none | **MITRE:** T1546, T1053, T1098.004, T1543, T1574.006, T1556.003, T1547.001

Detects AI agent access to persistence-sensitive locations (cron, systemd, SSH authorized_keys, shell startup files, Windows Run keys, scheduled tasks) or execution of persistence-related commands (crontab, schtasks.exe, sc.exe, reg.exe, systemctl enable). File opens are tiered by path criticality and demoted for read-only access; registry writes detect Run key additions, service modifications, Winlogon hijacks, AppInit_DLLs, IFEO debugger, and Defender exclusions.

Context: `signal_type="persistence_path"`, `pattern="{file_path}"` (file opens); `signal_type="persistence_cmd"`, `pattern="{cmdline}"` (exec).

| Signal | Confidence |
|--------|------------|
| Critical path write (crontab, sudoers, authorized_keys, ld.so.preload, PAM, registry) | 0.95 |
| Critical command exec (crontab, schtasks.exe, sc.exe, reg.exe, systemctl enable) | 0.95 |
| High path write (init.d, git hooks, systemd, shell rc, autostart, Windows Startup) | 0.85 |
| Medium path write (profile.d, udev rules, NetworkManager dispatcher) | 0.70 |
| Read-only open of critical path (demoted to high) | 0.80 |
| Registry: Defender exclusion addition | 0.90 |

### ai.privilege_escalation (critical)

**Triggers on:** `process_exec`, `privilege_use` | **Window:** none | **MITRE:** T1548, T1548.003, T1068, T1611, T1055.008

Detects AI agent execution of privilege escalation binaries (sudo, su, pkexec, nsenter, kernel module tools, runas/psexec), LOLBins (PowerShell bypass, mshta, regsvr32, rundll32, certutil, wmic), capability manipulation (setcap, chmod u+s, chown root), debugger attach (strace -p, gdb attach), raw disk reads, and namespace escalation (unshare --user). Also detects Windows sensitive privilege usage (SeDebugPrivilege, SeTcbPrivilege) from Security Audit Event 4672.

Context: `signal_type="escalation_cmd"`, `pattern="{cmdline}"`.

| Signal | Confidence |
|--------|------------|
| Critical binary exec (sudo, su, pkexec, nsenter, modprobe, runas.exe, psexec.exe) | 0.95 |
| PowerShell with -ExecutionPolicy Bypass or -EncodedCommand | 0.95 |
| High binary exec (setcap, capsh, chroot, powershell.exe, mshta.exe, certutil.exe) | 0.85 |
| chmod u+s / chown root / strace -p / gdb attach / dd raw disk | 0.85 |
| Medium binary exec (mount, umount, unshare, firejail) | 0.70 |
| privilege_use: SeDebugPrivilege / SeTcbPrivilege / SeCreateTokenPrivilege | 0.95 |
| privilege_use: SeImpersonatePrivilege / SeBackupPrivilege | 0.90 |

### ai.code_tampering (high)

**Triggers on:** `file_open` | **Window:** none | **MITRE:** T1195.002, T1554, T1059.006

Detects AI agent write-mode modifications to security-critical source files, CI/CD pipeline configurations, container definitions, and dependency manifests. Only fires on write opens — read-only access excluded to reduce false positives. Categories include CI/CD configs (.gitlab-ci.yml, Jenkinsfile, GitHub Actions workflows), Dockerfiles, dependency manifests (package.json, go.mod, requirements.txt, Cargo.toml), and auth-related source code files.

Context: `signal_type="code_tamper"`, `pattern="{file_path}"`.

| Signal | Confidence |
|--------|------------|
| CI/CD config write (.gitlab-ci.yml, Jenkinsfile, .github/workflows/) | 0.90 |
| Dockerfile / docker-compose write | 0.90 |
| Dependency manifest write (package.json, go.mod, requirements.txt, etc.) | 0.80 |
| Auth-related source code write (auth/login/session/token in filename) | 0.70 |

### ai.container_escape (critical)

**Triggers on:** `file_open`, `process_exec` | **Window:** none | **MITRE:** T1611, T1610, T1613

Detects AI agent attempts to escape container isolation: accessing container runtime sockets (docker.sock, containerd.sock), kernel interfaces (/proc/sysrq-trigger, /proc/kcore), host filesystem mounts (/host/, /rootfs/), cgroup escape paths (release_agent), namespace files (/proc/self/ns/*), raw block devices, or executing container management tools (docker, kubectl, runc, ctr, crictl, kubelet).

Context: `signal_type="container_escape"`, `pattern="{file_path}"` (file); `signal_type="binary"`, `pattern="{cmdline}"` (exec).

| Signal | Confidence |
|--------|------------|
| Container runtime socket access (docker.sock, containerd.sock, crio.sock) | 0.95 |
| Kernel interface / cgroup release_agent write | 0.95 |
| Host filesystem / cgroup directory access | 0.90 |
| Container management tool exec (docker, kubectl, runc, ctr) | 0.90 |
| Namespace file access (/proc/self/ns/*) | 0.85 |
| Block device access (/dev/sd*, /dev/nvme*) | 0.85 |

### ai.discovery (low)

**Triggers on:** `process_exec` | **Window:** 60s | **MITRE:** T1082, T1083, T1057, T1016, T1049, T1033

Detects AI agent reconnaissance and pre-attack enumeration. High-value active scanners (nmap, masscan, nikto, linpeas, pspy) fire immediately at high severity. Common discovery commands (whoami, id, ifconfig, ps, netstat, etc.) only fire when 3+ distinct recon binaries execute within a 60-second window. Severity escalates with the number of distinct commands.

Context: `signal_type="discovery_cmd"`, `pattern="{cmdline}"` (scanners); `signal_type="discovery_burst"`, `pattern="pid:{pid}:discovery:{count}"` (burst).

| Signal | Confidence |
|--------|------------|
| Active scanner exec (nmap, masscan, nikto, linpeas, pspy) | 0.85 |
| 3-4 distinct discovery commands in 60s (low) | 0.55 |
| 5-7 distinct discovery commands in 60s (medium) | 0.70 |
| 8+ distinct discovery commands in 60s (high) | 0.80 |

### ai.command_activity (low)

**Triggers on:** `process_exec` | **Window:** none | **MITRE:** T1059

Catch-all audit rule tracking every command executed by an AI agent for visibility. Filters out Electron/Chromium subprocess internals, AI agent root binaries, Windows system startup noise, build tool internals, and bare runtime invocations. Extracts the inner user command from shell wrappers (bash -c "source ... && eval '...'") for clean display.

Context: `signal_type="command"`, `pattern="{display_cmd}"`.

| Signal | Confidence |
|--------|------------|
| Any non-noise command executed by AI agent | 0.30 |
| Script interpreter running a file (secondary) | 0.25 |

### ai.file_activity (low)

**Triggers on:** `file_open` | **Window:** none | **MITRE:** T1083

Catch-all audit rule tracking every file opened by an AI agent for visibility. Filters out runtime noise (/proc/, /sys/, /dev/), noisy extensions (.so, .dll, .pyc), VCS probes, temp/build/cache directories, zero-byte files, PATHEXT probes, and files already covered by higher-severity rules (credential_access, code_tampering, persistence) to avoid duplicates.

Context: `signal_type="file_activity"`, `pattern="{file_path}"`.

| Signal | Confidence |
|--------|------------|
| Any non-noise file opened by AI agent | 0.25 |

## Rule Interaction Map

```
ai.credential_access (Tier 1)         ai.data_exfiltration
  fires immediately on file_open        fires on net_connect if ANY
  of SSH keys, /etc/shadow, crypto      sensitive file (Tier 1+2) was
                                        read in last 15min
  CAN co-fire (correct — different signals)

ai.unauthorized_exec                   ai.unexpected_network
  binary blocklist OR cmdline           external non-standard port OR
  pattern match                         high-risk internal target
  Independent of each other

ai.excessive_writes                    ai.suspicious_dns
  path diversity scoring                agent-categorized domain queries
  Independent rules
```

## Finding Cooldown (FindingCooldown)

Rate-limits repeat findings per `finding.ID` (= `detection_id:host_id:pattern_key`).

| Rule | Window |
|------|--------|
| `ai.credential_access` | 15 min |
| `ai.unexpected_network` | 5 min |
| all others | 10 min (default) |

- First finding always emits
- Chain findings (`chain.*`) always bypass cooldown
- Background goroutine evicts expired entries every 5 min
- `done chan struct{}` + `Stop()` for clean shutdown

## Attack Chain Correlator (ChainCorrelator)

Buffers emitted findings per `host_id:session_id`. Session-first keying; falls back to `host_id:pid:PID` when no session available (prevents cross-process false positives).

### Chain Patterns

| Pattern ID | Steps | Window | Severity | Confidence | MITRE |
|------------|-------|--------|----------|------------|-------|
| `credential_theft` | credential_access → data_exfiltration | 20 min | critical | 0.95 | T1552, T1041 |
| `reverse_shell_setup` | unauthorized_exec → unexpected_network | 5 min | critical | 0.90 | T1059, T1071 |
| `lateral_movement` | unauthorized_exec → unexpected_network[internal_threat≠""] | 10 min | high | 0.85 | T1059, T1021 |
| `full_compromise` | credential_access → unauthorized_exec → (data_exfiltration OR unexpected_network) | 30 min | critical | 0.95 | T1552, T1059, T1041 |
| `persistence_backdoor` | privilege_escalation → persistence | 15 min | critical | 0.95 | T1548, T1053, T1546 |
| `supply_chain_attack` | code_tampering → (data_exfiltration OR unexpected_network) | 20 min | critical | 0.90 | T1195.002, T1041 |
| `data_staging` | excessive_writes → (data_exfiltration OR unexpected_network) | 20 min | critical | 0.90 | T1074, T1041 |
| `credential_persistence` | credential_access → persistence | 15 min | critical | 0.95 | T1552, T1546 |
| `privesc_credential_exfil` | privilege_escalation → credential_access → (data_exfiltration OR unexpected_network) | 30 min | critical | 0.95 | T1548, T1552, T1041 |
| `recon_to_escalation` | discovery → privilege_escalation | 15 min | high | 0.85 | T1082, T1548 |
| `container_breakout` | container_escape → (persistence OR credential_access OR privilege_escalation) | 10 min | critical | 0.95 | T1611, T1552, T1546 |

Chain findings:
- `DetectionID`: `chain.<pattern_id>`
- `ID`: `chain.<pattern_id>:<host_id>:<session_id>:<window_start_unix>` (deterministic for DB dedup)
- `Context`: `chain_pattern`, `chain_steps` (constituent finding IDs), `chain_window_secs`
- Bypass cooldown; stored via `FindingStore.Insert` (ON CONFLICT DO NOTHING)
- Background cleanup every 5 min (maxAge = 30 min buffer retention)

## Rule Exception Store (RuleExceptionStore)

Per-org DB-backed suppression. In-memory cached (30s refresh). Implements `detection.ExceptionChecker`.

### Schema (migration 049)

```sql
CREATE TABLE rule_exceptions (
    id BIGSERIAL PRIMARY KEY,
    org_id TEXT NOT NULL,
    detection_id TEXT NOT NULL,   -- "ai.credential_access" or "*" for all rules
    host_id TEXT NOT NULL,        -- specific host or "*" for all hosts
    context_key TEXT DEFAULT '',  -- context field to filter on
    context_value TEXT DEFAULT '', -- required value ("" = any non-empty)
    reason TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Matching Logic

1. `detection_id` must match finding's detection_id OR be `"*"`
2. `host_id` must match finding's host_id OR be `"*"`
3. If `context_key` set → finding must have matching context value
4. All conditions must pass for suppression

Nil-safe: `if s == nil { return false }`.

## Rule Settings Store (RuleSettingsStore)

Per-org tunable rule thresholds. In-memory cached (30s refresh). Implements `detection.RuleSettingsReader`.

### Schema (migration 050)

```sql
CREATE TABLE detection_rule_settings (
    org_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    setting_key TEXT NOT NULL,
    setting_value TEXT NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (org_id, rule_id, setting_key)
);
```

Composite cache key separator: `\x00` (null byte) — avoids collisions with dots in rule IDs (e.g. `ai.credential_access`).

Nil-safe: `GetFloat/GetInt` return defaults when store is nil.

## Finding Store (FindingStore)

PostgreSQL CRUD for findings. Org-scoped: all queries filter `(org_id = $X OR org_id IS NULL)` for backwards compat (migration 052).

### Key Methods

| Method | Purpose |
|--------|---------|
| `Insert(f)` | ON CONFLICT DO NOTHING (deterministic ID dedup) |
| `ListByHost(orgID, hostID, status, since, limit)` | Filtered list for a host |
| `ListAll(orgID, status, since, limit)` | All findings for org |
| `CountByStatus(orgID, since)` | Aggregate counts (total, pending, allowed, dismissed, suppressed) |
| `GetByID(orgID, id)` | Single finding (org-scoped) |
| `UpdateStatus(orgID, id, status, resolution, resolvedBy)` | Status change; returns ErrNotFound on 0 rows |
| `SetIncidentID(orgID, findingID, incidentID)` | Links finding to incident (Phase 4) |

SELECT columns include `incident_id` (added in migration 056).

## API Endpoints

### Findings

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| GET | `/api/v1/findings` | ListFindings | Filtered list with totals |
| PATCH | `/api/v1/findings/{id}` | ResolveFinding | Status transition + baseline learning |

ResolveFinding: when status = "allowed" → `BaselineCollector.LearnFromFinding()` → upsert with source='user_confirmed'. Uses `middleware.ActorFromContext()` for `resolvedBy`.

### Exceptions

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| GET | `/api/v1/exceptions` | ListExceptions | All exceptions for org |
| POST | `/api/v1/exceptions` | CreateException | Add new suppression rule |
| DELETE | `/api/v1/exceptions/{id}` | DeleteException | Remove exception (org-scoped) |

### Rule Settings

| Method | Path | Handler | Purpose |
|--------|------|---------|---------|
| GET | `/api/v1/detection/settings` | ListSettings | All custom settings for org |
| PUT | `/api/v1/detection/settings/{rule_id}` | UpsertSetting | Set/update threshold |
| DELETE | `/api/v1/detection/settings/{rule_id}/{key}` | DeleteSetting | Reset to default |

## Pipeline Integration

Full flow in `internal/ingest/live_ingest.go`:

```
1. Validation + sampling
2. Store in PostgreSQL (telemetry + canonical)
3. AI attribution
4. Tier 1 process tree write (Neo4j)
5. Detection engine evaluate → findings[]
6. For each finding:
   a. Baseline suppression (MatchesBaseline)
   b. Exception suppression (ExceptionChecker.Matches)
   c. Cooldown check (FindingCooldown.ShouldEmit)
   d. Store to FindingStore.Insert
   e. Track as emittedFinding
7. Chain correlation: feed emittedFindings → ChainCorrelator.Ingest → store chain findings
8. Incident correlation: feed emittedFindings + chainFindings → IncidentCorrelator.Ingest
9. If zero findings: behavioral baseline observe (ShouldBaseline → Observe)
10. Tier 2 event buffer push
```

All optional components (cooldown, chainCorrelator, exceptionChecker, ruleSettings, incidentCorrelator) accept nil — pass nil to disable.

## Wiring (cmd/api/main.go + cmd/telemetry/main.go)

Both planes wire identical detection stacks:
- `detection.NewEngine()` → `engine.RegisterPack(ai_pack.NewAIPack())`
- `detection.NewBaselineCollector(db)` → `defer bc.Stop()`
- `detection.NewFindingCooldown()` → `defer cooldown.Stop()`
- `detection.NewChainCorrelator()` → `defer chain.Stop()`
- `storage.NewRuleExceptionStore(db)` → `defer res.Stop()`
- `storage.NewRuleSettingsStore(db)` → `defer rss.Stop()`
- Pass all to `IngestCanonicalEvents()`

## Database Migrations

| Migration | Purpose |
|-----------|---------|
| 048 | `findings.confidence` column |
| 049 | `rule_exceptions` table |
| 050 | `detection_rule_settings` table |
| 051 | Default safe domains (12 AI/cloud providers) |
| 052 | `findings.org_id` column + indexes |
| 056 | `findings.incident_id` column (Phase 4) |

## Resilience & Edge Cases

- **Panic recovery**: `safeEvaluate()` wraps every `d.Evaluate()` call with defer/recover. A panicking rule doesn't crash the pipeline.
- **Nil-safe stores**: `RuleExceptionStore.Matches()`, `RuleSettingsStore.GetFloat/GetInt`, `BaselineCollector.MatchesBaseline/Observe/LearnFromFinding` all handle nil receiver gracefully (return safe defaults).
- **Go nil interface pitfall**: concrete nil pointer passed as interface = non-nil interface. All stores use `if s == nil` guards on method receivers.
- **Background goroutines**: All 5 components (BaselineCollector, FindingCooldown, RuleExceptionStore, RuleSettingsStore, ChainCorrelator) have `done chan struct{}` + `Stop()` method + select-based loop. Both main.go files call `defer X.Stop()`.
- **Org isolation**: FindingStore queries use `AND (org_id = $X OR org_id IS NULL)` for backwards compat. Baselines, exceptions, and settings are all org-scoped.
- **Source preservation**: Baseline upsert never downgrades `user_confirmed` → `observed` (CASE expression in ON CONFLICT).
- **Chain buffer key**: Sessionless findings grouped by PID (was "default" — caused cross-process false positives, fixed).
- **Composite key separator**: RuleSettingsStore uses `\x00` not `.` to avoid splitting dotted rule IDs.
