# AI Tool Hooks (correlic-hook)

`correlic-hook` is a small binary that Claude Code and Cursor run on every
tool call. It records exactly what the AI did — the command, the file, the
URL, the session — with perfect attribution, and it can deny a command or a
file access before it runs using the organisation's existing block rules.

It complements the kernel agents (eBPF on Linux, ETW on Windows): where an
agent runs, hook events and kernel events share the same host; where none
runs — in particular on macOS, where Endpoint Security needs a paid Apple
account — the hook is the only host-level signal and still gives a complete,
attributed audit trail of the AI's actions.

It is pure Go, builds for Linux, macOS and Windows, needs no root and no
kernel driver, and never prints anything on stdout except a deny decision.

## What is captured

Every hook invocation becomes one canonical event (`POST /ingest/events`,
exactly like the agent's ingest sink):

| Field | Value |
|-------|-------|
| `type` / `source` | `ai_tool_call` / `hook` |
| `host_id` | the agent's host id when readable, else a stable per-user id (see below) |
| `actor` | `pid` = the AI tool's process (the hook's parent), `comm` = `claude` or `cursor`, `user`, `session_id` |
| `target.file_path` | the file a Read/Edit/Write/NotebookEdit (Claude Code) or beforeReadFile/afterFileEdit (Cursor) touched |
| `target.domain` | the host of a WebFetch URL |
| `context.is_ai`, `ai_type` | `true`, `claude-code` or `cursor` |
| `context.ai_session_id` | Claude Code `session_id` / Cursor `conversation_id` |
| `context.hook_event`, `phase` | the raw event name; `pre`, `post`, `session` or `prompt` |
| `context.tool_name`, `tool_use_id` | `Bash`, `Edit`, `mcp__server__tool`, ... (Cursor: `shell`, `mcp`, `file_edit`, `file_read` and a derived `tool_use_id` that pairs before/after events) |
| `context.command`, `file_path`, `url`, `cwd`, `workspace` | what the tool was asked to do |
| `context.decision` | `allowed` or `blocked` (+ `block_rule_id`, `block_signal_type`, `block_candidate`) |
| `context.success`, `error`, `interrupted`, `duration_ms` | post events only: the outcome, `error` is the first line of the failure (e.g. `Exit code 1`) |

### What is not captured (privacy)

The hook never sends file contents, tool output (`tool_response` bodies,
shell stdout/stderr), edit strings (`old_string`/`new_string`, `content`,
Cursor `edits`), prompts or transcripts. Only commands, paths, URLs, names
and ids are kept. `UserPromptSubmit` / `beforeSubmitPrompt` are not even
registered by `setup`; if such an event arrives it is recorded as a bare
`phase: prompt` event without content.

## Install

The binary ships next to `correlic-agent` in every release: `bin/correlic-hook`
in the Linux bundle, `/usr/bin/correlic-hook` from the .deb/.rpm,
`bin\correlic-hook.exe` in the Windows bundle. On a Mac (or any machine
without an installer) build it from source:

```bash
cd agent && go build -o correlic-hook ./cmd/correlic-hook   # CGO not needed
```

### 1. Configure

Write `~/.correlic/hook.yaml` (the keys are a subset of `agent.yaml`, so an
existing agent config can also be pointed at with `CORRELIC_HOOK_CONFIG`):

```yaml
telemetry_url: "https://correlic.example.com:8081"   # the telemetry plane
api_key: "crl_agent_..."                              # an agent-type key (correlic-admin create-api-key --type agent)
# mTLS, when the backend requires it:
tls_ca_file: "/path/to/ca.crt"
tls_client_cert_file: "/path/to/client.crt"
tls_client_key_file: "/path/to/client.key"
# allow_insecure_http: true      # http:// URLs, local development only
# host_id: ""                    # override the host id
# block_enabled: true            # evaluate block rules on pre-tool events (default true)
# cache_dir: ~/.correlic/hook    # rule cache + spool of undelivered events
```

Environment variables override the file: `CORRELIC_TELEMETRY_URL`,
`CORRELIC_API_KEY`, `CORRELIC_TLS_CA_FILE`, `CORRELIC_TLS_CLIENT_CERT_FILE`,
`CORRELIC_TLS_CLIENT_KEY_FILE`; `CORRELIC_HOOK_CONFIG` names another config
file. Unknown keys are ignored. Keep the file private (`chmod 600`): it holds
the API key.

### 2. Register with the AI tools

```bash
correlic-hook setup                      # Claude Code and Cursor, user-global
correlic-hook setup --claude             # only ~/.claude/settings.json
correlic-hook setup --cursor             # only ~/.cursor/hooks.json
correlic-hook setup --project ~/src/app  # <project>/.claude/settings.json and <project>/.cursor/hooks.json
```

`setup` merges the entries into the existing files without touching anything
else in them (other hooks, permissions, model settings), using the absolute
path of the running binary. It is idempotent: run it again after moving the
binary and the existing `correlic-hook` entries are updated in place.

Claude Code gets `PreToolUse`, `PostToolUse` and `PostToolUseFailure` with the
matcher `Bash|Edit|Write|MultiEdit|NotebookEdit|Read|WebFetch` plus a second
entry matching `mcp__.*`, and `SessionStart` / `SessionEnd`:

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash|Edit|Write|MultiEdit|NotebookEdit|Read|WebFetch",
                           "hooks": [{"type": "command", "command": "/usr/bin/correlic-hook"}]},
                          {"matcher": "mcp__.*", "hooks": [{"type": "command", "command": "/usr/bin/correlic-hook"}]}]}}
```

Cursor gets `beforeShellExecution`, `afterShellExecution`,
`beforeMCPExecution`, `afterMCPExecution`, `afterFileEdit`, `beforeReadFile`,
`sessionStart` and `sessionEnd`:

```json
{"version": 1, "hooks": {"beforeShellExecution": [{"command": "/usr/bin/correlic-hook"}]}}
```

Restart Claude Code / Cursor afterwards (hooks are read at startup).

### 3. Verify

```bash
correlic-hook test
```

prints the resolved configuration (key redacted), the host id, the backend's
answer to one synthetic `ai_tool_call` event (`accepted=1`) and the number of
block rules it can see. The event is tagged `context.synthetic: true`.

The dashboard's agent activity stream (`GET /agents/activity`) then shows a
session named `claude-code (hooks)` or `cursor (hooks)` on hosts without a
kernel agent; on hosts with one, hook events join the agent's AI session.

## Blocking

For `PreToolUse` (Claude Code) and `beforeShellExecution`,
`beforeMCPExecution`, `beforeReadFile` (Cursor) the hook evaluates the org's
enabled block rules (`GET /agent/block-rules`, the same rules the agent
enforces) before the tool runs:

- `process_exec` rules match the executable of every simple command in the
  command line (split on `&&`, `||`, `;`, `|`, newlines; `sudo`, `env`,
  `nohup`, `exec`, `time`, `nice` and `VAR=value` prefixes are skipped). The
  match is on the basename, case-insensitive, exactly like the agent: a rule
  `nc` matches `/usr/bin/nc` and `NC`, not `ncat`; a rule `mimikatz.exe`
  matches `mimikatz.exe` only.
- `file_open` rules are globs matched against the path of a Read/Edit/Write
  tool or an MCP tool's `path`/`file_path`, and against the path-like tokens
  of a shell command (`cat /etc/shadow`, `cat ~/.aws/credentials`), so a
  file rule stops the command even though the kernel never saw the open.
- `net_connect` rules do not apply to hooks.

On a match the hook prints the tool's deny document and exits 0:

```json
{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
  "permissionDecisionReason": "Correlic block rule #12 (process_exec \"nc\") denied this command: nc"}}
```

```json
{"permission": "deny", "user_message": "Correlic block rule #12 ...", "agent_message": "Correlic block rule #12 ... Choose another approach; do not retry the same call."}
```

The `ai_tool_call` event is sent with `decision: blocked` and the block is
reported to `POST /agent/block-events` (visible under block events in the
dashboard, `agent_id: correlic-hook`, `success: true` because the call was
denied before it ran).

When the call is allowed the hook prints nothing: for Claude Code an empty
stdout means "no decision", so the user's own permission prompts still
apply (an explicit `allow` would bypass them). Rules are cached for 60 s in
`<cache_dir>/block-rules.json` (refreshed with `If-None-Match`) so hooks stay
fast; if the rules cannot be fetched and no cache exists, the call is
allowed. `block_enabled: false` turns evaluation off entirely; post events are
never denied.

## Detection

Hook events run through the detection engine like any other AI-attributed
event. `ai.tool_call_sensitive_path` (high) fires when the command or file
path of a pre event matches the sampler's built-in suspicious-path patterns
(`.ssh/`, `.aws/`, `/etc/shadow`, `.env`, certificates, secrets, ...). For
commands only path-like tokens are tested, so `git config` stays quiet while
`cat ~/.aws/credentials` does not. A denied call is still reported — the
attempt is the signal. Findings carry `signal_type` `file_activity` or
`command` and a `pattern`, so they can be baselined like the kernel rules.

`ai_tool_call` is on the sampler's always-keep list (hook events also carry
`is_ai`, which keeps them anyway).

## Timing, failure modes, spooling

The whole invocation is budgeted at about two seconds: rule fetch ≤ 0.7 s,
event delivery ≤ 0.8 s, block report ≤ 0.4 s, then spool retry with what is
left. Every error fails open: the hook exits 0 with no output, so a slow or
unreachable backend never holds the AI tool up and never blocks it (Claude
Code also ignores hooks that time out).

Events that could not be delivered because of a network error or a 5xx are
written to `<cache_dir>/spool/` (at most 500 files, oldest dropped) and sent
by the next invocation, oldest first, in batches of 100. 401/403 (the key is
not an agent key for this org) and other 4xx responses drop the event and
are logged; events older than six days are discarded (the backend rejects
events older than seven).

## Host id

Events carry, in order of preference: the `host_id` from the config; the
agent's host id file (`/var/lib/correlic/host_id`,
`/Library/Application Support/Correlic/host_id`, `C:\ProgramData\Correlic\host_id`)
when the hook can read it — on Windows it usually can, so hook and agent
events share one host; otherwise a stable per-user id generated once into
`~/.correlic/host_id`. The agent's directory is root-only on Linux and
macOS, so an unprivileged hook normally uses the per-user id there; set
`host_id` in `hook.yaml` to the agent's value if you want them merged.

## Troubleshooting

- **Nothing shows up**: run `correlic-hook test`. "not configured" means no
  `hook.yaml` and no `CORRELIC_TELEMETRY_URL`; a 401/403 means the key is
  not an agent-type key of this org; a TLS error means the backend's CA is
  not in `tls_ca_file` (or mTLS is required and no client cert is set).
- **Logs**: `~/.correlic/hook.log` (rotated at 1 MiB to `hook.log.1`).
  `CORRELIC_HOOK_DEBUG=1` also prints to stderr, which Claude Code shows in
  its hook output — never set it in a production hook.
- **Hook not firing**: check that `setup` wrote the file the tool reads
  (`~/.claude/settings.json` vs `<project>/.claude/settings.json`; `/hooks`
  in Claude Code lists the active hooks) and restart the tool.
- **A command is denied unexpectedly**: the reason names the rule id;
  disable or edit it under Block Rules. `block_enabled: false` stops
  evaluation on this machine. The cache refreshes within 60 s.
- **Spool growing**: the backend is unreachable; `ls ~/.correlic/hook/spool`
  and `hook.log` show why. The spool is bounded at 500 events.
- **Cursor**: Cursor's hook payloads were implemented from secondary
  sources; unknown events are recorded generically (`phase: other`) and
  never denied. If a `before*` event is not blocked as expected, run with
  `CORRELIC_HOOK_DEBUG=1` to see how it was parsed.
