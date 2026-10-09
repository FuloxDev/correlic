# Correlic MCP Server (`correlic-mcp`)

`correlic-mcp` is a [Model Context Protocol](https://modelcontextprotocol.io)
server that puts Correlic's findings, incidents, agent activity and telemetry
in front of any MCP client: Claude Code, Claude Desktop, Cursor and others.
Ask the assistant "what did my coding agents do in the last hour?" or "is the
critical incident on dev-laptop-01 real?" and it answers from the same data
the dashboard shows, with the ids it needs to dig deeper.

It is a single static binary (`backend/cmd/mcp`), speaks MCP over stdio
(newline-delimited JSON-RPC 2.0) and is a thin client of the Correlic REST
API: every tool call is one or two HTTPS requests authenticated with the API
key you configure. It stores nothing and needs no database access.

## Install

The binary ships with every release next to `correlic-admin`:

| Platform | Location |
|----------|----------|
| Linux tar.gz bundle | `bin/correlic-mcp` |
| `.deb` / `.rpm` | `/usr/bin/correlic-mcp` |
| Windows bundle | `bin\correlic-mcp.exe` |
| From source | `cd backend && go build -o correlic-mcp ./cmd/mcp` |

The MCP server runs on the machine where the MCP client runs (your laptop),
not necessarily on the Correlic host: it only needs to reach the API plane.

## Configuration

Everything is passed by environment variables; the client launches the
binary and inherits them from its config.

| Variable | Meaning |
|----------|---------|
| `CORRELIC_API_URL` | API plane base URL (default `https://localhost:8080`) |
| `CORRELIC_API_KEY` | A dashboard API key (not an agent key). The key's organisation and role decide what the tools can see. |
| `CORRELIC_TLS_CA_FILE` | CA that signed the API certificate: `ca.crt` from `correlic-admin bootstrap` / `gen-certs.sh` |
| `CORRELIC_TLS_CLIENT_CERT_FILE` | Client certificate for mTLS (`client.crt`) |
| `CORRELIC_TLS_CLIENT_KEY_FILE` | Its private key (`client.key`) |
| `CORRELIC_MCP_ALLOW_WRITES` | `true` enables the write tools; same as `--allow-writes` |

The API plane requires mTLS, so the three `CORRELIC_TLS_*` variables are
needed whenever you talk to it directly (they are the same files and names the
agent and `correlic-hook` use). Through a proxy that terminates TLS for you,
leave them unset.

Flags: `--allow-writes` enables `correlic.finding.resolve`; `--version`
prints the version.

### Claude Code

```bash
claude mcp add correlic \
  -e CORRELIC_API_URL=https://correlic.example.com:8080 \
  -e CORRELIC_API_KEY=ck_... \
  -e CORRELIC_TLS_CA_FILE=/etc/correlic/certs/ca.crt \
  -e CORRELIC_TLS_CLIENT_CERT_FILE=/etc/correlic/certs/client.crt \
  -e CORRELIC_TLS_CLIENT_KEY_FILE=/etc/correlic/certs/client.key \
  -- correlic-mcp
```

Add `--allow-writes` after `correlic-mcp` to let the assistant resolve
findings. `claude mcp list` shows the server; in a session, `/mcp` lists the
tools as `mcp__correlic__correlic.findings.list` and so on.

### Claude Desktop

`claude_desktop_config.json` (Settings > Developer > Edit Config):

```json
{
  "mcpServers": {
    "correlic": {
      "command": "/usr/bin/correlic-mcp",
      "args": [],
      "env": {
        "CORRELIC_API_URL": "https://correlic.example.com:8080",
        "CORRELIC_API_KEY": "ck_...",
        "CORRELIC_TLS_CA_FILE": "/etc/correlic/certs/ca.crt",
        "CORRELIC_TLS_CLIENT_CERT_FILE": "/etc/correlic/certs/client.crt",
        "CORRELIC_TLS_CLIENT_KEY_FILE": "/etc/correlic/certs/client.key"
      }
    }
  }
}
```

On Windows use the `.exe` path (`C:\\Program Files\\Correlic\\bin\\correlic-mcp.exe`)
and escape the backslashes.

### Cursor

`.cursor/mcp.json` in the project (or `~/.cursor/mcp.json` globally):

```json
{
  "mcpServers": {
    "correlic": {
      "command": "correlic-mcp",
      "args": ["--allow-writes"],
      "env": {
        "CORRELIC_API_URL": "https://correlic.example.com:8080",
        "CORRELIC_API_KEY": "ck_...",
        "CORRELIC_TLS_CA_FILE": "/etc/correlic/certs/ca.crt",
        "CORRELIC_TLS_CLIENT_CERT_FILE": "/etc/correlic/certs/client.crt",
        "CORRELIC_TLS_CLIENT_KEY_FILE": "/etc/correlic/certs/client.key"
      }
    }
  }
}
```

Cursor shows the server under Settings > MCP; enable the tools you want the
agent to use.

## Security model

- **The key decides.** The server has no identity of its own: it forwards
  `Authorization: Bearer <CORRELIC_API_KEY>` and the API applies that key's
  organisation scope and role. A member key sees the member's own agents; an
  admin key sees the organisation. Agent keys (the ones in `agent.yaml`) are
  rejected on every query endpoint, so they cannot be used here. Create a
  dedicated key for the MCP server (`correlic-admin create-api-key` or
  Settings > API Keys) so it can be revoked on its own.
- **Read-only by default.** Only the read tools are listed. With
  `--allow-writes` the server also lists `correlic.finding.resolve`
  (allow / dismiss / investigate a finding); without the flag a call to it is
  answered with a tool error and never reaches the API. The write goes through
  the same `PATCH /api/v1/findings/{id}` route the dashboard uses and is
  recorded with the key's user as `resolved_by`.
- **Nothing is cached or stored.** Every call is a fresh request; no file on
  disk is written. The key is only read from the environment.
- **mTLS to the API.** The client certificate authenticates the connection
  like any other API client; the API key authenticates the user.
- **What the model sees.** Tool results are the API responses: finding and
  incident context (file paths, commands, destinations), activity feeds and
  raw telemetry events. Do not hand the server to an assistant you would not
  show the dashboard to.
- **Transport.** stdio only; the server reads requests from stdin and writes
  responses to stdout. Logs go to stderr.

## Tool reference

All results are one `text` content block holding JSON (compacted to one
line for the stdio transport). API failures (`401`, `403`, `404`, `5xx`) and
argument errors are returned as MCP tool errors (`isError: true` with the
message), never as protocol errors, so the assistant can read and recover
from them.

`since` arguments accept an RFC 3339 timestamp (`2026-10-09T10:00:00Z`) or a
duration back from now (`30m`, `6h`, `7d`, `2w`).

| Tool | Arguments | Backend route | Notes |
|------|-----------|---------------|-------|
| `correlic.agents.list` | `state` (optional filter) | `GET /agents` | Hosts with hostname, OS, profile, version, state, first/last seen. Start here for host ids. |
| `correlic.agents.activity` | `minutes` (1–10080, default 30), `min_significance` (1–5, default 2) | `GET /agents/activity` | "What did my agents do in the last N minutes": one entry per AI session with scored actions (commands, files, connections) and stats. |
| `correlic.findings.list` | `severity`, `status` (`pending`/`allowed`/`dismissed`/`investigating`/`blocked`), `host`, `since` (default 24h), `limit` (default 50, max 500) | `GET /api/v1/findings` | `severity` is filtered client-side (the API has no severity parameter; up to 2000 rows are fetched). Returns `findings`, `count`, `total`, `total_pending` and the applied `filters`. |
| `correlic.incidents.list` | `severity`, `status` (`open`/`investigating`/`resolved`/`dismissed`/`auto_resolved`), `host`, `category`, `since` (default 7d), `limit` | `GET /api/v1/incidents` | Incidents with `finding_ids`, MITRE techniques and status counts. |
| `correlic.incident.get` | `id` (required), `max_timeline` (default 100, max 200), `full` (bool) | `GET /api/v1/incidents/{id}` | Incident, its findings, the event timeline (cut to `max_timeline`, with `timeline_truncated`/`timeline_total` when cut), process details; `full=true` adds the process tree and event graph. |
| `correlic.finding.resolve` | `id`, `status` (`allowed`/`dismissed`/`investigating`), `resolution`, `expires_in` (`7d`/`30d`/`90d`, with `allowed`) | `PATCH /api/v1/findings/{id}` | **Only with `--allow-writes`.** Resolving every finding of an incident resolves the incident. |
| `correlic.ai.proof` | `since`, `until` (required), `agent_id`, `include_non_ai` | `GET /ai/proof` | Evidence-backed AI activity report for a window. |
| `correlic.network.summary` | `since`, `until`, `agent_id` | `GET /network/summary` | DNS + connection aggregates. |
| `correlic.ports.summary` | `since`, `until`, `agent_id` | `GET /ports/summary` | Listening services and exposure. |
| `correlic.telemetry.search` | `event_type`, `agent_id`, `since`, `until`, `pid`, `limit`, `offset`, `ai_only` | `GET /telemetry` | Raw telemetry events, newest first. |

The server implements MCP revision `2024-11-05` (`initialize`, `tools/list`,
`tools/call`, `ping`); a client that asks for a newer revision is answered
with that one, as the specification's version negotiation requires, and the
tool subset is identical across revisions. The `initialize` result carries
`instructions` that tell the model where to start.

## Trying it without an MCP client

`scripts/dev/mcp_client.py` is a 100-line JSON-RPC client that launches the
server, performs the handshake and runs tool calls from the command line:

```bash
export CORRELIC_API_URL=https://127.0.0.1:8080 CORRELIC_API_KEY=ck_... \
       CORRELIC_TLS_CA_FILE=.certs/ca.crt CORRELIC_TLS_CLIENT_CERT_FILE=.certs/client.crt \
       CORRELIC_TLS_CLIENT_KEY_FILE=.certs/client.key
scripts/dev/mcp_client.py --server ./correlic-mcp \
    correlic.agents.list \
    'correlic.findings.list:{"severity":"critical","since":"24h"}'
```

## Captured transcript

Everything below is real output, captured on 2026-10-09 with
`scripts/dev/mcp_client.py` against a local stack started for this purpose
(API plane on `:28080`, telemetry plane on `:28081`, fresh database,
`correlic-admin bootstrap`). The data came from one heartbeat, two
`correlic-admin emit-*` commands (`emit-ssh-key-read`, `emit-process-exec`),
one canonical event through `correlic-admin ingest-events`, and one
`POST /ingest/events` batch of five AI-attributed events for a Claude Code
session (`claude-code/cli.js` exec, `git status`, reads of
`~/.ssh/id_ed25519` and `~/.aws/credentials`, a `curl` to `203.0.113.10`),
which the live detection turned into six findings and two incidents.

Lines starting with `-->` are what the client wrote to the server's stdin,
`<--` what the server answered on stdout. On the wire each response is one
line and each tool result's `text` is a JSON *string*; the client script
parses it and pretty-prints the whole message for readability. Long results
are trimmed where marked; ids, timestamps and values are as returned.

**initialize (the client asks for 2025-06-18, the server answers with the revision it implements)**

```json
--> {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcp_client.py", "version": "1"}}}
<-- {
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "capabilities": {
      "tools": {
        "listChanged": false
      }
    },
    "instructions": "Correlic is a runtime security monitor for AI coding agents. Start with correlic.agents.list to learn the host ids, correlic.agents.activity for what the agents did recently, correlic.findings.list / correlic.incidents.list for detections and correlic.incident.get for the full story of one incident. Timestamps are RFC 3339 UTC; `since` also accepts durations like 30m, 6h, 7d. This server is read-only.",
    "protocolVersion": "2024-11-05",
    "serverInfo": {
      "name": "correlic-mcp",
      "version": "1.1.0-dev"
    }
  }
}
```

**tools/list (descriptions and schemas trimmed; the full text is in the tool reference above)**

```json
--> {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
<-- {
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "correlic.ai.proof",
        "description": "Generate an AI Proof report: evidence-backed summary of what AI agents did on monitored ho…",
        "inputSchema": "…"
      },
      {
        "name": "correlic.network.summary",
        "description": "Network summary for a time window: DNS lookups and outbound connections aggregated by dest…",
        "inputSchema": "…"
      },
      {
        "name": "correlic.ports.summary",
        "description": "Listening ports summary for a time window: open services and their exposure across hosts.",
        "inputSchema": "…"
      },
      {
        "name": "correlic.telemetry.search",
        "description": "Search raw telemetry events (process_exec, file_open, net_connect, dns_query, ...) with fi…",
        "inputSchema": "…"
      },
      {
        "name": "correlic.findings.list",
        "description": "List detection findings (one per matched rule, e.g. ai.credential_access). Filter by sever…",
        "inputSchema": "…"
      },
      {
        "name": "correlic.incidents.list",
        "description": "List incidents: clusters of related findings on one host with a severity, category, MITRE …",
        "inputSchema": "…"
      },
      {
        "name": "correlic.incident.get",
        "description": "Full detail of one incident: the incident record, its findings, a chronological timeline o…",
        "inputSchema": "…"
      },
      {
        "name": "correlic.agents.activity",
        "description": "What did my AI agents do recently: a human-readable, significance-scored activity feed per…",
        "inputSchema": "…"
      },
      {
        "name": "correlic.agents.list",
        "description": "List the monitored hosts (agents) with hostname, OS, profile, version, state and last-seen…",
        "inputSchema": "…"
      }
    ]
  }
}
```

**correlic.agents.list**

```json
--> {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "correlic.agents.list", "arguments": {}}}
<-- {
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": {
          "agents": [
            {
              "agent_id": "dev-laptop-01",
              "first_seen_at": "2026-10-09T11:14:03.374071Z",
              "hostname": "dev-laptop-01",
              "last_seen_at": "2026-10-09T11:14:03.374071Z",
              "liveness": "",
              "os": "linux",
              "profile": "developer",
              "state": "active",
              "user_id": "a284e275-6e37-4bd6-9719-cc672817c784",
              "version": "1.0.1"
            }
          ],
          "count": 1
        }
      }
    ],
    "isError": false
  }
}
```

**correlic.agents.activity (actions after the fourth trimmed)**

```json
--> {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "correlic.agents.activity", "arguments": {"minutes": 60, "min_significance": 2}}}
<-- {
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "content": [
      {
        "type": "text",
        "text": {
          "agents": [
            {
              "agent_name": "node",
              "agent_pid": 4200,
              "ai_type": "claude",
              "host_id": "dev-laptop-01",
              "exe_path": "/usr/bin/node",
              "started_at": "2026-10-09T11:11:03Z",
              "duration": "3m",
              "actions": [
                {
                  "timestamp": "2026-10-09T11:11:03Z",
                  "category": "command",
                  "action": "⚙️ node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
                  "detail": "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
                  "significance": 2,
                  "event_id": "evt-claude-exec",
                  "event_type": "process_exec",
                  "process_pid": 4200,
                  "process_comm": "node"
                },
                {
                  "timestamp": "2026-10-09T11:12:03Z",
                  "category": "command",
                  "action": "⚙️ Ran: git status",
                  "detail": "git status",
                  "significance": 4,
                  "event_id": "evt-claude-git",
                  "event_type": "process_exec",
                  "process_pid": 4201,
                  "process_comm": "git"
                },
                {
                  "timestamp": "2026-10-09T11:12:03Z",
                  "category": "file",
                  "action": "🔑 Read sensitive file /home/dev/.ssh/id_ed25519",
                  "detail": "/home/dev/.ssh/id_ed25519",
                  "significance": 5,
                  "event_id": "evt-claude-sshkey",
                  "event_type": "file_open",
                  "process_pid": 4202,
                  "process_comm": "cat"
                },
                {
                  "timestamp": "2026-10-09T11:13:03Z",
                  "category": "file",
                  "action": "🔑 Read sensitive file /home/dev/.aws/credentials",
                  "detail": "/home/dev/.aws/credentials",
                  "significance": 5,
                  "event_id": "evt-claude-awscreds",
                  "event_type": "file_open",
                  "process_pid": 4203,
                  "process_comm": "cat"
                }
              ],
              "stats": {
                "files_modified": 0,
                "files_read": 2,
                "commands_run": 2,
                "connections": 1,
                "dns_lookups": 0,
                "total_events": 5
              },
              "child_count": 4
            }
          ],
          "window_start": "2026-10-09T10:14:38.45557087Z",
          "window_end": "2026-10-09T11:14:38.45693924Z"
        }
      }
    ],
    "isError": false
  }
}
```

**correlic.findings.list (second finding trimmed)**

```json
--> {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "correlic.findings.list", "arguments": {"severity": "critical", "since": "24h", "limit": 5}}}
<-- {
  "jsonrpc": "2.0",
  "id": 5,
  "result": {
    "content": [
      {
        "type": "text",
        "text": {
          "count": 2,
          "filters": {
            "host": "",
            "limit": 5,
            "severity": "critical",
            "since": "2026-10-08T11:14:38Z",
            "status": ""
          },
          "findings": [
            {
              "anchor_event": "evt-claude-awscreds",
              "confidence": 0.6,
              "context": {
                "ai_type": "claude",
                "comm": "cat",
                "file_path": "/home/dev/.aws/credentials",
                "file_size": 116,
                "mitre_techniques": [
                  "T1552"
                ],
                "pattern": "/home/dev/.aws/**",
                "pid": 4203,
                "signal_type": "credential_file"
              },
              "created_at": "2026-10-09T11:14:03.471241Z",
              "detection_id": "ai.credential_access",
              "host_id": "dev-laptop-01",
              "id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.aws/**",
              "incident_id": "inc:1aa9073877c24f78:1791544443",
              "org_id": "c31c4782-5af9-44e4-9f0a-d89ba2710484",
              "related_events": null,
              "severity": "critical",
              "status": "pending",
              "summary": "claude process accessed /home/dev/.aws/credentials",
              "suppressed": false,
              "title": "AI agent accessed sensitive credentials"
            },
            "… (1 more finding trimmed)"
          ],
          "total": 6,
          "total_pending": 6
        }
      }
    ],
    "isError": false
  }
}
```

**correlic.incidents.list (org_id, context_summary and timestamps trimmed)**

```json
--> {"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "correlic.incidents.list", "arguments": {"since": "7d"}}}
<-- {
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "content": [
      {
        "type": "text",
        "text": {
          "count": 2,
          "counts": {
            "total": 2,
            "open": 1,
            "investigating": 0,
            "resolved": 0,
            "dismissed": 0,
            "auto_resolved": 1
          },
          "incidents": [
            {
              "id": "inc:c158c4ad8f51c0c5:1791544443",
              "host_id": "dev-laptop-01",
              "category": "exfiltration",
              "severity": "low",
              "confidence": 0.4,
              "title": "claude data exfiltration campaign",
              "summary": "AI agent made unexpected external connection",
              "mitre_techniques": [
                "T1071.001"
              ],
              "finding_ids": [
                "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.unexpected_network:dev-laptop-01:203.0.113.0/24:443"
              ],
              "started_at": "2026-10-09T11:14:03.491999Z",
              "status": "auto_resolved"
            },
            {
              "id": "inc:1aa9073877c24f78:1791544443",
              "host_id": "dev-laptop-01",
              "category": "credential_theft",
              "severity": "critical",
              "confidence": 0.75,
              "title": "claude credential access campaign",
              "summary": "AI agent accessed sensitive credentials",
              "mitre_techniques": [
                "T1552",
                "T1552.004"
              ],
              "finding_ids": [
                "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.ssh/**",
                "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.aws/**"
              ],
              "started_at": "2026-10-09T11:14:03.461452Z",
              "status": "open"
            }
          ]
        }
      }
    ],
    "isError": false
  }
}
```

**correlic.incident.get (findings reduced to ids, timeline cut to three entries, process details trimmed)**

```json
--> {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "correlic.incident.get", "arguments": {"id": "inc:1aa9073877c24f78:1791544443", "max_timeline": 5}}}
<-- {
  "jsonrpc": "2.0",
  "id": 7,
  "result": {
    "content": [
      {
        "type": "text",
        "text": {
          "incident": {
            "category": "credential_theft",
            "confidence": 0.75,
            "finding_ids": [
              "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.ssh/**",
              "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.aws/**"
            ],
            "findings": [
              {
                "detection_id": "ai.credential_access",
                "id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.ssh/**",
                "severity": "critical",
                "status": "pending",
                "title": "AI agent accessed sensitive credentials"
              },
              {
                "detection_id": "ai.credential_access",
                "id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.aws/**",
                "severity": "critical",
                "status": "pending",
                "title": "AI agent accessed sensitive credentials"
              }
            ],
            "host_id": "dev-laptop-01",
            "id": "inc:1aa9073877c24f78:1791544443",
            "mitre_techniques": [
              "T1552",
              "T1552.004"
            ],
            "process_details": "… (6 entries trimmed)",
            "severity": "critical",
            "status": "open",
            "summary": "AI agent accessed sensitive credentials",
            "timeline": [
              {
                "detail": "claude process accessed /home/dev/.ssh/id_ed25519",
                "finding_id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.ssh/**",
                "pid": 4202,
                "severity": "critical",
                "timestamp": "2026-10-09T11:14:03.461452Z",
                "title": "AI agent accessed sensitive credentials",
                "type": "finding"
              },
              {
                "detail": "claude process accessed /home/dev/.aws/credentials",
                "finding_id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.credential_access:dev-laptop-01:/home/dev/.aws/**",
                "pid": 4203,
                "severity": "critical",
                "timestamp": "2026-10-09T11:14:03.471241Z",
                "title": "AI agent accessed sensitive credentials",
                "type": "finding"
              }
            ],
            "title": "claude credential access campaign"
          }
        }
      }
    ],
    "isError": false
  }
}
```

**correlic.finding.resolve without --allow-writes**

```json
--> {"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "correlic.finding.resolve", "arguments": {"id": "x", "status": "dismissed"}}}
<-- {
  "jsonrpc": "2.0",
  "id": 9,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "writes are disabled: start correlic-mcp with --allow-writes to resolve findings"
      }
    ],
    "isError": true
  }
}
```

**tools/list with --allow-writes (names only)**

```json
--> {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
<-- {
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      "correlic.ai.proof",
      "correlic.network.summary",
      "correlic.ports.summary",
      "correlic.telemetry.search",
      "correlic.findings.list",
      "correlic.incidents.list",
      "correlic.incident.get",
      "correlic.agents.activity",
      "correlic.agents.list",
      "correlic.finding.resolve"
    ]
  }
}
```

**correlic.finding.resolve with --allow-writes**

```json
--> {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "correlic.finding.resolve", "arguments": {"id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.unexpected_network:dev-laptop-01:203.0.113.0/24:443", "status": "dismissed", "resolution": "paste.example.net is the team pastebin"}}}
<-- {
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": {
          "id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.unexpected_network:dev-laptop-01:203.0.113.0/24:443",
          "ok": true,
          "response": {
            "id": "c31c4782-5af9-44e4-9f0a-d89ba2710484:ai.unexpected_network:dev-laptop-01:203.0.113.0/24:443",
            "ok": true,
            "status": "dismissed"
          },
          "status": "dismissed"
        }
      }
    ],
    "isError": false
  }
}
```

**API error with a wrong key (reported as a tool error, not a protocol error)**

```json
--> {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "correlic.agents.list", "arguments": {}}}
<-- {
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "correlic api error 401: unauthorized"
      }
    ],
    "isError": true
  }
}
```

## Troubleshooting

- `correlic api error 401: unauthorized` — the key is wrong, revoked or an
  agent key. Create a dashboard key.
- `correlic api error 403: ...` — the key's role does not allow the route
  (member keys see only their own agents).
- `x509: certificate signed by unknown authority` / `tls: bad certificate` —
  set `CORRELIC_TLS_CA_FILE` and the client certificate pair from the
  certificates directory of the Correlic host.
- `tls: failed to verify certificate: ... not valid for <host>` — the
  server certificate from `bootstrap` covers `localhost`, `127.0.0.1` and
  `::1` only; for a remote Correlic host regenerate it for that host name
  (`install/gen-certs.sh`) or connect through a name the certificate carries.
- The client shows no tools — check the client's MCP log for the server's
  stderr; `correlic-mcp --version` must run from the configured path.
