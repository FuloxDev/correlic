# Correlic roadmap

**Current version:** v1.0.x (open-source, MIT)

Correlic is self-hosted software. Nothing in this document refers to a hosted
service; every feature listed runs on your own machines.

## What exists today

- **Linux agent** — eBPF programs for exec, fork, exit, connect, bind, file
  open, unlink, setuid and DNS; AI session tracking with inheritance across
  fork/exec; block-rule enforcement. Kernel 5.8+ with BTF.
- **Windows agent** — ETW providers (process, registry, privilege, scheduled
  tasks) plus the Security audit log; block-rule enforcement; SCM service.
- **macOS agent (preview)** — kqueue process events and polling for file and
  network activity. No Endpoint Security framework yet.
- **Detection** — 13 AI-gated rules and 11 chain patterns, suppression
  pipeline (cooldown → baselines → exceptions → safe domains → never-baseline
  list), per-org thresholds, MITRE ATT&CK mapping. Rules run with or without
  Neo4j; the graph adds process-tree context when present.
- **Backend** — Go, PostgreSQL (plus optional Neo4j), telemetry and API
  planes, incident clustering, notifications (in-app, webhook, Slack), BYOK
  LLM layer with streaming chat and pre-computed incident dossiers, MCP server.
- **Dashboard** — findings triage, incidents with AI chat, baselines, block
  rules, timeline, settings.
- **Install paths** — all-in-one container, Docker Compose, Linux installer
  (systemd, `.deb`/`.rpm`), Windows installer.

## Known limitations

- macOS collection is polling-based and lower fidelity than Linux/Windows.
- Multi-organisation isolation is partial: events and the process graph are
  scoped by host, not organisation. Run one organisation per install.
- Detection rules and the ingest pipeline have thin automated test coverage.
- The dashboard is designed for desktop widths; phones get a drawer layout
  but no dedicated views.

## Planned

1. Endpoint Security framework collector for macOS.
2. Organisation id on events and graph nodes; per-organisation safe domains
   and AI patterns.
3. Test suite for every detection rule and chain pattern using recorded event
   fixtures.
4. A "fire a test incident" command for first-run verification.
5. Lighter default footprint: PostgreSQL-only attribution so Neo4j becomes a
   pure add-on in every install path.
6. Agent packaging for Homebrew and winget.

Contributions toward any of these are welcome; see `CONTRIBUTING.md`.
