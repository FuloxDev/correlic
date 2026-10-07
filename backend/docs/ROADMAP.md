# Correlic Roadmap

**Last updated:** April 12, 2026
**Current version:** v1.0 (launched April 10, 2026)

This document reflects the post-launch state of Correlic and the work ahead. Priorities are grouped by immediate / short / medium / long term rather than rigid quarters — v1.0 just shipped and we're in growth mode.

---

## Current Status — v1.0 (Shipped April 10, 2026)

Correlic v1.0 is the first production release. Everything below is live and running in production.

### Multi-Platform Agent
- **Linux** — eBPF (12 BPF programs: execsnoop, fork, exit, connect, fileopen, DNS, privilege escalation, bind, accept). Requires kernel 5.8+ and BTF.
- **Windows** — ETW (4 kernel providers: process, registry, privilege, scheduled tasks) + USN Journal + PEB command-line capture. Windows 10 1809+ / Server 2019+. SCM-integrated service.
- **macOS** — Endpoint Security Framework + FSEvents + kqueue + lsof (MVP level).
- **AI session tracking** — UUID per AI root process, inherited across fork/exec by every descendant, 10s grace TTL for exited PIDs (handles cross-PID correlation races).
- **Block enforcement** — soft-block enforcer terminates matching processes; rules synced every 30s.

### Detection Engine
- **13 AI-gated detection rules** — all only fire for processes inside an AI agent process tree:
  `credential_access`, `unauthorized_exec`, `excessive_writes`, `data_exfiltration`, `unexpected_network`, `suspicious_dns`, `persistence`, `privilege_escalation`, `code_tampering`, `container_escape`, `discovery`, `command_activity`, `file_activity`
- **11 chain patterns** — multi-step attack correlation:
  credential_theft, reverse_shell_setup, lateral_movement, full_compromise, persistence_backdoor, supply_chain_attack, data_staging, credential_persistence, privesc_credential_exfil, recon_to_escalation, container_breakout
- **Suppression pipeline** — cooldown rate limiting → behavioral baseline → rule exceptions → severity dampening → safe-domain allowlist → never-baseline safety list
- **Per-org tunable thresholds** via `detection_rule_settings`
- **MITRE ATT&CK mapping** on every finding and incident

### Behavioral Baseline System
- Auto-observed + user-confirmed baselines
- Case-insensitive matching for Windows paths
- Forward-slash path normalization across all platforms
- Never-baseline safety list (Tier 1 sensitive resources)
- Reconcile API with batch retroactive resolution
- Safe-domain allowlist with pipe-to-shell guard

### Backend (Go 1.24+)
- PostgreSQL 14+ for events, findings, incidents, baselines, auth, audit
- Neo4j 5+ (optional, graceful degradation) for process trees, activity edges, AI label propagation, attack-chain traversal
- Intelligent sampling (90% event reduction) with security-first order: AlwaysKeep → Suspicious → AIBypass → BenignDrop → Probabilistic
- Correlation engine: Tier 1 real-time + Tier 2 buffered windowed correlation
- Incident engine: chain-findings clustering, 30-min merge window, auto-resolution for low-severity singletons, MITRE union, context assembly for AI consumption
- **85 SQL migrations** shipped
- 4 binaries: `api`, `admin`, `telemetry`, `mcp` (Model Context Protocol server)

### AI Intelligence (3-Layer Context)
- **Layer 1** — per-host executable profiles, hourly updates
- **Layer 2** — hierarchical rollups (1-min → 1-hr → 24-hr → weekly), anomaly scoring
- **Layer 3** — learned verdict patterns from user feedback (allowed / dismissed / investigated)
- **BYOK LLM providers** — OpenAI, Anthropic, Google Gemini, Groq, xAI (AES-256 encrypted key storage)
- **Tool-calling** — 18 context-query tools available to the LLM
- **Streaming SSE** threaded chat with full history
- **Pre-computed dossier** — overview, attack sequence, process chain, detections, timeline, network, sensitive files, behavioral context, related incidents

### API Surface
- **80+ HTTP endpoints** across ingestion, findings, incidents, baselines, block rules, detection settings, exceptions, AI, notifications, network analysis, enrichment, Neo4j timeline/tree/attack-path, agents, auth, dashboard, admin
- **Auth** — mTLS + API key (agents), session + Google OAuth (users), RBAC (admin/user), multi-tenant `org_id` scoping, rate limiting (300 req/min default), full audit trail
- **Notifications** — in-app, webhook (HMAC-SHA256 signed), Slack (Block Kit)
- Full reference: [API_REFERENCE.md](./API_REFERENCE.md)

### UI (Next.js 16 / React 19)
- Dashboard with real-time event timeline (5–60s refresh)
- Findings triage (allow / dismiss / investigate) with auto-resolved tab
- Incidents with AI-powered threaded chat investigation
- Behavioral baseline management + case-insensitive Windows tree
- Block rule creation + enforcement monitoring
- Process tree visualization
- Network analysis (connections, domains, ports)
- Notification configuration (webhook, Slack)
- 3 themes: Cyber, Forge, Neon
- Command extraction + expand for full cmdline

### Deployment
- Docker Compose stack: PostgreSQL 16 + correlic-api (Fastify) + correlix-ui (Next.js) + Nginx reverse proxy + Certbot (Let's Encrypt)
- Self-hosted install package with `gen-certs.sh` for self-signed certs

---

## Immediate Focus — April–May 2026 (Post-Launch Stabilization)

v1.0 just shipped. These are the things that matter in the first 4–6 weeks before scaling up feature work again.

### 1. Real-World Hardening
- Monitor production telemetry from the first wave of installs
- Fix bugs and edge cases that only surface on real machines
- Tune false-positive rates per detection rule based on real data
- Verify behavioral baselines converge correctly on diverse workloads

### 2. macOS Agent → Production Grade
- macOS is currently MVP (kqueue/FSEvents/lsof polling).
- Migrate primary event source to Endpoint Security Framework AUTH/NOTIFY events end-to-end
- Sign and notarize the binary
- Installer package (`.pkg`) with LaunchDaemon registration

### 3. Onboarding & Install Experience
- One-line install scripts per platform
- First-run wizard in the UI (agent registration, LLM key, first baseline pass)
- Clear "your agent is healthy" signal on the dashboard
- Example alerts and demo mode for evaluators

### 4. Observability of Correlic Itself
- Agent health monitoring surfaced in UI (last heartbeat, version, OS, health status)
- Backend internal metrics (events/sec, sampling rate hit, detection latency, incident lag)
- Error rate dashboards per component

### 5. Docs & Developer Experience
- OpenAPI / Swagger spec generated from the 80+ endpoints
- Quickstart guide for each OS
- Webhook payload reference with examples
- Troubleshooting runbook

---

## Short Term — Q2 2026

### Detection & Rules
- **Community rule repository** — shareable rule format, import/export
- **Rule authoring UI** — create custom AI-gated rules without code changes
- **YARA and Sigma adapters** — evaluate compatibility with AI-gated model
- **Per-rule tuning dashboard** — confidence curves, suppression hit rates

### Investigation & Response
- **Process tree visualization v2** — interactive graph, attack-chain highlighting, timeline scrub
- **Incident response workspace** — evidence collection, notes, assignee, playbook attachment
- **Query builder UI** — advanced filters across events, findings, incidents; saved searches

### Performance
- Database query optimization (slow query audit, index pass)
- Event batching improvements on ingestion path
- Redis caching layer for hot dashboard queries
- Connection pooling tuning under real load

### Agent Fleet Management
- Agent inventory UI (already partially there) — group by org/host/tag
- Remote configuration updates pushed from backend
- Version rollout controls (canary / staged rollout)
- Agent deployment scripts for common provisioning tools

---

## Medium Term — Q3 2026

### Container & Cloud Workloads
- Docker container monitoring with cgroup v2 attribution
- Kubernetes pod-level tracking + pod→node correlation
- Container escape detection chain (already have the rule — add runtime context)
- Image vulnerability correlation when a container launches a known-bad digest

### Network Analysis v2
- Connection graph visualization (host → host, host → domain)
- Geo-IP + ASN/BGP enrichment already shipped — surface it in the UI
- DNS query correlation into findings
- TLS/SNI inspection where possible

### File Integrity Monitoring
- Track changes to critical files beyond the current detection patterns
- FIM-style baseline for compliance workloads
- Change attribution (which AI session touched this file, when, why)

### Compliance
- PCI-DSS evidence view
- HIPAA audit report export
- SOC 2 control mapping
- Custom framework builder

### Machine Learning
- Anomaly detection on process behavior (supplement rules, don't replace)
- Automated baseline learning quality signal
- Suspicious pattern discovery from production data
- False-positive reduction model trained on user verdicts (Layer 3 already captures this — feed it forward)

### API Enhancements
- GraphQL layer over existing REST endpoints
- Webhook subscriptions with topic filters
- Bulk export API (findings, incidents, events)
- Real-time WebSocket / SSE event stream

---

## Long Term — Q4 2026 and Beyond

### Scale
- Horizontal backend scaling (stateless API nodes behind LB)
- Event streaming (Kafka or Pulsar) for ingestion decoupling
- Time-series store (ClickHouse or TimescaleDB) for events/telemetry
- Distributed caching
- Multi-region deployment

### Distributed Tracing Correlation
- OpenTelemetry integration — link Correlic events to application traces
- Cross-service correlation when the AI agent triggers work in downstream services
- Service mesh awareness

### Advanced eBPF
- Memory access monitoring
- Kernel module loading detection
- Extended syscall filtering
- User-supplied eBPF programs (sandboxed)

### Threat Intelligence
- IOC matching (hash, domain, IP)
- MISP / STIX / TAXII feed ingestion
- Reputation scoring fed into correlation
- Automated threat hunting queries

### Multi-Cloud Native
- AWS CloudTrail + GuardDuty correlation
- Azure Security Center
- GCP Security Command Center
- Unified AI-agent security view across clouds

### Forensics
- Event replay at full fidelity
- Timeline reconstruction
- Memory / disk image analysis integration

### Automation / SOAR
- Splunk Phantom / Cortex XSOAR integrations
- Automated response playbooks
- Custom remediation scripts triggered by finding/incident

---

## Technical Debt & Ongoing Work

### Testing
- [ ] Increase backend test coverage to 80%+
- [ ] Integration test suite for ingestion → detection → incident → notification end-to-end
- [ ] Agent integration tests on real OS images (Linux / Windows / macOS CI runners)
- [ ] Performance benchmarking suite
- [ ] Load testing framework (target: 10k events/sec sustained)

### DevOps
- [ ] CI/CD pipeline (GitHub Actions): build, test, lint, release
- [ ] Automated releases with signed binaries
- [ ] Multi-arch Docker images (amd64 + arm64)
- [ ] Helm chart for Kubernetes deployment
- [ ] Terraform module for cloud deployments
- [ ] SBOM generation on every release

### Documentation
- [x] Architecture docs (`docs/` — this directory)
- [x] Detection engine reference
- [x] AI intelligence reference
- [ ] OpenAPI/Swagger spec
- [ ] Video walkthroughs
- [ ] Deployment guides (bare-metal, AWS, GCP, Azure, Kubernetes)

### Security
- [ ] Third-party security audit
- [ ] External penetration test
- [ ] Dependabot / dependency scanning
- [ ] Signed releases (cosign / GPG)
- [ ] SBOM published per release
- [ ] Bug bounty program

---

## Important Things To Do Next (Ranked)

These are the concrete next actions out of the post-launch list above. Work top to bottom.

1. **Ship OpenAPI spec + Swagger UI** — fastest DX win, every new user asks for it.
2. **Agent health tile on dashboard** — operators need to know the agent is alive. Critical trust signal.
3. **One-line install scripts (curl | sh) for Linux/macOS + MSI for Windows** — reduce first-install friction.
4. **First-run wizard** — baseline pass, LLM BYOK key, sample incident — first 10 minutes decide retention.
5. **macOS agent ESF migration** — needed before we can credibly sell "full macOS coverage".
6. **Real-data FP tuning pass** — collect verdicts from early users, retune confidence thresholds per rule.
7. **Backend self-metrics** — events/sec, sampling ratio, detection latency, incident lag — surfaced to ops.
8. **CI/CD for backend + agent + UI** — automated builds, tests, signed releases. Currently manual.
9. **Load test to 10k events/sec** — know the ceiling before a deployment finds it.
10. **Community rule repository MVP** — start the moat. Shareable rules = shareable defense.

---

## Version Milestones

### v1.0 — Shipped April 10, 2026
Multi-platform agent, 13 detection rules + 11 chain patterns, behavioral baselines, BYOK AI intelligence, 80+ API endpoints, Next.js dashboard, Neo4j-backed correlation, MITRE mapping, block rules, audit trail, RBAC.

### v1.1 — Target: late Q2 2026
Post-launch stabilization release. OpenAPI, agent health UI, install scripts, first-run wizard, macOS ESF, backend self-metrics, FP tuning pass.

### v1.2 — Target: Q3 2026
Community rules, rule authoring UI, incident response workspace, query builder, process tree v2, performance + caching layer.

### v1.5 — Target: late Q3 2026
Container/Kubernetes security, network graph v2, FIM, compliance exports, ML anomaly layer (beta), GraphQL + streaming API.

### v2.0 — Target: Q4 2026+
Horizontal scale, event streaming bus, distributed tracing correlation, threat intel, multi-cloud, forensics, SOAR.

---

## How Priority Is Decided

1. **Security impact** — does this close a real attack window on AI-agent workloads?
2. **User pain** — are users hitting this right now?
3. **Moat** — does it widen our 12–18 month window of uniqueness on AI-agent observability?
4. **Implementation cost** — how much engineering and how much risk?

---

## Contributing

1. Pick an item from this roadmap
2. Open an issue to discuss your approach
3. Submit a PR with your implementation
4. Update docs as needed

See [DEVELOPMENT.md](./DEVELOPMENT.md) for contribution guidelines.

---

## Feedback

Open an issue or discussion on GitHub with ideas, complaints, or "this is wrong because…" — we read all of it.
