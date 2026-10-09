# Changelog

## Unreleased

AI tool hooks
- New `correlic-hook` binary (`agent/cmd/correlic-hook`, pure Go, Linux /
  macOS / Windows) that Claude Code and Cursor run on every tool call. It
  records the command, file or URL and the session as an `ai_tool_call`
  event (source `hook`, same host id and credentials as the agent), denies
  calls that match the org's `process_exec` / `file_open` block rules before
  they run and reports the block, fails open on any error within a ~2 s
  budget, and spools undelivered events (bounded) for the next invocation.
  `correlic-hook setup` merges the hook entries into `~/.claude/settings.json`
  and `~/.cursor/hooks.json` (or a project's) idempotently; `test` sends a
  synthetic event. Config: `~/.correlic/hook.yaml` or `CORRELIC_*` env vars.
  Only commands, paths, names and ids are sent, never contents or prompts.
- Backend: `ai_tool_call` is always kept by the sampler, shown in the agent
  activity stream (hook-only sessions are named `claude-code (hooks)` /
  `cursor (hooks)`, denied calls are high significance) and evaluated by the
  new `ai.tool_call_sensitive_path` rule, which fires when a hook command or
  file path matches the sampler's suspicious-path patterns.
- UI: `ai_tool_call` renders as "AI tool call" with its command/path in the
  live activity feed, incident timeline and event graph.
- Packaging: `correlic-hook` / `correlic-hook.exe` ships next to the agent
  in the Linux and Windows bundles, the .deb/.rpm and the installers.
  Documented in `backend/docs/HOOKS.md`.

macOS
- The Endpoint Security collectors (exec/exit, file open, DNS lookup with
  real PIDs) are wired into the agent behind the `esf` build tag, with
  automatic fallback to the kqueue/FSEvents/lsof collectors when the
  entitlement, root or Full Disk Access is missing, and CI now builds and
  tests the agent on a macOS runner. The project does not ship signed,
  notarized or Endpoint Security-enabled macOS builds: they need a paid
  Apple Developer Program membership. macOS stays a best-effort,
  build-from-source preview; see `backend/docs/MACOS_AGENT.md`.
- The minimum macOS version is 11 (Big Sur), which Go 1.26 requires.

macOS eslogger
- Endpoint Security events without an Apple Developer account: on macOS 13
  or newer the agent runs Apple's `/usr/bin/eslogger` (root plus Full Disk
  Access for the agent or its terminal) and gets process exec/exit/fork and
  file open events with real PIDs in real time. Network connections stay on
  lsof polling and there is no DNS. The kqueue/FSEvents/lsof pollers remain
  the fallback; `eslogger_enabled: false` turns the new path off.
- eslogger is supervised: a startup failure falls back to polling with one
  WARN naming the fix, a later crash is restarted with backoff (up to five
  times a minute), shutdown sends SIGTERM then SIGKILL, and the agent's own
  activity is excluded. Lines eslogger prints that the agent cannot parse
  are counted and logged, never fatal, since Apple reserves the right to
  change the format.
- The Endpoint Security runners are shared between the native ESF client
  and eslogger (`agent/internal/darwin/esevents`, no build tag, tested on
  Linux), and `check-compat` reports which path a Mac will use.
  See `backend/docs/MACOS_AGENT.md`.

Build
- The backend and the agent require Go 1.26 (golang.org/x/crypto 0.57 and
  golang.org/x/sys 0.48 need it); the Docker build stages use golang:1.26.
- Dependency updates: pgx 5.11, neo4j-go-driver 5.28.5, ulid 2.1.2,
  cilium/ebpf 0.22, React 19.3, framer-motion 14, Tailwind CSS 4.3,
  tailwind-merge 3.7, dotenv 18, cors 2.8.6, React type packages 19.3,
  recharts 3.10, lucide-react 1.52; GitHub Actions on their Node 24
  releases.
- The dashboard and proxy run on Node 24 LTS: CI, the container images and
  the portable Node in the Linux and Windows bundles move from Node 20
  (end of life since April 2026) to 24.21.0. Building from source needs
  Node 22 or newer.

Linux arm64
- The Linux agent, backend and dashboard now build and ship for arm64
  (aarch64) alongside amd64: Apple Silicon Linux VMs, AWS Graviton,
  Raspberry Pi 5 and other arm64 hosts with a BTF-enabled Linux 5.8+
  kernel. One `go generate` emits the eBPF objects for both architectures
  (`bpf2go -target amd64,arm64`); the kprobe programs (`dns`, `bind`)
  include `bpf/arch_arm64.h`, which declares the arm64 register file that
  libbpf's `PT_REGS_*` / `BPF_KPROBE` macros read. The unlink collector no
  longer fails on kernels without the `unlink(2)` syscall (arm64's generic
  syscall table) and monitors `unlinkat` there.
- Release artifacts: the container images are linux/amd64 + linux/arm64
  manifests (the Go stages cross-compile, QEMU covers the rest); the Linux
  release adds `correlic-linux-<v>-arm64.tar.gz`, `correlic_<v>_arm64.deb`
  and `correlic-<v>-1.aarch64.rpm` next to the unchanged amd64 assets, with
  apt (`binary-arm64`) and yum (`aarch64`) repository trees, all listed in
  `SHA256SUMS-linux.txt`. `install/install.sh` accepts aarch64 and downloads
  the matching bundle.
- CI: a new `agent-linux-arm64` job on GitHub's `ubuntu-24.04-arm` runner
  generates, builds, vets and tests the agent and loads the arm64 eBPF
  objects into the runner's kernel; `CORRELIC_BPF_LOAD_REQUIRED=1` makes the
  load test fail instead of skipping when BTF or privileges are missing.

Supply chain and security scanning
- Container images are signed by digest with Sigstore keyless signing
  (`cosign sign --recursive`; identity `release-images.yml`, issuer GitHub
  OIDC, recorded in Rekor), carry SLSA provenance (`provenance: mode=max`)
  and a BuildKit SBOM in the image index, and get one syft SPDX SBOM per
  platform attached with `cosign attest --type spdxjson`. The workflow
  verifies the signature and the attestations before it finishes and scans
  each pushed image with Trivy (SARIF to the Security tab, non-blocking).
- Release assets: every tar.gz, .deb, .rpm, zip and the `SHA256SUMS-*.txt`
  files are signed with `cosign sign-blob` and published with a
  `<asset>.sigstore.json` bundle; syft writes `<asset>.spdx.json` for every
  bundle and package tree, listed in the signed checksum file. Both bundle
  workflows verify their own signatures with `cosign verify-blob` before
  uploading. `SHA256SUMS-linux.txt` now also covers the apt/yum repo
  tarball. The optional GPG signing of .deb/.rpm is unchanged and documented.
- New `.github/workflows/security.yml`: CodeQL for Go (traced manual build
  with the eBPF objects generated) and JavaScript/TypeScript, `govulncheck`
  for the backend and the agent, a Trivy filesystem scan (vulnerabilities and
  misconfigurations) and `dependency-review-action` on pull requests; weekly,
  on push to `main` and on pull requests. New
  `.github/workflows/scorecard.yml` runs the OpenSSF Scorecard with
  published results. Only `govulncheck` and the dependency review can fail,
  and only on a known vulnerability.
- Docs: `SECURITY.md` rewritten (supported versions, reporting, response
  targets, scope, the security design with code paths, a hardening
  checklist and "Verifying a release" with the exact cosign commands);
  new `backend/docs/THREAT_MODEL.md` (assets, trust boundaries, four attacker
  models, what is and is not detected, mitigations mapped to code, residual
  risks) and `backend/docs/RELEASE_PROCESS.md` (cutting a release, what is
  signed where, GPG key rotation, verification). `.github/CODEOWNERS` added;
  `NOTICE.md` lists the Node.js 24 runtime the bundles actually ship.
Integrations and detection coverage
- Notification channels: Discord (channel webhook, one embed per incident
  with severity colour, host, rule, MITRE and dashboard link; only
  `discord.com` / `discordapp.com` webhook URLs are accepted), e-mail (SMTP
  via `net/smtp`: STARTTLS by default and refused if the server does not
  offer it, implicit TLS or none, SMTP PLAIN auth, plain-text plus minimal
  HTML body, subject prefix) and syslog (RFC 5424 over UDP, TCP with
  octet-counting framing, or TCP+TLS with an optional CA file; app-name
  `correlic`, structured data with incident/finding ids, severity, host,
  category, detection ids and MITRE techniques; JSON payload as the
  message), next to webhook and Slack. The Settings page offers all five.
- Endpoint secrets (SMTP password, webhook HMAC secret) are sealed with
  `LLM_ENCRYPTION_KEY` (AES-256-GCM, shared `internal/secrets` package)
  before storage and are no longer returned by the API; responses carry
  `password_set` / `secret_set` instead, and an update that omits the secret
  keeps the stored one. Existing webhook endpoints keep working with their
  plaintext secret until it is re-entered. The telemetry plane reads
  `LLM_ENCRYPTION_KEY` optionally and leaves deliveries it cannot decrypt to
  the API plane. `FRONTEND_URL` gives Discord embeds and e-mails an absolute
  incident link. The delivery payload gains `category`, `detection_ids` and
  `finding_ids`.
- Detection coverage: migration 006 seeds process patterns for OpenCode,
  Sourcegraph Amp, AWS Kiro (IDE and kiro-cli), Google Jules Tools, Roo
  Code, Charm Crush, Factory Droid, Qwen Code, JetBrains Junie, Augment
  (`auggie` CLI), Moonshot Kimi CLI, Codebuff and Plandex, plus their vendor
  API domains (and Trae's), bringing the seeded list to 43 tools. The
  migration documents the false-positive risk of the short names (`amp`,
  `roo`, `crush`, `jules`) and leaves `augment` out on purpose. The
  dashboard shows display names for every seeded agent type.
- MCP server: `correlic-mcp` (`backend/cmd/mcp`) now exposes
  `correlic.findings.list`, `correlic.incidents.list`,
  `correlic.incident.get`, `correlic.agents.activity`,
  `correlic.agents.list` and, only with `--allow-writes`,
  `correlic.finding.resolve`, next to the existing `ai.proof`,
  `network.summary`, `ports.summary` and `telemetry.search` tools; every
  tool has a precise description and JSON schema, API and argument errors
  come back as MCP tool errors, `since` accepts durations (`30m`, `6h`,
  `7d`), and the server connects to the API plane with mTLS
  (`CORRELIC_TLS_*`, the hook's variable names) and `Authorization: Bearer`.
  Protocol version negotiation follows the specification (a newer client
  revision is answered with the server's instead of refused), `initialize`
  carries usage instructions, and `--version` is supported. The binary ships
  in the Linux and Windows bundles and the `.deb`/`.rpm`.
  `backend/docs/MCP_SERVER.md` has the install steps for Claude Code, Claude
  Desktop and Cursor, the tool reference, the security model and a captured
  transcript; `scripts/dev/mcp_client.py` is a stdio JSON-RPC client for
  trying the server without an MCP host.

## v1.0.1 (2026-10-08)

Release: https://github.com/FuloxDev/correlic/releases/tag/v1.0.1

Security
- Removed the dashboard's automatic login with a server-side API key and the
  "any mTLS identity is admin" fallback. Unauthenticated requests through the
  proxy are now rejected.
- API keys carry a type: agent keys are restricted to ingest, heartbeat and
  agent endpoints; dashboard keys and sessions carry the user's role.
- Non-GET requests on configuration routes (block rules, exceptions, detection
  settings, baselines, notification endpoints, AI settings, users, API keys)
  require the admin role.
- Webhook and Slack endpoints are validated against loopback, private and
  link-local addresses; redirects are disabled.
- Google sign-in is registered only when `GOOGLE_CLIENT_ID` is set and always
  verifies the token audience and issuer.
- Login rate limiting is keyed by client address plus a per-account backoff.
- Session logout endpoint, session TTL cap, expired-session pruning.
- Response headers: `X-Content-Type-Options`, `Referrer-Policy`,
  `Cache-Control: no-store`, HSTS when TLS is on.

Detection
- Detection rules now run without Neo4j, using the agent's own process
  attribution; Neo4j remains an optional enrichment for process trees.
- The ingest sampler's credential-path patterns (`.ssh/`, `.aws/`, `id_rsa`,
  ...) now match anywhere in the path. Previously they only matched absolute
  prefixes and never fired.
- Finding ids and cooldown keys are qualified by organisation.
- The Agent Activity page and the dashboard's live feed work without Neo4j:
  `/agents/activity` is built from the events table using the agent's AI
  session tags when the graph is not configured.

Agent
- Thread exits no longer unregister the whole process.
- AI tools are matched on executable and argument basenames, not substrings of
  the whole command line (a branch named `claude/...` or a path under a
  `claude-*` directory no longer makes `git` or `ls` an AI session).
- The startup `/proc` scan registers a matching process below another
  matching process as a descendant; one running tree no longer splits into
  two sessions.
- Patterns are refreshed periodically and cached on disk; heartbeats are sent;
  the primary ingest path retries with backoff.
- Missing or invalid config files are an error instead of silent defaults.

First run
- `correlic-admin bootstrap` creates a verified admin, a dashboard key and a
  separate agent key, and writes `agent.yaml` into the certificates directory.
- The `agents` table gained the `user_id` column the code expected; the Agents
  page and heartbeats work on fresh installs.
- The all-in-one image keeps certificates and Neo4j data in the data volume
  and binds the dashboard to 127.0.0.1.

## v1.0.0 (2026-10-07)

First open-source release: single MIT-licensed repository, no hosted
dependency, no feature tiers.
