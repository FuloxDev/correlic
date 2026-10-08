# Changelog

## Unreleased

macOS
- The Endpoint Security collectors (exec/exit, file open, DNS lookup with
  real PIDs) are wired into the agent behind the `esf` build tag, with
  automatic fallback to the kqueue/FSEvents/lsof collectors when the
  entitlement, root or Full Disk Access is missing. CI compiles the ESF code
  on a macOS runner; `build-macos-agent` produces a universal app bundle and
  signs and notarizes it when the Apple secrets are set. The Apple-side steps
  are in `backend/docs/MACOS_ESF_SETUP.md`.

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
