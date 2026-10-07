# Correlic Backend -- Complete API Reference

> Auto-generated from route registrations in `cmd/api/main.go` and `internal/api/ai_handler.go`.
> Last updated: 2026-03-29

All endpoints are served on `:8080` over TLS (or plain HTTP in dev mode).

**Auth legend:**

| Tag | Meaning |
|-----|---------|
| **authed** | Requires a valid session cookie or `X-API-Key` header |
| **unauthed** | No authentication required (rate-limited only) |
| **admin** | Requires authed session with `role = admin` |
| **conditional** | Only registered when a feature flag / env var is set |

---

## 1. Health and Debug

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | unauthed | Liveness probe. Returns 200 if the server is running. Indicates whether detection engine is active. |
| GET | `/readiness` | unauthed | Readiness probe. Checks database connectivity. |
| GET | `/debug/vars` | authed, conditional | Go `expvar` metrics. Only registered when `ENABLE_DEBUG_ENDPOINTS=true`. |
| GET | `/debug/pprof/` | authed, conditional | pprof index. Only registered when `ENABLE_DEBUG_ENDPOINTS=true`. |
| GET | `/debug/pprof/cmdline` | authed, conditional | pprof cmdline. Only registered when `ENABLE_DEBUG_ENDPOINTS=true`. |
| GET | `/debug/pprof/profile` | authed, conditional | pprof CPU profile. Only registered when `ENABLE_DEBUG_ENDPOINTS=true`. |
| GET | `/debug/pprof/symbol` | authed, conditional | pprof symbol lookup. Only registered when `ENABLE_DEBUG_ENDPOINTS=true`. |
| GET | `/debug/pprof/trace` | authed, conditional | pprof execution trace. Only registered when `ENABLE_DEBUG_ENDPOINTS=true`. |

---

## 2. Authentication

### Sessions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/sessions` | unauthed | Login with email and password. Returns session cookie. |
| DELETE | `/auth/sessions` | unauthed | Logout / destroy session. |

### Google OAuth

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/google` | unauthed | Sign in with Google OAuth ID token. Requires `GOOGLE_CLIENT_ID` env var. |

### Email Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/email/send-verification` | unauthed | Send a verification email to the user's address. |
| GET | `/auth/email/verify` | unauthed | Verify email via token in query string. Redirects to frontend. |

### Password Reset

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/password/reset` | authed | Reset password for the authenticated user. |

### User Profile (Self-Service)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/profile` | authed | Get the current user's profile. |
| PUT | `/auth/profile` | authed | Update the current user's profile. |

---

## 3. Users and Organizations (Admin)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/users` | admin | List all users in the organization. |
| POST | `/users` | admin | Create a new user. |
| DELETE | `/users` | admin | Delete a user. |
| GET | `/orgs/` | authed | Organization CRUD. Supports sub-path routing (e.g. `/orgs/{id}`). |

---

## 4. API Keys and Agent Tokens

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api-keys` | admin | List API keys for the organization. |
| POST | `/api-keys` | admin | Create a new API key. |
| DELETE | `/api-keys` | admin | Revoke an API key. |
| GET | `/agent-tokens` | authed | List agent enrollment tokens. |
| POST | `/agent-tokens` | authed | Create a new agent enrollment token. |
| DELETE | `/agent-tokens` | authed | Revoke an agent enrollment token. |

---

## 5. Telemetry and Ingestion

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/telemetry` | authed | Legacy telemetry ingestion endpoint. Supports batch event upload. |
| POST | `/ingest/events` | authed | Primary canonical event ingestion. Runs sampling, detection, baseline collection, chain correlation, and incident correlation in real time. |

---

## 6. Findings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/findings` | authed | List detection findings. Supports filtering by host, severity, status, rule, time range, and pagination. |
| GET | `/api/v1/findings/suppressed-summary` | authed | Summary of suppressed (baselined/excepted) findings. |
| POST | `/api/v1/findings/reconcile` | authed | Reconcile findings against current baselines and exceptions. |
| GET | `/api/v1/findings/{id}` | authed | Get a single finding by ID with full context. |
| PATCH | `/api/v1/findings/{id}` | authed | Resolve a finding (allow, dismiss, investigate, etc.). |
| POST | `/api/v1/findings/{id}/resolve-domain` | authed | Resolve a finding by adding its domain to the safe list. |

---

## 7. Detection Settings and Exceptions

### Rule Settings (Per-Org Tunable Thresholds)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/detection/settings` | authed | List all detection rule settings for the organization. |
| PUT | `/api/v1/detection/settings/{rule_id}` | authed | Create or update a rule setting (threshold, enabled state). |
| DELETE | `/api/v1/detection/settings/{rule_id}` | authed | Delete a rule setting (revert to defaults). |

### Per-Rule Exceptions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/exceptions` | authed | List all rule exceptions. |
| POST | `/api/v1/exceptions` | authed | Create a new rule exception (suppress findings matching criteria). |
| DELETE | `/api/v1/exceptions/{id}` | authed | Delete a rule exception. |

---

## 8. Baselines and Safe Domains

### Behavioral Baselines

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/baselines` | authed | List behavioral baselines. Supports filtering by host, status, signal type. |
| POST | `/api/v1/baselines` | authed | Manually create a baseline entry. |
| GET | `/api/v1/baselines/summary` | authed | Aggregated baseline statistics. |
| POST | `/api/v1/baselines/{id}/confirm` | authed | Confirm a pending baseline (promote to active). |
| DELETE | `/api/v1/baselines/{id}` | authed | Delete a baseline. |
| PATCH | `/api/v1/baselines/{id}` | authed | Suspend a baseline. |

### Never-Baseline List

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/baselines/never-baselines` | authed | List patterns that should never be baselined. |
| POST | `/api/v1/baselines/never-baselines` | authed | Add a never-baseline pattern. |
| DELETE | `/api/v1/baselines/never-baselines/{id}` | authed | Remove a never-baseline pattern. |

### Exclusions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/baselines/exclusions` | authed | List baseline exclusion patterns. |
| DELETE | `/api/v1/baselines/exclusions/{id}` | authed | Delete a baseline exclusion. |

### Noise Filters

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/baselines/noise-filters` | authed | List noise filter rules used during baseline collection. |

### Safe Domains

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/baselines/safe-domains` | authed | List safe (trusted) domains. |
| POST | `/api/v1/baselines/safe-domains` | authed | Add a domain to the safe list. |
| DELETE | `/api/v1/baselines/safe-domains/{id}` | authed | Remove a domain from the safe list. |

---

## 9. Block Rules and Block Events

### Block Rules

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/block-rules` | authed | List block rules for the organization. |
| POST | `/api/v1/block-rules` | authed | Create a new block rule. |
| PUT | `/api/v1/block-rules/{id}` | authed | Update an existing block rule. |
| DELETE | `/api/v1/block-rules/{id}` | authed | Delete a block rule. |

### Block Events

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/block-events` | authed | List block events (enforcement log). |
| GET | `/api/v1/block-events/stats` | authed | Aggregated block event statistics. |

---

## 10. Incidents

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/incidents` | authed | List incidents. Supports filtering by host, severity, status, and pagination. |
| GET | `/api/v1/incidents/{id}` | authed | Get full incident detail including context summary. |
| GET | `/api/v1/incidents/{id}/timeline` | authed | Get the incident timeline (ordered events). |
| PATCH | `/api/v1/incidents/{id}` | authed | Update incident status (acknowledge, resolve, etc.). |

---

## 11. AI

### LLM Provider Settings (BYOK)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/ai/settings` | authed | List configured LLM providers and available provider catalog. |
| POST | `/api/v1/ai/settings` | authed | Save LLM provider settings (provider name, model, API key). |
| DELETE | `/api/v1/ai/settings` | authed | Delete LLM provider settings. Requires `?provider=` query param. |
| PUT | `/api/v1/ai/settings/switch` | authed | Switch active LLM provider. Disables others, enables the specified one. |

### AI Analysis and Explanation

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/ai/analyze` | authed | Analyze a set of events using the configured LLM. Accepts event IDs, PID+host, or raw events. |
| POST | `/api/v1/ai/explain` | authed | Explain a single event using the configured LLM. |
| GET | `/api/v1/ai/patterns` | authed | List AI agent detection patterns (string needles only). |
| GET | `/api/v1/ai/agent-patterns` | authed | List all AI agent patterns with full details (id, pattern, agent_type, description). |
| POST | `/api/v1/ai/agent-patterns` | authed | Create a new AI agent pattern. |
| DELETE | `/api/v1/ai/agent-patterns/{id}` | authed | Delete an AI agent pattern by ID. |
| POST | `/api/v1/ai/suggest-patterns` | authed | Use LLM to suggest process name patterns for a given software name. |

### AI Proof (Attribution)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ai/proof` | authed | Retrieve AI attribution proof data for telemetry events. |

### Incident and Finding AI

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/api/v1/incidents/{id}/explain` | authed | AI-generated explanation of an incident using dossier context. |
| POST | `/api/v1/incidents/{id}/ask` | authed | Ask a question about an incident (single response). |
| POST | `/api/v1/incidents/{id}/ask/stream` | authed | Ask a question about an incident (streaming SSE response). |
| POST | `/api/v1/incidents/{id}/chat` | authed | Threaded chat about an incident (dossier-based). |
| GET | `/api/v1/incidents/{id}/chat/history` | authed | Get chat history for an incident. |
| DELETE | `/api/v1/incidents/{id}/chat/thread/{thread_id}` | authed | Delete a chat thread for an incident. |
| POST | `/api/v1/findings/{id}/explain` | authed | AI-generated explanation of a single finding. |

---

## 12. Notifications and Endpoints

### In-App Notifications

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/notifications` | authed | List in-app notifications. Supports pagination. |
| GET | `/api/v1/notifications/count` | authed | Count of unread notifications. |
| POST | `/api/v1/notifications/read-all` | authed | Mark all notifications as read. |
| PATCH | `/api/v1/notifications/{id}` | authed | Mark a single notification as read. |
| DELETE | `/api/v1/notifications/{id}` | authed | Dismiss a notification. |

### Notification Endpoints (Channel Config)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/notification-endpoints` | authed | List notification endpoints (webhooks, Slack, etc.). |
| POST | `/api/v1/notification-endpoints` | authed | Create a new notification endpoint. |
| PUT | `/api/v1/notification-endpoints/{id}` | authed | Update a notification endpoint. |
| DELETE | `/api/v1/notification-endpoints/{id}` | authed | Delete a notification endpoint. |
| POST | `/api/v1/notification-endpoints/{id}/test` | authed | Send a test notification to an endpoint. |

### Delivery History

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/notification-deliveries` | authed | List notification delivery attempts and their statuses. |

---

## 13. Dashboard

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/dashboard/stats` | authed | Dashboard metrics: event counts, finding severity breakdown, active incidents, AI attribution stats. |
| GET | `/dashboard/trends` | authed | Time-series trend data for dashboard charts. |

---

## 14. Network and Ports

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/network/summary` | authed | Network activity summary (connection counts, top destinations). |
| GET | `/network/domain` | authed | Network activity grouped by domain. |
| GET | `/network/destination` | authed | Network activity grouped by destination IP/port. |
| GET | `/ports/summary` | authed | Listening ports summary across hosts. |
| GET | `/ports/service` | authed | Listening ports grouped by service name. |

---

## 15. Query Services

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/query/containers` | authed | Query container events from telemetry. |
| GET | `/query/ports` | authed | Query port/listener events. |
| GET | `/query/connections` | authed | Query network connection events. |
| GET | `/query/inbound` | authed | Query inbound connection events. |
| GET | `/query/processes` | authed | Query process events. |
| GET | `/process/lifecycles` | authed | Query canonical process lifecycle events. |

---

## 16. Neo4j / Graph

All Neo4j endpoints are **conditional** -- only registered when Neo4j is connected and `timelineService` or `investigationService` is initialized.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/neo4j/timeline` | authed, conditional | Graph-powered process timeline for a host. |
| GET | `/neo4j/process-tree` | authed, conditional | Full process tree from Neo4j (parent/child relationships). |
| GET | `/neo4j/attack-path` | authed, conditional | Attack path visualization from graph data. |
| GET | `/neo4j/investigation/` | authed, conditional | Investigation queries against the graph. Sub-path routed. |

---

## 17. Process Timeline and Agent Activity

All endpoints in this section are **conditional** -- only registered when Neo4j `timelineService` is available.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/processes/tree` | authed, conditional | Interactive process tree for the UI. |
| GET | `/processes/activity` | authed, conditional | Process activity stream (file, network, registry events by process). |
| GET | `/processes/summary` | authed, conditional | Process network summary (per-process connection stats). |
| GET | `/agents/activity` | authed, conditional | Human-readable agent activity feed (action stream). |

---

## 18. Enrichment

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/v1/enrich/ip` | authed | Resolve a single IP address to domain, ASN, and geolocation. |
| POST | `/api/v1/enrich/ips` | authed | Bulk-resolve multiple IP addresses. |

---

## 19. Tier

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/tier` | authed | Return the current subscription tier and feature flags. Controlled by `CORRELIC_TIER` env var. |

---

## 20. Agents

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/agents` | authed | List all registered agents with inventory metadata. |
| POST | `/heartbeat` | authed | Agent heartbeat. Updates last-seen timestamp and agent metadata. |
| * | `/agents/` | authed | Agent sub-resource router (identity, config, commands). Handles `/agents/{id}/*` paths. |

---

## 21. Process Timeline (Legacy)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/timeline` | unauthed | Legacy process timeline endpoint (pre-Neo4j). Returns PostgreSQL-based timeline. |

---

## Notes

- **Rate Limiting**: All endpoints (authed and unauthed) pass through the rate limiter. Configurable via `CORRELIC_RATE_LIMIT_PER_MIN` env var.
- **mTLS**: When `MTLS_CA_FILE` is set, agent-facing endpoints require mutual TLS client certificates.
- **CORS**: Handled at the middleware layer; not shown in route registration.
- **Trailing slashes**: Paths ending in `/` (e.g., `/api/v1/findings/`, `/orgs/`) use sub-path routing to handle `{id}` segments.
- **Method routing**: Some endpoints use Go 1.22+ method-prefixed patterns (e.g., `POST /api/v1/ai/analyze`), while others dispatch on `r.Method` inside the handler.
