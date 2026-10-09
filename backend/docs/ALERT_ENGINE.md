# Phase 6 — Alert Engine

## Architecture
```
Detection Pipeline → Finding stored → Manager.OnFindingStored()  → in-app notification INSERT
                   → Incident created/escalated → OnIncidentCreated/Escalated() → in-app + delivery queue
                                                                                      ↓
DeliveryWorker (5s poll) → PollPending() → Senders (webhook / slack / discord / email / syslog) → MarkDelivered/Failed
```

## Key Design Decisions
- In-app notifications for ALL findings (already deduplicated by pipeline cooldown)
- External channels (webhook, Slack, Discord, email, syslog) only for incidents (not 50 notifications per burst)
- Skip auto_resolved incidents for external delivery
- Severity gating: user sets min_severity per endpoint
- Dedup: unique index on (endpoint_id, reference_type, reference_id)
- Endpoint secrets (SMTP password, webhook HMAC secret) are sealed with `LLM_ENCRYPTION_KEY` (AES-256-GCM, `internal/secrets`) before they reach PostgreSQL and are never returned by the API; responses carry `password_set` / `secret_set` booleans instead. The telemetry plane's worker needs the same key to deliver those endpoints; without it the delivery is left for the API plane (not counted as an attempt).
- NotificationEmitter interface defined in `incident` package to avoid circular imports (notification → incident → notification)
- FindingNotifier interface defined in `ingest` package for the same reason

## Database Tables
- `notification_endpoints` (064) — channel config (`channel_type` + JSONB `config`, see below), min_severity, enabled flag
- `notifications` (065) — in-app feed with category/severity/reference/read/dismissed
- `notification_deliveries_v2` (066) — external delivery queue with retry state

## Files
| File | Purpose |
|------|---------|
| `internal/notification/types.go` | Endpoint, Notification, Delivery structs, SeverityRank map |
| `internal/notification/endpoint_store.go` | CRUD for notification_endpoints (nil-safe) |
| `internal/notification/notification_store.go` | Insert, List, CountUnread, MarkRead, MarkAllRead, Dismiss |
| `internal/notification/delivery_store.go` | Enqueue (ON CONFLICT DO NOTHING), PollPending (FOR UPDATE SKIP LOCKED), MarkDelivered/Failed/Dead |
| `internal/notification/manager.go` | NotificationEmitter + FindingNotifier implementation |
| `internal/notification/worker.go` | Background DeliveryWorker (5s poll, exponential backoff) |
| `internal/notification/config.go` | Channel types, per-type config validation (`ValidateConfig`), secret sealing/redaction (`SealSecrets`, `MergeSecrets`, `Redacted`, `ResolveSecret`) |
| `internal/notification/senders.go` | `Senders`: one sender per channel type, dispatch by `channel_type`, shared payload parsing |
| `internal/notification/webhook.go` | WebhookSender: POST JSON + HMAC-SHA256 signature |
| `internal/notification/slack.go` | SlackSender: Slack Block Kit formatting |
| `internal/notification/discord.go` | DiscordSender: one embed per incident, host allowlist (discord.com / discordapp.com) |
| `internal/notification/email.go` | EmailSender: SMTP via `net/smtp`, STARTTLS / implicit TLS / none, multipart text + HTML |
| `internal/notification/syslog.go` | SyslogSender: RFC 5424 over UDP, TCP (RFC 6587 octet counting) or TCP+TLS |
| `internal/notification/urlcheck.go` | Outbound URL guard (SSRF) shared by the HTTP channels |
| `internal/api/notification_handler.go` | All HTTP handlers for notifications/endpoints/deliveries |
| `components/NotificationBell.tsx` | In-app notification bell with dropdown panel |

## API Endpoints
| Method | Path | Handler |
|--------|------|---------|
| GET | /api/v1/notifications | ListNotifications |
| GET | /api/v1/notifications/count | CountUnread |
| POST | /api/v1/notifications/read-all | MarkAllRead |
| PATCH | /api/v1/notifications/{id}/read | MarkRead |
| DELETE | /api/v1/notifications/{id} | DismissNotification |
| GET | /api/v1/notification-endpoints | ListEndpoints |
| POST | /api/v1/notification-endpoints | CreateEndpoint |
| PUT | /api/v1/notification-endpoints/{id} | UpdateEndpoint |
| DELETE | /api/v1/notification-endpoints/{id} | DeleteEndpoint |
| POST | /api/v1/notification-endpoints/{id}/test | TestEndpoint |
| GET | /api/v1/notification-deliveries | ListDeliveries |

## Channels

Every channel receives the same delivery payload (`buildWebhookPayload` in `manager.go`):

```json
{
  "event": "incident.created",            // or incident.escalated, test
  "incident": {
    "id": "…", "severity": "critical", "confidence": 0.9,
    "title": "…", "summary": "…", "host_id": "host-a",
    "category": "credential_access",
    "detection_ids": ["ai.credential_access"],
    "mitre_techniques": ["T1552", "T1552.004"],
    "finding_ids": ["…"], "finding_count": 2,
    "started_at": "2026-10-09T10:00:00Z", "ended_at": "…"
  },
  "actions": { "view_url": "/incidents/…", "resolve": {…}, "dismiss": {…} }
}
```

`FRONTEND_URL` (the dashboard's public base URL) turns `view_url` into an
absolute link in Discord embeds and e-mails; without it those channels show
the incident id only.

### Config schema per `channel_type`

| Type | Required | Optional | Notes |
|------|----------|----------|-------|
| `webhook` | `url` | `secret` (HMAC-SHA256, header `X-Correlic-Signature: sha256=…`), `headers` (map) | `url` must pass the SSRF guard (public address, http/https, no redirects followed). `secret` is sealed at rest. |
| `slack` | `webhook_url` | — | Slack incoming webhook; Block Kit message. SSRF guard. |
| `discord` | `webhook_url` | — | Must be `https://discord.com/api/webhooks/…` or `https://discordapp.com/api/webhooks/…` (port 443). One embed: severity colour (red/orange/yellow/green), title, summary, host, rule (detection ids or category), MITRE, incident id, link. Mentions are disabled (`allowed_mentions.parse = []`). SSRF guard on top of the host allowlist. |
| `email` | `smtp_host`, `from`, `to` (list or comma-separated) | `smtp_port` (default 587), `security` = `starttls` (default) \| `tls` \| `none`, `username`, `password`, `subject_prefix` (≤ 64 chars) | `starttls` fails if the server does not offer STARTTLS (no silent downgrade); `tls` is implicit TLS (SMTPS, usually 465); `none` is cleartext and only accepts a username for a loopback/localhost relay. Auth is SMTP PLAIN. Subject: `<prefix> [Correlic] CRITICAL: <title>`; body is `multipart/alternative` (plain text + minimal escaped HTML). One session timeout of 20 s. `password` is sealed at rest and never returned. The SMTP host is **not** run through the HTTP SSRF guard (relays are usually internal); endpoints need the admin role. |
| `syslog` | `host` | `port` (514; 6514 for tcp+tls), `protocol` = `udp` (default) \| `tcp` \| `tcp+tls`, `facility` (name `local0`…`local7`, `auth`, `daemon`, … or 0–23; default `local0`), `ca_file` (absolute PEM path on the backend host, tcp+tls only), `insecure_skip_verify` (bool, tcp+tls only) | RFC 5424 frame `<PRI>1 TIMESTAMP HOSTNAME correlic - MSGID [correlic@32473 …] MSG`: HOSTNAME is the backend host, MSGID the event, the SD element carries `event`, `incident_id`, `severity`, `host_id`, `category`, `detection_ids`, `finding_ids`, `finding_count`, `mitre`, and MSG is the JSON payload (no UTF-8 BOM). Severity map: critical→2, high→3, medium→4, low→5, other→6. TCP uses RFC 6587 octet-counting framing; UDP frames above 65 000 bytes are refused. Like SMTP, the collector is not run through the HTTP SSRF guard. |

Examples (`POST /api/v1/notification-endpoints`):

```json
{"name": "SOC Discord", "channel_type": "discord", "min_severity": "high",
 "config": {"webhook_url": "https://discord.com/api/webhooks/1234/abcd"}}

{"name": "On-call mail", "channel_type": "email", "min_severity": "critical",
 "config": {"smtp_host": "smtp.example.com", "smtp_port": 587, "security": "starttls",
            "username": "alerts@example.com", "password": "…",
            "from": "Correlic <alerts@example.com>", "to": ["soc@example.com", "oncall@example.com"],
            "subject_prefix": "[prod]"}}

{"name": "SIEM", "channel_type": "syslog", "min_severity": "medium",
 "config": {"host": "siem.internal", "port": 6514, "protocol": "tcp+tls",
            "facility": "local4", "ca_file": "/etc/correlic/siem-ca.pem"}}
```

The response (and every later `GET`/`PUT`) returns the config without
`password` / `secret`; it carries `"password_set": true` / `"secret_set": true`
instead. A `PUT` whose `config` omits the secret (or sends it empty) keeps the
stored value; sending a new plaintext value replaces it.

`POST /api/v1/notification-endpoints/{id}/test` sends a synthetic
`event: "test"` payload (severity medium) through the real sender and returns
`{"ok": true}` or `{"ok": false, "error": "<category>"}` where the category is
one of `http <status>`, `blocked destination`, `invalid url`, `dns`,
`timeout`, `connection refused`, `request failed` (full details stay in the
server log).

## Block Rules Integration
When the agent's soft-block enforcer matches an active block rule, findings are created with `status = "blocked"` instead of `"pending"`. Blocked findings appear in the UI's "Blocked" tab and are excluded from the pending count. The block status is set when `evt.Context["action"] == "blocked"`. See `docs/BLOCK_RULES.md` for the full block rules system.

## Pipeline Integration Points
1. `incident/correlator.go` — `ingestChain()`: OnIncidentCreated after Upsert
2. `incident/correlator.go` — `mergeInto()`: OnIncidentEscalated if severity increased
3. `incident/correlator.go` — `createSeed()`: OnIncidentCreated if not auto_resolved
4. `ingest/live_ingest.go` — OnFindingStored after regular and chain finding storage

## Wiring (both cmd/api/main.go and cmd/telemetry/main.go)
```go
endpointStore := notification.NewEndpointStore(db)
notifStore := notification.NewNotificationStore(db)
deliveryStore := notification.NewDeliveryStore(db)
notifManager := notification.NewManager(notifStore, deliveryStore, endpointStore)
incidentCorrelator.SetNotificationEmitter(notifManager)
senders := notification.NewSenders(notification.SenderOptions{
    Cipher:       secretCipher,               // secrets.NewCipher(LLM_ENCRYPTION_KEY); optional on the telemetry plane
    DashboardURL: os.Getenv("FRONTEND_URL"),  // incident links in Discord embeds and e-mails
})
deliveryWorker := notification.NewDeliveryWorker(deliveryStore, endpointStore, senders)
go deliveryWorker.Start()
defer deliveryWorker.Stop()
// Pass notifManager as last arg to NewLiveIngestHandler; the API plane also
// hands secretCipher + senders to api.NewNotificationHandler.
```
