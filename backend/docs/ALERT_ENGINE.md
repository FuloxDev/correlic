# Phase 6 — Alert Engine

## Architecture
```
Detection Pipeline → Finding stored → Manager.OnFindingStored()  → in-app notification INSERT
                   → Incident created/escalated → OnIncidentCreated/Escalated() → in-app + delivery queue
                                                                                      ↓
DeliveryWorker (5s poll) → PollPending() → WebhookSender / SlackSender → MarkDelivered/Failed
```

## Key Design Decisions
- In-app notifications for ALL findings (already deduplicated by pipeline cooldown)
- External channels (webhook/Slack) only for incidents (not 50 notifications per burst)
- Skip auto_resolved incidents for external delivery
- Severity gating: user sets min_severity per endpoint
- Dedup: unique index on (endpoint_id, reference_type, reference_id)
- NotificationEmitter interface defined in `incident` package to avoid circular imports (notification → incident → notification)
- FindingNotifier interface defined in `ingest` package for the same reason

## Database Tables
- `notification_endpoints` (064) — channel config (webhook/slack), min_severity, enabled flag
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
| `internal/notification/webhook.go` | WebhookSender: POST JSON + HMAC-SHA256 signature |
| `internal/notification/slack.go` | SlackSender: Slack Block Kit formatting |
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
deliveryWorker := notification.NewDeliveryWorker(deliveryStore, endpointStore)
go deliveryWorker.Start()
defer deliveryWorker.Stop()
// Pass notifManager as last arg to NewLiveIngestHandler
```
