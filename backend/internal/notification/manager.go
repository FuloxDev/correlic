package notification

import (
	"context"
	"encoding/json"
	"log"
	"net/url"
	"time"

	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/incident"
)

// NotificationEmitter is the interface the pipeline calls to emit notifications.
// Nil-safe: pass nil to disable notifications entirely.
type NotificationEmitter interface {
	OnFindingStored(orgID string, f detection.Finding)
	OnIncidentCreated(orgID string, inc incident.Incident)
	OnIncidentEscalated(orgID string, inc incident.Incident, oldSeverity string)
}

// Manager orchestrates notification creation and delivery enqueueing.
// Implements NotificationEmitter. All methods do DB INSERTs only (fast, non-blocking).
type Manager struct {
	notifStore    *NotificationStore
	deliveryStore *DeliveryStore
	endpointStore *EndpointStore
}

// NewManager creates a new notification manager. Returns nil if stores are nil.
func NewManager(notifStore *NotificationStore, deliveryStore *DeliveryStore, endpointStore *EndpointStore) *Manager {
	if notifStore == nil {
		return nil
	}
	return &Manager{
		notifStore:    notifStore,
		deliveryStore: deliveryStore,
		endpointStore: endpointStore,
	}
}

// OnFindingStored is a no-op for in-app notifications.
// Findings are too granular — 10 findings may merge into 1 incident, producing
// duplicate noise. Users see findings on the findings page; incidents create
// the actionable notification via OnIncidentCreated.
func (m *Manager) OnFindingStored(orgID string, f detection.Finding) {
	// intentionally empty — incident-level notifications are sufficient
}

// OnIncidentCreated creates an in-app notification and enqueues external deliveries.
func (m *Manager) OnIncidentCreated(orgID string, inc incident.Incident) {
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// In-app notification
	n := Notification{
		OrgID:         orgID,
		Category:      "incident",
		Severity:      inc.Severity,
		Title:         "New Incident: " + inc.Title,
		Summary:       inc.Summary,
		ReferenceType: "incident",
		ReferenceID:   inc.ID,
		HostID:        inc.HostID,
		Context: map[string]any{
			"mitre_techniques": inc.MITRETechniques,
			"finding_count":    len(inc.FindingIDs),
		},
	}
	if err := m.notifStore.Insert(ctx, n); err != nil {
		log.Printf("WARN: notification insert for incident failed: %v", err)
	}

	// External delivery
	m.enqueueExternalDeliveries(ctx, orgID, inc, "incident.created")
}

// OnIncidentEscalated creates an in-app notification and enqueues external deliveries
// when an incident's severity increases.
func (m *Manager) OnIncidentEscalated(orgID string, inc incident.Incident, oldSeverity string) {
	if m == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := Notification{
		OrgID:         orgID,
		Category:      "incident",
		Severity:      inc.Severity,
		Title:         "Escalated: " + inc.Title,
		Summary:       "Severity changed from " + oldSeverity + " to " + inc.Severity,
		ReferenceType: "incident",
		ReferenceID:   inc.ID,
		HostID:        inc.HostID,
		Context: map[string]any{
			"old_severity":     oldSeverity,
			"mitre_techniques": inc.MITRETechniques,
			"finding_count":    len(inc.FindingIDs),
		},
	}
	if err := m.notifStore.Insert(ctx, n); err != nil {
		log.Printf("WARN: notification insert for escalation failed: %v", err)
	}

	m.enqueueExternalDeliveries(ctx, orgID, inc, "incident.escalated")
}

// enqueueExternalDeliveries creates delivery queue entries for all matching endpoints.
func (m *Manager) enqueueExternalDeliveries(ctx context.Context, orgID string, inc incident.Incident, eventType string) {
	if m.endpointStore == nil || m.deliveryStore == nil {
		return
	}

	sevRank := SeverityRank[inc.Severity]
	endpoints, err := m.endpointStore.ListEnabled(ctx, orgID, sevRank)
	if err != nil {
		log.Printf("WARN: list enabled endpoints failed: %v", err)
		return
	}

	payload := buildWebhookPayload(eventType, inc)

	for _, ep := range endpoints {
		d := Delivery{
			OrgID:         orgID,
			EndpointID:    ep.ID,
			ReferenceType: "incident",
			ReferenceID:   inc.ID,
			Payload:       payload,
			MaxAttempts:   5,
		}
		if err := m.deliveryStore.Enqueue(ctx, d); err != nil {
			log.Printf("WARN: enqueue delivery for endpoint %s failed: %v", ep.ID, err)
		}
	}
}

// buildWebhookPayload constructs the JSON payload for external delivery.
func buildWebhookPayload(eventType string, inc incident.Incident) map[string]any {
	encodedID := url.PathEscape(inc.ID)
	return map[string]any{
		"event": eventType,
		"incident": map[string]any{
			"id":               inc.ID,
			"severity":         inc.Severity,
			"confidence":       inc.Confidence,
			"title":            inc.Title,
			"summary":          inc.Summary,
			"host_id":          inc.HostID,
			"mitre_techniques": inc.MITRETechniques,
			"finding_count":    len(inc.FindingIDs),
			"started_at":       inc.StartedAt.Format(time.RFC3339),
			"ended_at":         inc.EndedAt.Format(time.RFC3339),
		},
		"actions": map[string]any{
			"view_url": "/incidents/" + encodedID,
			"resolve": map[string]any{
				"method": "PATCH",
				"path":   "/api/v1/incidents/" + encodedID,
				"body":   json.RawMessage(`{"status":"resolved"}`),
			},
			"dismiss": map[string]any{
				"method": "PATCH",
				"path":   "/api/v1/incidents/" + encodedID,
				"body":   json.RawMessage(`{"status":"dismissed"}`),
			},
		},
	}
}
