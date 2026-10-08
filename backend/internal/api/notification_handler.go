package api

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/notification"
	"github.com/google/uuid"
)

// NotificationHandler handles HTTP requests for notifications, endpoints, and deliveries.
type NotificationHandler struct {
	notifStore    *notification.NotificationStore
	endpointStore *notification.EndpointStore
	deliveryStore *notification.DeliveryStore
}

// NewNotificationHandler creates a new notification handler.
func NewNotificationHandler(notifStore *notification.NotificationStore, endpointStore *notification.EndpointStore, deliveryStore *notification.DeliveryStore) *NotificationHandler {
	return &NotificationHandler{
		notifStore:    notifStore,
		endpointStore: endpointStore,
		deliveryStore: deliveryStore,
	}
}

// --- In-App Notifications ---

// ListNotifications handles GET /api/v1/notifications?unread_only=true&limit=50
func (h *NotificationHandler) ListNotifications(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	unreadOnly := r.URL.Query().Get("unread_only") == "true"
	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		n := 0
		for _, c := range l {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 && n <= 200 {
			limit = n
		}
	}

	notifications, err := h.notifStore.List(r.Context(), orgID, unreadOnly, limit)
	if err != nil {
		log.Printf("ERROR: list notifications: %v", err)
		Internal(w)
		return
	}
	if notifications == nil {
		notifications = []notification.Notification{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"notifications": notifications,
		"count":         len(notifications),
	})
}

// CountUnread handles GET /api/v1/notifications/count
func (h *NotificationHandler) CountUnread(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	count, err := h.notifStore.CountUnread(r.Context(), orgID)
	if err != nil {
		log.Printf("ERROR: count unread notifications: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"unread_count": count})
}

// MarkRead handles PATCH /api/v1/notifications/{id}/read
func (h *NotificationHandler) MarkRead(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	id := extractNotificationID(r.URL.Path, "/read")
	if id == "" {
		BadRequest(w, "notification ID required")
		return
	}

	if err := h.notifStore.MarkRead(r.Context(), orgID, id); err != nil {
		if err.Error() == "notification not found" {
			NotFound(w, "notification not found")
			return
		}
		log.Printf("ERROR: mark notification read: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// MarkAllRead handles POST /api/v1/notifications/read-all
func (h *NotificationHandler) MarkAllRead(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	if err := h.notifStore.MarkAllRead(r.Context(), orgID); err != nil {
		log.Printf("ERROR: mark all notifications read: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// DismissNotification handles DELETE /api/v1/notifications/{id}
func (h *NotificationHandler) DismissNotification(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	id := extractTrailingID(r.URL.Path, "/api/v1/notifications/")
	if id == "" {
		BadRequest(w, "notification ID required")
		return
	}

	if err := h.notifStore.Dismiss(r.Context(), orgID, id); err != nil {
		log.Printf("ERROR: dismiss notification: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// --- Notification Endpoints (channel config) ---

// ListEndpoints handles GET /api/v1/notification-endpoints
func (h *NotificationHandler) ListEndpoints(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	endpoints, err := h.endpointStore.List(r.Context(), orgID)
	if err != nil {
		log.Printf("ERROR: list notification endpoints: %v", err)
		Internal(w)
		return
	}
	if endpoints == nil {
		endpoints = []notification.Endpoint{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"endpoints": endpoints,
		"count":     len(endpoints),
	})
}

// CreateEndpoint handles POST /api/v1/notification-endpoints
func (h *NotificationHandler) CreateEndpoint(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	var body struct {
		Name        string         `json:"name"`
		ChannelType string         `json:"channel_type"`
		Config      map[string]any `json:"config"`
		MinSeverity string         `json:"min_severity"`
		Enabled     *bool          `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid request body")
		return
	}

	if body.Name == "" {
		BadRequest(w, "name is required")
		return
	}
	if body.ChannelType != "webhook" && body.ChannelType != "slack" {
		BadRequest(w, "channel_type must be 'webhook' or 'slack'")
		return
	}
	if body.Config == nil {
		body.Config = map[string]any{}
	}

	// Validate channel-specific config, including the SSRF guard on the URL.
	if msg, ok := validateEndpointConfig(body.ChannelType, body.Config); !ok {
		BadRequest(w, msg)
		return
	}

	validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
	if body.MinSeverity == "" {
		body.MinSeverity = "medium"
	}
	if !validSeverities[body.MinSeverity] {
		BadRequest(w, "min_severity must be: low, medium, high, or critical")
		return
	}

	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	endpoint := notification.Endpoint{
		ID:          uuid.New().String(),
		OrgID:       orgID,
		Name:        body.Name,
		ChannelType: body.ChannelType,
		Config:      body.Config,
		MinSeverity: body.MinSeverity,
		Enabled:     enabled,
	}

	if err := h.endpointStore.Create(r.Context(), endpoint); err != nil {
		log.Printf("ERROR: create notification endpoint: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]any{
		"endpoint": endpoint,
	})
}

// UpdateEndpoint handles PUT /api/v1/notification-endpoints/{id}
func (h *NotificationHandler) UpdateEndpoint(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	id := extractTrailingID(r.URL.Path, "/api/v1/notification-endpoints/")
	if id == "" {
		BadRequest(w, "endpoint ID required")
		return
	}

	// Verify endpoint exists and belongs to org
	existing, err := h.endpointStore.GetByID(r.Context(), orgID, id)
	if err != nil {
		if err == sql.ErrNoRows {
			NotFound(w, "endpoint not found")
			return
		}
		log.Printf("ERROR: get endpoint for update: %v", err)
		Internal(w)
		return
	}

	var body struct {
		Name        *string        `json:"name"`
		ChannelType *string        `json:"channel_type"`
		Config      map[string]any `json:"config"`
		MinSeverity *string        `json:"min_severity"`
		Enabled     *bool          `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid request body")
		return
	}

	// Apply partial updates
	if body.Name != nil {
		existing.Name = *body.Name
	}
	if body.ChannelType != nil {
		if *body.ChannelType != "webhook" && *body.ChannelType != "slack" {
			BadRequest(w, "channel_type must be 'webhook' or 'slack'")
			return
		}
		existing.ChannelType = *body.ChannelType
	}
	if body.Config != nil {
		existing.Config = body.Config
	}
	if body.MinSeverity != nil {
		validSeverities := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		if !validSeverities[*body.MinSeverity] {
			BadRequest(w, "min_severity must be: low, medium, high, or critical")
			return
		}
		existing.MinSeverity = *body.MinSeverity
	}
	if body.Enabled != nil {
		existing.Enabled = *body.Enabled
	}

	// Re-run the config/URL validation whenever the channel or config changed.
	if body.ChannelType != nil || body.Config != nil {
		if msg, ok := validateEndpointConfig(existing.ChannelType, existing.Config); !ok {
			BadRequest(w, msg)
			return
		}
	}

	if err := h.endpointStore.Update(r.Context(), *existing); err != nil {
		log.Printf("ERROR: update notification endpoint: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"endpoint": existing,
	})
}

// DeleteEndpoint handles DELETE /api/v1/notification-endpoints/{id}
func (h *NotificationHandler) DeleteEndpoint(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	id := extractTrailingID(r.URL.Path, "/api/v1/notification-endpoints/")
	if id == "" {
		BadRequest(w, "endpoint ID required")
		return
	}

	if err := h.endpointStore.Delete(r.Context(), orgID, id); err != nil {
		log.Printf("ERROR: delete notification endpoint: %v", err)
		Internal(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// TestEndpoint handles POST /api/v1/notification-endpoints/{id}/test
func (h *NotificationHandler) TestEndpoint(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract ID: strip /test suffix, then extract trailing ID
	path := strings.TrimSuffix(r.URL.Path, "/test")
	id := extractTrailingID(path, "/api/v1/notification-endpoints/")
	if id == "" {
		BadRequest(w, "endpoint ID required")
		return
	}

	endpoint, err := h.endpointStore.GetByID(r.Context(), orgID, id)
	if err != nil {
		if err == sql.ErrNoRows {
			NotFound(w, "endpoint not found")
			return
		}
		log.Printf("ERROR: get endpoint for test: %v", err)
		Internal(w)
		return
	}

	// Build a test payload
	testPayload := map[string]any{
		"event": "test",
		"incident": map[string]any{
			"id":               "test-" + uuid.New().String()[:8],
			"severity":         "medium",
			"confidence":       0.75,
			"title":            "Test Notification",
			"summary":          "This is a test notification from Correlic to verify your endpoint configuration.",
			"host_id":          "test-host",
			"mitre_techniques": []string{"T0000"},
			"finding_count":    1,
		},
	}

	// Stored endpoints predate the SSRF guard or may have been re-pointed by
	// DNS since: validate again before contacting anything.
	if msg, ok := validateEndpointConfig(endpoint.ChannelType, endpoint.Config); !ok {
		BadRequest(w, msg)
		return
	}

	var sendErr error
	switch endpoint.ChannelType {
	case "webhook":
		sender := notification.NewWebhookSender()
		sendErr = sender.Send(r.Context(), *endpoint, testPayload)
	case "slack":
		sender := notification.NewSlackSender()
		sendErr = sender.Send(r.Context(), *endpoint, testPayload)
	default:
		BadRequest(w, "unsupported channel type")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if sendErr != nil {
		// Full error (dial addresses, upstream bodies) stays in the log; the
		// client only learns the failure category.
		log.Printf("WARN: test notification endpoint %s failed: %v", endpoint.ID, sendErr)
		json.NewEncoder(w).Encode(map[string]any{
			"ok":    false,
			"error": notification.CategorizeSendError(sendErr),
		})
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// validateEndpointConfig checks the channel-specific config of a notification
// endpoint and runs the outbound URL guard. It returns a client-safe message
// and false on failure.
func validateEndpointConfig(channelType string, config map[string]any) (string, bool) {
	var key, rawURL string
	switch channelType {
	case "webhook":
		key = "url"
	case "slack":
		key = "webhook_url"
	default:
		return "channel_type must be 'webhook' or 'slack'", false
	}
	rawURL, _ = config[key].(string)
	if strings.TrimSpace(rawURL) == "" {
		return channelType + " config requires '" + key + "'", false
	}
	if err := notification.ValidateOutboundURL(rawURL); err != nil {
		log.Printf("WARN: notification endpoint %s rejected: %v", key, err)
		return key + " rejected: " + notification.CategorizeSendError(err), false
	}
	return "", true
}

// --- Delivery History ---

// ListDeliveries handles GET /api/v1/notification-deliveries?limit=50
func (h *NotificationHandler) ListDeliveries(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	limit := 50
	if l := r.URL.Query().Get("limit"); l != "" {
		n := 0
		for _, c := range l {
			if c >= '0' && c <= '9' {
				n = n*10 + int(c-'0')
			}
		}
		if n > 0 && n <= 200 {
			limit = n
		}
	}

	deliveries, err := h.deliveryStore.ListByOrg(r.Context(), orgID, limit)
	if err != nil {
		log.Printf("ERROR: list deliveries: %v", err)
		Internal(w)
		return
	}
	if deliveries == nil {
		deliveries = []notification.Delivery{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"deliveries": deliveries,
		"count":      len(deliveries),
	})
}

// --- Helpers ---

// extractTrailingID extracts the ID after a prefix. e.g. /api/v1/notifications/abc → "abc"
func extractTrailingID(path, prefix string) string {
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := path[len(prefix):]
	id = strings.TrimSuffix(id, "/")
	// Stop at next slash if any
	if idx := strings.Index(id, "/"); idx >= 0 {
		id = id[:idx]
	}
	return id
}

// extractNotificationID extracts notification ID from paths like /api/v1/notifications/{id}/read
func extractNotificationID(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	return extractTrailingID(path, "/api/v1/notifications/")
}
