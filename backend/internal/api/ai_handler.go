package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/correlic/correlic-backend/internal/ai/attribution"
	"github.com/correlic/correlic-backend/internal/ai/provider"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/storage"
	neo4jstore "github.com/correlic/correlic-backend/internal/storage/neo4j"
	"github.com/google/uuid"
)

// AIHandler handles AI-related API endpoints.
type AIHandler struct {
	settingsStore      *provider.SettingsStore
	telemetryStore     storage.TelemetryStore
	graphStore         *neo4jstore.GraphStore
	attributionService *attribution.Service
}

// NewAIHandler creates a new AI handler.
func NewAIHandler(settingsStore *provider.SettingsStore, telemetryStore storage.TelemetryStore, graphStore *neo4jstore.GraphStore, attributionService *attribution.Service) *AIHandler {
	return &AIHandler{
		settingsStore:      settingsStore,
		telemetryStore:     telemetryStore,
		graphStore:         graphStore,
		attributionService: attributionService,
	}
}

// RegisterRoutes registers AI routes with the mux.
//
//   - wrapAuthed: any non-agent actor (admin, member).
//   - wrapAgent: additionally allows the agent role; used for the pattern list
//     that agents poll.
//   - wrapAdminWrites: GET for admin and member, every other method admin only;
//     used for provider settings and pattern management.
func (h *AIHandler) RegisterRoutes(mux *http.ServeMux, wrapAuthed, wrapAgent, wrapAdminWrites func(http.Handler) http.Handler) {
	mux.Handle("GET /api/v1/ai/patterns", wrapAgent(http.HandlerFunc(h.ListPatterns)))
	mux.Handle("GET /api/v1/ai/settings", wrapAdminWrites(http.HandlerFunc(h.ListSettings)))
	mux.Handle("POST /api/v1/ai/settings", wrapAdminWrites(http.HandlerFunc(h.SaveSettings)))
	mux.Handle("DELETE /api/v1/ai/settings", wrapAdminWrites(http.HandlerFunc(h.DeleteSettings)))
	mux.Handle("PUT /api/v1/ai/settings/switch", wrapAdminWrites(http.HandlerFunc(h.SwitchProvider)))
	mux.Handle("POST /api/v1/ai/analyze", wrapAuthed(http.HandlerFunc(h.AnalyzeEvents)))
	mux.Handle("POST /api/v1/ai/explain", wrapAuthed(http.HandlerFunc(h.ExplainEvent)))
	mux.Handle("GET /api/v1/ai/agent-patterns", wrapAdminWrites(http.HandlerFunc(h.ListAgentPatterns)))
	mux.Handle("POST /api/v1/ai/agent-patterns", wrapAdminWrites(http.HandlerFunc(h.CreateAgentPattern)))
	mux.Handle("DELETE /api/v1/ai/agent-patterns/", wrapAdminWrites(http.HandlerFunc(h.DeleteAgentPattern)))
	mux.Handle("POST /api/v1/ai/suggest-patterns", wrapAdminWrites(http.HandlerFunc(h.SuggestPatterns)))
}

// ListSettings returns configured LLM providers.
func (h *AIHandler) ListSettings(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromContext(r)
	if orgID == uuid.Nil {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	settings, err := h.settingsStore.ListSettings(r.Context(), orgID)
	if err != nil {
		InternalErr(w, "list llm settings", err)
		return
	}

	writeJSON(w, map[string]any{
		"settings": settings,
		"available_providers": []map[string]any{
			{
				"name":         "groq",
				"display_name": "Groq (Free)",
				"models":       []string{"llama-3.3-70b-versatile", "mixtral-8x7b-32768", "llama-3.1-8b-instant"},
				"free":         true,
			},
			{
				"name":         "gemini",
				"display_name": "Google Gemini",
				"models":       []string{"gemini-3-pro", "gemini-2.5-pro", "gemini-2.0-flash-lite", "gemini-1.5-pro"},
				"free":         false,
			},
			{
				"name":         "openai",
				"display_name": "OpenAI",
				"models":       []string{"gpt-4o", "gpt-4o-mini", "gpt-4-turbo"},
				"free":         false,
			},
			{
				"name":         "anthropic",
				"display_name": "Anthropic",
				"models":       []string{"claude-sonnet-4-20250514", "claude-haiku-4-20250414"},
				"free":         false,
			},
			{
				"name":         "xai",
				"display_name": "xAI (Grok)",
				"models":       []string{"grok-3-mini", "grok-3", "grok-2"},
				"free":         false,
			},
		},
	})
}

// SaveSettings saves LLM provider settings.
func (h *AIHandler) SaveSettings(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromContext(r)
	if orgID == uuid.Nil {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	var req struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		APIKey   string `json:"api_key"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Provider == "" || req.APIKey == "" {
		http.Error(w, "provider and api_key required", http.StatusBadRequest)
		return
	}

	// Validate provider
	if req.Provider != "openai" && req.Provider != "gemini" && req.Provider != "groq" && req.Provider != "anthropic" && req.Provider != "xai" {
		http.Error(w, "invalid provider: must be 'openai', 'gemini', 'groq', 'anthropic', or 'xai'", http.StatusBadRequest)
		return
	}

	// Set default model if not provided
	if req.Model == "" {
		switch req.Provider {
		case "openai":
			req.Model = "gpt-4o-mini"
		case "gemini":
			req.Model = "gemini-2.0-flash-lite"
		case "groq":
			req.Model = "llama-3.3-70b-versatile"
		case "anthropic":
			req.Model = "claude-sonnet-4-20250514"
		case "xai":
			req.Model = "grok-3-mini"
		}
	}

	settings, err := h.settingsStore.SaveSettings(r.Context(), orgID, req.Provider, req.Model, req.APIKey)
	if err != nil {
		InternalErr(w, "save llm settings", err)
		return
	}

	writeJSON(w, map[string]any{
		"message":  "settings saved",
		"settings": settings,
	})
}

// DeleteSettings removes LLM provider settings.
func (h *AIHandler) DeleteSettings(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromContext(r)
	if orgID == uuid.Nil {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		http.Error(w, "provider query param required", http.StatusBadRequest)
		return
	}

	if err := h.settingsStore.DeleteSettings(r.Context(), orgID, providerName); err != nil {
		InternalErr(w, "delete llm settings", err)
		return
	}

	writeJSON(w, map[string]string{"message": "settings deleted"})
}

// SwitchProvider switches to a different configured provider.
func (h *AIHandler) SwitchProvider(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromContext(r)
	if orgID == uuid.Nil {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	var req struct {
		Provider string `json:"provider"`
		Model    string `json:"model,omitempty"` // Optional: also change model
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Provider == "" {
		http.Error(w, "provider required", http.StatusBadRequest)
		return
	}

	// Verify provider is configured
	settings, _, err := h.settingsStore.GetSettings(r.Context(), orgID, req.Provider)
	if err != nil {
		InternalErr(w, "check llm provider", err)
		return
	}
	if settings == nil {
		http.Error(w, "provider not configured - please add API key first", http.StatusBadRequest)
		return
	}

	// Disable other providers, enable this one
	allSettings, _ := h.settingsStore.ListSettings(r.Context(), orgID)
	for _, s := range allSettings {
		if s.Provider != req.Provider {
			h.settingsStore.DisableProvider(r.Context(), orgID, s.Provider)
		}
	}

	// Enable and optionally update model
	model := req.Model
	if model == "" {
		model = settings.Model
	}

	// Re-save to enable and update
	settings, err = h.settingsStore.EnableProvider(r.Context(), orgID, req.Provider, model)
	if err != nil {
		InternalErr(w, "switch llm provider", err)
		return
	}

	writeJSON(w, map[string]any{
		"message":         "switched to " + req.Provider,
		"active_provider": settings,
	})
}

// AnalyzeEvents analyzes events using the configured LLM.
func (h *AIHandler) AnalyzeEvents(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromContext(r)
	if orgID == uuid.Nil {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	var req struct {
		EventIDs []string         `json:"event_ids,omitempty"`
		PID      int64            `json:"pid,omitempty"`
		HostID   string           `json:"host_id,omitempty"`
		Events   []map[string]any `json:"events,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Get LLM provider
	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if llmProvider == nil {
		http.Error(w, "no LLM provider configured - please add API key in settings", http.StatusBadRequest)
		return
	}

	// Get events to analyze
	events := req.Events
	if len(events) == 0 && h.graphStore != nil && req.PID > 0 && req.HostID != "" {
		// Query from Neo4j graph
		result, err := h.graphStore.GetProcessTree(r.Context(), req.PID, req.HostID)
		if err == nil && len(result.Events) > 0 {
			for _, e := range result.Events {
				events = append(events, map[string]any{
					"id":      e.ID,
					"type":    e.Type,
					"pid":     e.ActorPID,
					"ppid":    e.ActorPPID,
					"exe":     e.ActorExe,
					"user":    e.ActorUser,
					"host_id": e.HostID,
				})
			}
		}
	}

	if len(events) == 0 {
		http.Error(w, "no events provided and no events found for the given criteria", http.StatusBadRequest)
		return
	}

	// Analyze with LLM
	analysis, err := llmProvider.AnalyzeEvents(r.Context(), events)
	if err != nil {
		http.Error(w, "LLM analysis failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, analysis)
}

// ExplainEvent explains a single event using the configured LLM.
func (h *AIHandler) ExplainEvent(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromContext(r)
	if orgID == uuid.Nil {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	var req struct {
		Event   map[string]any `json:"event,omitempty"`
		EventID string         `json:"event_id,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Get LLM provider
	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if llmProvider == nil {
		http.Error(w, "no LLM provider configured - please add API key in settings", http.StatusBadRequest)
		return
	}

	event := req.Event
	if len(event) == 0 {
		http.Error(w, "event object required", http.StatusBadRequest)
		return
	}

	// Explain with LLM
	explanation, err := llmProvider.ExplainEvent(r.Context(), event)
	if err != nil {
		http.Error(w, "LLM explanation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, explanation)
}

// getProvider creates an LLM provider from settings.
func (h *AIHandler) getProvider(ctx context.Context, orgID uuid.UUID) (provider.Provider, error) {
	settings, apiKey, err := h.settingsStore.GetActiveProvider(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if settings == nil {
		return nil, nil
	}

	cfg := provider.Config{
		APIKey:      apiKey,
		Model:       settings.Model,
		MaxTokens:   settings.MaxTokens,
		Temperature: settings.Temperature,
	}

	switch settings.Provider {
	case "openai":
		return provider.NewOpenAIProvider(cfg), nil
	case "gemini":
		return provider.NewGeminiProvider(cfg), nil
	case "groq":
		return provider.NewGroqProvider(cfg), nil
	case "anthropic":
		return provider.NewAnthropicProvider(cfg), nil
	case "xai":
		return provider.NewXAIProvider(cfg), nil
	default:
		return nil, nil
	}
}

// getOrgIDFromContext extracts org_id from request context.
func getOrgIDFromContext(r *http.Request) uuid.UUID {
	orgIDStr, ok := middleware.OrgFromContext(r.Context())
	if !ok || orgIDStr == "" {
		return uuid.Nil
	}
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return uuid.Nil
	}
	return orgID
}

func writeJSON(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// ListPatterns returns the list of AI agent patterns (string-only, for agent consumption).
func (h *AIHandler) ListPatterns(w http.ResponseWriter, r *http.Request) {
	if h.attributionService == nil {
		writeJSON(w, map[string]any{"patterns": []string{}})
		return
	}

	// Built-ins plus this org's own patterns (never another tenant's).
	orgID, _ := middleware.OrgFromContext(r.Context())
	patterns := h.attributionService.GetPatternNeedlesForOrg(orgID)
	if patterns == nil {
		patterns = []string{}
	}
	writeJSON(w, map[string]any{
		"patterns": patterns,
	})
}

// ListAgentPatterns returns all AI agent patterns with full details.
func (h *AIHandler) ListAgentPatterns(w http.ResponseWriter, r *http.Request) {
	if h.attributionService == nil {
		writeJSON(w, map[string]any{"patterns": []attribution.AIAgentPattern{}})
		return
	}

	orgID, _ := middleware.OrgFromContext(r.Context())
	patterns, err := h.attributionService.GetAllPatterns(orgID)
	if err != nil {
		http.Error(w, "failed to list patterns", http.StatusInternalServerError)
		return
	}
	if patterns == nil {
		patterns = []attribution.AIAgentPattern{}
	}

	writeJSON(w, map[string]any{"patterns": patterns})
}

// CreateAgentPattern adds a new AI agent pattern.
func (h *AIHandler) CreateAgentPattern(w http.ResponseWriter, r *http.Request) {
	if h.attributionService == nil {
		http.Error(w, "attribution service not available", http.StatusInternalServerError)
		return
	}

	var req struct {
		Pattern     string `json:"pattern"`
		AgentType   string `json:"agent_type"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if strings.TrimSpace(req.Pattern) == "" || strings.TrimSpace(req.AgentType) == "" {
		http.Error(w, "pattern and agent_type are required", http.StatusBadRequest)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok || orgID == "" {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	// The pattern is owned by the creating org; built-ins (org_id NULL) come only from migrations.
	created, err := h.attributionService.CreatePattern(orgID, attribution.AIAgentPattern{
		Pattern:     req.Pattern,
		AgentType:   req.AgentType,
		Description: req.Description,
	})
	if err != nil {
		if errors.Is(err, attribution.ErrPatternExists) {
			http.Error(w, "pattern already exists", http.StatusConflict)
			return
		}
		http.Error(w, "failed to create pattern", http.StatusInternalServerError)
		return
	}

	// Update global needles so detection pipeline picks up the change immediately
	SetAIProcessNeedles(h.attributionService.GetPatternNeedles())

	resp := map[string]any{"pattern": created}
	if len(strings.TrimSpace(req.Pattern)) > 15 {
		resp["warning"] = "Pattern exceeds 15 characters. Linux truncates process names (comm) to 15 chars. " +
			"The agent will still match via full command line, but primary comm-based matching may miss this pattern."
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, resp)
}

// DeleteAgentPattern removes an AI agent pattern by ID.
func (h *AIHandler) DeleteAgentPattern(w http.ResponseWriter, r *http.Request) {
	if h.attributionService == nil {
		http.Error(w, "attribution service not available", http.StatusInternalServerError)
		return
	}

	// Extract ID from path: /api/v1/ai/agent-patterns/{id}
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")
	if len(parts) == 0 {
		http.Error(w, "pattern ID required", http.StatusBadRequest)
		return
	}
	idStr := parts[len(parts)-1]
	id, err := strconv.Atoi(idStr)
	if err != nil {
		http.Error(w, "invalid pattern ID", http.StatusBadRequest)
		return
	}

	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok || orgID == "" {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	// Only the org's own patterns are deletable; built-ins and other orgs' read as not found.
	if err := h.attributionService.DeletePattern(orgID, id); err != nil {
		if errors.Is(err, attribution.ErrPatternNotFound) {
			http.Error(w, "pattern not found", http.StatusNotFound)
			return
		}
		http.Error(w, "failed to delete pattern", http.StatusInternalServerError)
		return
	}

	// Update global needles
	SetAIProcessNeedles(h.attributionService.GetPatternNeedles())

	w.WriteHeader(http.StatusNoContent)
}

// SuggestPatterns uses the configured LLM to suggest process name patterns for a given software.
func (h *AIHandler) SuggestPatterns(w http.ResponseWriter, r *http.Request) {
	orgID := getOrgIDFromContext(r)
	if orgID == uuid.Nil {
		http.Error(w, "org_id required", http.StatusUnauthorized)
		return
	}

	var req struct {
		SoftwareName string `json:"software_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(req.SoftwareName) == "" {
		http.Error(w, "software_name is required", http.StatusBadRequest)
		return
	}

	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if llmProvider == nil {
		http.Error(w, "no LLM provider configured - please add API key in settings first", http.StatusBadRequest)
		return
	}

	systemPrompt := `You are a security expert helping configure process monitoring on Linux.
The user wants to monitor a specific software. Return a JSON array of process name patterns to track.

Each entry must have:
- "pattern": the process name substring (max 15 chars, lowercase) as it appears in ps aux or top
- "agent_type": a short snake_case identifier for this software (e.g., "docker", "vscode")
- "description": one-line explanation of what this process does

Rules:
- Only include patterns specific enough to avoid false positives
- Focus on the main binary names and common helper processes
- Keep patterns short (Linux comm field is limited to 15 chars)
- Return ONLY the JSON array, no markdown fences, no explanation text`

	userMsg := "Suggest process name patterns for monitoring: " + strings.TrimSpace(req.SoftwareName)

	resp, err := llmProvider.Chat(r.Context(), &provider.ChatRequest{
		Messages: []provider.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userMsg},
		},
	})
	if err != nil {
		http.Error(w, "LLM request failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]any{
		"suggestion": resp.Content,
		"model":      resp.Model,
	})
}
