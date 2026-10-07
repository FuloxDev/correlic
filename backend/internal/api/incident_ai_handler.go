package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/correlic/correlic-backend/internal/ai"
	"github.com/correlic/correlic-backend/internal/ai/conversation"
	"github.com/correlic/correlic-backend/internal/ai/dossier"
	"github.com/correlic/correlic-backend/internal/ai/intelligence"
	"github.com/correlic/correlic-backend/internal/ai/provider"
	"github.com/correlic/correlic-backend/internal/ai/tools"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/query"
	"github.com/correlic/correlic-backend/internal/storage"
	neo4jstore "github.com/correlic/correlic-backend/internal/storage/neo4j"
	"github.com/google/uuid"
)

// IncidentAIHandler handles AI endpoints scoped to incidents and findings.
type IncidentAIHandler struct {
	settingsStore  *provider.SettingsStore
	assembler      *incident.ContextAssembler
	findingStore   *storage.FindingStore
	summaryStore   *ai.IncidentSummaryStore   // nil-safe
	dossierStore   *dossier.Store             // nil-safe
	dossierBuilder *dossier.DossierBuilder    // nil-safe
	convStore      *conversation.Store        // nil-safe
	toolRegistry   map[string]*tools.Tool     // nil-safe — tool-calling disabled when nil
	queryService   *query.Service             // nil-safe — required for tool execution
	graphStore     *neo4jstore.GraphStore     // nil-safe — graph tools unavailable when nil
	intStore       *intelligence.Store        // nil-safe — intelligence tools unavailable when nil
}

// maxToolIterations is the maximum number of tool-calling loop iterations per chat request.
const maxToolIterations = 5

// NewIncidentAIHandler creates a new incident AI handler.
func NewIncidentAIHandler(
	settingsStore *provider.SettingsStore,
	assembler *incident.ContextAssembler,
	findingStore *storage.FindingStore,
	summaryStore *ai.IncidentSummaryStore,
	dossierStore *dossier.Store,
	dossierBuilder *dossier.DossierBuilder,
	convStore *conversation.Store,
	queryService *query.Service,
	graphStore *neo4jstore.GraphStore,
	intStore *intelligence.Store,
) *IncidentAIHandler {
	var registry map[string]*tools.Tool
	if queryService != nil {
		registry = tools.NewRegistry(queryService, graphStore, intStore)
	}
	return &IncidentAIHandler{
		settingsStore:  settingsStore,
		assembler:      assembler,
		findingStore:   findingStore,
		summaryStore:   summaryStore,
		dossierStore:   dossierStore,
		dossierBuilder: dossierBuilder,
		convStore:      convStore,
		toolRegistry:   registry,
		queryService:   queryService,
		graphStore:     graphStore,
		intStore:       intStore,
	}
}

// buildToolDefinitions converts the tool registry into provider.ToolDefinition slice
// with JSON Schema parameters for each tool.
func (h *IncidentAIHandler) buildToolDefinitions() []provider.ToolDefinition {
	if h.toolRegistry == nil {
		return nil
	}
	defs := make([]provider.ToolDefinition, 0, len(h.toolRegistry))
	for _, t := range h.toolRegistry {
		var params map[string]any

		switch t.Name {
		case "get_system_profile":
			params = map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			}
		case "get_recent_activity":
			params = map[string]any{
				"type": "object",
				"properties": map[string]any{
					"granularity": map[string]any{
						"type":        "string",
						"description": "Time granularity: '1m', '1h', '24h', or 'weekly'",
					},
					"count": map[string]any{
						"type":        "integer",
						"description": "Number of windows to return (default: 1, max: 10)",
					},
				},
				"required": []string{"granularity"},
			}
		case "get_learned_patterns":
			params = map[string]any{
				"type":       "object",
				"properties": map[string]any{},
			}
		case "get_false_positive_rate":
			params = map[string]any{
				"type": "object",
				"properties": map[string]any{
					"since": map[string]any{
						"type":        "string",
						"format":      "date-time",
						"description": "Start time (RFC3339). Default: 30 days ago.",
					},
				},
			}
		default:
			params = map[string]any{
				"type": "object",
				"properties": map[string]any{
					"host_id": map[string]any{
						"type":        "string",
						"description": "Host ID to query (auto-set by system, do not override)",
					},
					"since": map[string]any{
						"type":        "string",
						"format":      "date-time",
						"description": "Start of time window (RFC3339)",
					},
					"until": map[string]any{
						"type":        "string",
						"format":      "date-time",
						"description": "End of time window (RFC3339)",
					},
					"pattern": map[string]any{
						"type":        "string",
						"description": "Search pattern (file path, executable name, or IP address)",
					},
					"pid": map[string]any{
						"type":        "integer",
						"description": "Process ID or session ID for graph queries",
					},
					"base_since": map[string]any{
						"type":        "string",
						"format":      "date-time",
						"description": "Start of baseline window for diff tools (RFC3339)",
					},
					"base_until": map[string]any{
						"type":        "string",
						"format":      "date-time",
						"description": "End of baseline window for diff tools (RFC3339)",
					},
					"compare_since": map[string]any{
						"type":        "string",
						"format":      "date-time",
						"description": "Start of comparison window for diff tools (RFC3339)",
					},
					"compare_until": map[string]any{
						"type":        "string",
						"format":      "date-time",
						"description": "End of comparison window for diff tools (RFC3339)",
					},
				},
			}
		}

		defs = append(defs, provider.ToolDefinition{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  params,
		})
	}
	return defs
}

// executeToolCall runs a single tool call with security enforcement.
// Forces host_id to the incident's host, and clamps time windows to incident bounds +/- 30min.
func (h *IncidentAIHandler) executeToolCall(
	ctx context.Context,
	call provider.ToolCall,
	detail *incident.IncidentDetail,
) (string, error) {
	tool, ok := h.toolRegistry[call.Name]
	if !ok {
		return fmt.Sprintf(`{"error":"unknown tool %q"}`, call.Name), nil
	}

	// Intelligence tools use their own parameter parsing (no time clamping needed).
	var params tools.Params
	if tools.IntelligenceToolNames[call.Name] {
		params = tools.ParseIntelligenceArgs(call.Name, []byte(call.Arguments), detail.OrgID, detail.HostID)
	} else {
		// Parse arguments from JSON.
		var rawArgs struct {
			HostID       string `json:"host_id"`
			Since        string `json:"since"`
			Until        string `json:"until"`
			Pattern      string `json:"pattern"`
			PID          int64  `json:"pid"`
			BaseSince    string `json:"base_since"`
			BaseUntil    string `json:"base_until"`
			CompareSince string `json:"compare_since"`
			CompareUntil string `json:"compare_until"`
		}
		if err := json.Unmarshal([]byte(call.Arguments), &rawArgs); err != nil {
			return fmt.Sprintf(`{"error":"invalid tool arguments: %s"}`, err.Error()), nil
		}

		// Security: force host_id to the incident's host — AI must not query other hosts.
		params = tools.Params{
			OrgID:   detail.OrgID,
			HostID:  detail.HostID,
			Pattern: rawArgs.Pattern,
			PID:     rawArgs.PID,
		}

		// Time bounding: clamp to incident window +/- 30min.
		windowPad := 30 * time.Minute
		minTime := detail.StartedAt.Add(-windowPad)
		maxTime := detail.EndedAt.Add(windowPad)
		// If EndedAt is zero (ongoing incident), use now + 30min.
		if detail.EndedAt.IsZero() {
			maxTime = time.Now().Add(windowPad)
		}

		params.Since = clampTime(parseTimeOrDefault(rawArgs.Since, minTime), minTime, maxTime)
		params.Until = clampTime(parseTimeOrDefault(rawArgs.Until, maxTime), minTime, maxTime)
		params.BaseSince = clampTime(parseTimeOrDefault(rawArgs.BaseSince, minTime), minTime, maxTime)
		params.BaseUntil = clampTime(parseTimeOrDefault(rawArgs.BaseUntil, maxTime), minTime, maxTime)
		params.CompareSince = clampTime(parseTimeOrDefault(rawArgs.CompareSince, minTime), minTime, maxTime)
		params.CompareUntil = clampTime(parseTimeOrDefault(rawArgs.CompareUntil, maxTime), minTime, maxTime)
	}

	result, err := tool.Handler(ctx, h.queryService, h.graphStore, params)
	if err != nil {
		return fmt.Sprintf(`{"error":%q}`, err.Error()), nil
	}

	resultJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Sprintf(`{"error":"failed to marshal tool result: %s"}`, err.Error()), nil
	}

	// Cap result size to avoid blowing up context window.
	const maxResultBytes = 32 * 1024 // 32KB
	if len(resultJSON) > maxResultBytes {
		return string(resultJSON[:maxResultBytes]) + `..."truncated"}`, nil
	}

	return string(resultJSON), nil
}

// parseTimeOrDefault parses an RFC3339 string, returning def if empty or invalid.
func parseTimeOrDefault(s string, def time.Time) time.Time {
	if s == "" {
		return def
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return def
	}
	return t
}

// clampTime restricts t to [min, max].
func clampTime(t, min, max time.Time) time.Time {
	if t.Before(min) {
		return min
	}
	if t.After(max) {
		return max
	}
	return t
}

// ExplainIncident generates an AI explanation for a full incident.
// POST /api/v1/incidents/{id}/explain
func (h *IncidentAIHandler) ExplainIncident(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	incidentID := extractIncidentIDForAI(r.URL.Path, "/explain")
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	detailLevel := r.URL.Query().Get("detail_level")
	if detailLevel == "" {
		detailLevel = "standard"
	}

	// Check cache first (skip for deep mode — always fresh).
	if detailLevel != "deep" {
		if cached, err := h.summaryStore.GetSummary(orgID, incidentID); err == nil && cached != nil {
			reasoning, cleanContent := parseReasoning(cached.Summary)
			riskScore, riskJustification := parseRiskScore(cleanContent)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"content":            cleanContent,
				"reasoning":          reasoning,
				"model":              cached.Model,
				"cached":             true,
				"risk_score":         riskScore,
				"risk_justification": riskJustification,
				"tokens": map[string]int{
					"input":  cached.InputTokens,
					"output": cached.OutputTokens,
				},
			})
			return
		}
	}

	// Get LLM provider.
	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		log.Printf("ERROR: get provider failed: %v", err)
		Internal(w)
		return
	}
	if llmProvider == nil {
		BadRequest(w, "no LLM provider configured — add an API key in Settings")
		return
	}

	// Try pre-built dossier first (fast path).
	dossierText := ""
	if h.dossierStore != nil {
		if text, _, dErr := h.dossierStore.GetText(r.Context(), orgID, incidentID); dErr == nil && text != "" {
			dossierText = text
		}
	}

	// Fall back to on-demand assembly.
	if dossierText == "" {
		detail, err := h.assembler.Assemble(r.Context(), orgID, incidentID)
		if err != nil {
			if errors.Is(err, incident.ErrIncidentNotFound) {
				NotFound(w, "incident not found")
				return
			}
			log.Printf("ERROR: assemble incident %s failed: %v", incidentID, err)
			Internal(w)
			return
		}
		data := &dossier.DossierData{Detail: detail, BuiltAt: time.Now()}
		dossierText = dossier.FormatDossier(data)
	}

	// Build on-demand micro-context so the AI has temporal context even if
	// the background worker's 1-min context windows haven't been built yet.
	// Two windows: 5-min (immediate surroundings) + 30-min (session behavior).
	// Formatted as readable text (not raw JSON) for better LLM reasoning.
	microContext := ""
	if h.intStore != nil {
		hostID := ""
		if detail, aErr := h.assembler.Assemble(r.Context(), orgID, incidentID); aErr == nil && detail != nil {
			hostID = detail.Incident.HostID
		}
		if hostID != "" {
			if mc5, err5 := h.intStore.GetOnDemandContext(r.Context(), hostID, time.Now().Add(-5*time.Minute)); err5 == nil && mc5 != nil {
				microContext += "\n\nRECENT ACTIVITY (last 5 minutes):\n" + formatMicroContext(mc5)
			}
			if mc30, err30 := h.intStore.GetOnDemandContext(r.Context(), hostID, time.Now().Add(-30*time.Minute)); err30 == nil && mc30 != nil {
				microContext += "\n\nSESSION CONTEXT (last 30 minutes):\n" + formatMicroContext(mc30)
			}
		}
	}

	systemPrompt := provider.IncidentExplainPrompt(dossierText + microContext)
	resp, err := llmProvider.Chat(r.Context(), &provider.ChatRequest{
		Messages: []provider.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: "Analyze this incident. Follow the mandatory response format exactly."},
		},
	})
	if err != nil {
		log.Printf("ERROR: LLM explain incident failed: %v", err)
		writeError(w, http.StatusBadGateway, "llm_error", "LLM request failed: "+err.Error())
		return
	}

	reasoning, cleanContent := parseReasoning(resp.Content)

	// Cache the summary without the reasoning block (keeps cache compact).
	if detailLevel != "deep" {
		if saveErr := h.summaryStore.SaveSummary(orgID, incidentID, cleanContent, resp.Model, resp.InputTokens, resp.OutputTokens); saveErr != nil {
			log.Printf("WARN: failed to cache summary for incident %s: %v", incidentID, saveErr)
		}
	}

	riskScore, riskJustification := parseRiskScore(cleanContent)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"content":            cleanContent,
		"reasoning":          reasoning,
		"model":              resp.Model,
		"cached":             false,
		"risk_score":         riskScore,
		"risk_justification": riskJustification,
		"tokens": map[string]int{
			"input":  resp.InputTokens,
			"output": resp.OutputTokens,
		},
	})
}

// AskAboutIncident answers a user question about an incident.
// POST /api/v1/incidents/{id}/ask
func (h *IncidentAIHandler) AskAboutIncident(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	incidentID := extractIncidentIDForAI(r.URL.Path, "/ask")
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid request body")
		return
	}
	if body.Message == "" {
		BadRequest(w, "message required")
		return
	}

	// Get LLM provider.
	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		log.Printf("ERROR: get provider failed: %v", err)
		Internal(w)
		return
	}
	if llmProvider == nil {
		BadRequest(w, "no LLM provider configured — add an API key in Settings")
		return
	}

	// Assemble full incident detail.
	detail, err := h.assembler.Assemble(r.Context(), orgID, incidentID)
	if err != nil {
		if errors.Is(err, incident.ErrIncidentNotFound) {
			NotFound(w, "incident not found")
			return
		}
		log.Printf("ERROR: assemble incident %s failed: %v", incidentID, err)
		Internal(w)
		return
	}

	detailLevel := r.URL.Query().Get("detail_level")
	if detailLevel == "" {
		detailLevel = "standard"
	}
	detailJSON := buildLLMPayloadWithLevel(detail, detailLevel)

	systemPrompt := provider.IncidentAskSystemPrompt(detailJSON)
	resp, err := llmProvider.Chat(r.Context(), &provider.ChatRequest{
		Messages: []provider.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: body.Message},
		},
	})
	if err != nil {
		log.Printf("ERROR: LLM ask about incident failed: %v", err)
		writeError(w, http.StatusBadGateway, "llm_error", "LLM request failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"content": resp.Content,
		"model":   resp.Model,
		"tokens": map[string]int{
			"input":  resp.InputTokens,
			"output": resp.OutputTokens,
		},
	})
}

// StreamAskAboutIncident streams an AI response about an incident via SSE.
// POST /api/v1/incidents/{id}/ask/stream
func (h *IncidentAIHandler) StreamAskAboutIncident(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract ID: /api/v1/incidents/{id}/ask/stream
	path := strings.TrimSuffix(r.URL.Path, "/stream")
	incidentID := extractIncidentIDForAI(path, "/ask")
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	var body struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		BadRequest(w, "invalid request body")
		return
	}
	if body.Message == "" {
		BadRequest(w, "message required")
		return
	}

	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		log.Printf("ERROR: get provider failed: %v", err)
		Internal(w)
		return
	}
	if llmProvider == nil {
		BadRequest(w, "no LLM provider configured — add an API key in Settings")
		return
	}

	detail, err := h.assembler.Assemble(r.Context(), orgID, incidentID)
	if err != nil {
		if errors.Is(err, incident.ErrIncidentNotFound) {
			NotFound(w, "incident not found")
			return
		}
		log.Printf("ERROR: assemble incident %s failed: %v", incidentID, err)
		Internal(w)
		return
	}

	detailLevel := r.URL.Query().Get("detail_level")
	if detailLevel == "" {
		detailLevel = "standard"
	}
	detailJSON := buildLLMPayloadWithLevel(detail, detailLevel)
	systemPrompt := provider.IncidentAskSystemPrompt(detailJSON)
	chatReq := &provider.ChatRequest{
		Messages: []provider.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: body.Message},
		},
	}

	// Try streaming if provider supports it.
	streamingProvider, canStream := llmProvider.(provider.StreamingProvider)
	if !canStream {
		// Provider doesn't support streaming — try SSE with a single delta, else fall back to JSON.
		sse := NewSSEWriter(w)
		if sse == nil {
			// ResponseWriter doesn't support flushing — return a plain JSON response.
			resp, err := llmProvider.Chat(r.Context(), chatReq)
			if err != nil {
				log.Printf("ERROR: LLM chat failed: %v", err)
				Internal(w)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"content": resp.Content,
				"model":   resp.Model,
				"tokens": map[string]int{
					"input":  resp.InputTokens,
					"output": resp.OutputTokens,
				},
			})
			return
		}

		resp, err := llmProvider.Chat(r.Context(), chatReq)
		if err != nil {
			sse.WriteError("LLM request failed: " + err.Error())
			return
		}
		sse.WriteDelta(resp.Content)
		sse.WriteDone(resp.Model, resp.InputTokens, resp.OutputTokens)
		return
	}

	// Stream the response.
	sse := NewSSEWriter(w)
	if sse == nil {
		// Fallback: non-streaming JSON response.
		resp, err := streamingProvider.Chat(r.Context(), chatReq)
		if err != nil {
			log.Printf("ERROR: LLM chat failed: %v", err)
			Internal(w)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content": resp.Content,
			"model":   resp.Model,
			"tokens": map[string]int{
				"input":  resp.InputTokens,
				"output": resp.OutputTokens,
			},
		})
		return
	}

	resp, err := streamingProvider.StreamChat(r.Context(), chatReq, func(delta string) {
		sse.WriteDelta(delta)
	})
	if err != nil {
		sse.WriteError("LLM request failed: " + err.Error())
		return
	}
	sse.WriteDone(resp.Model, resp.InputTokens, resp.OutputTokens)
}

// ExplainFinding generates an AI explanation for a single finding.
// POST /api/v1/findings/{id}/explain
func (h *IncidentAIHandler) ExplainFinding(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	findingID := extractFindingIDForAI(r.URL.Path)
	if findingID == "" {
		BadRequest(w, "finding ID required")
		return
	}

	// Get LLM provider.
	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		log.Printf("ERROR: get provider failed: %v", err)
		Internal(w)
		return
	}
	if llmProvider == nil {
		BadRequest(w, "no LLM provider configured — add an API key in Settings")
		return
	}

	// Load finding.
	finding, err := h.findingStore.GetByID(orgID, findingID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			NotFound(w, "finding not found")
			return
		}
		log.Printf("ERROR: get finding %s failed: %v", findingID, err)
		Internal(w)
		return
	}

	findingJSON, err := json.Marshal(finding)
	if err != nil {
		log.Printf("ERROR: marshal finding failed: %v", err)
		Internal(w)
		return
	}

	systemPrompt := provider.FindingExplainSystemPrompt(string(findingJSON))
	resp, err := llmProvider.Chat(r.Context(), &provider.ChatRequest{
		Messages: []provider.Message{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: "Explain this security finding."},
		},
		MaxTokens: 1024,
	})
	if err != nil {
		log.Printf("ERROR: LLM explain finding failed: %v", err)
		writeError(w, http.StatusBadGateway, "llm_error", "LLM request failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"content": resp.Content,
		"model":   resp.Model,
		"tokens": map[string]int{
			"input":  resp.InputTokens,
			"output": resp.OutputTokens,
		},
	})
}

// ChatAboutIncident is the new threaded chat endpoint with dossier context.
// POST /api/v1/incidents/{id}/chat
func (h *IncidentAIHandler) ChatAboutIncident(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	incidentID := extractIncidentIDForAI(r.URL.Path, "/chat")
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	var body struct {
		Message  string `json:"message"`
		ThreadID string `json:"thread_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Message == "" {
		BadRequest(w, "message required")
		return
	}

	// Get LLM provider.
	llmProvider, err := h.getProvider(r.Context(), orgID)
	if err != nil {
		log.Printf("ERROR: get provider failed: %v", err)
		Internal(w)
		return
	}
	if llmProvider == nil {
		BadRequest(w, "no LLM provider configured — add an API key in Settings")
		return
	}

	// Always assemble incident detail — needed for tool security bounding (HostID, time window).
	detail, assembleErr := h.assembler.Assemble(r.Context(), orgID, incidentID)
	if assembleErr != nil {
		if errors.Is(assembleErr, incident.ErrIncidentNotFound) {
			NotFound(w, "incident not found")
			return
		}
		log.Printf("ERROR: assemble incident %s: %v", incidentID, assembleErr)
		Internal(w)
		return
	}

	// Load or build dossier.
	dossierText := ""
	if h.dossierStore != nil {
		if text, _, dErr := h.dossierStore.GetText(r.Context(), orgID, incidentID); dErr == nil && text != "" {
			dossierText = text
		}
	}
	if dossierText == "" {
		// Build on-demand (rare — proactive summarizer should have pre-built it).
		buildCtx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		if h.dossierBuilder != nil {
			if data, bErr := h.dossierBuilder.Build(buildCtx, orgID, incidentID); bErr == nil {
				dossierText = dossier.FormatDossier(data)
				if h.dossierStore != nil {
					_ = h.dossierStore.Save(r.Context(), orgID, incidentID, dossierText)
				}
			}
		}
	}
	if dossierText == "" {
		// Use the already-assembled detail.
		data := &dossier.DossierData{Detail: detail, BuiltAt: time.Now()}
		dossierText = dossier.FormatDossier(data)
	}

	// Get or create conversation thread.
	threadID := ""
	if h.convStore != nil {
		tid, tErr := h.convStore.GetOrCreateThread(r.Context(), orgID, incidentID, body.ThreadID)
		if tErr != nil {
			log.Printf("WARN: get/create thread: %v", tErr)
		} else {
			threadID = tid
		}
	}

	// Load thread history (last 20 turns).
	var history []conversation.Message
	if h.convStore != nil && threadID != "" {
		history, _ = h.convStore.GetHistory(r.Context(), threadID, orgID, 20)
	}

	// Build messages: system prompt + history turns + new user message.
	systemPrompt := provider.DossierChatSystemPrompt(dossierText)
	messages := []provider.Message{{Role: "system", Content: systemPrompt}}
	for _, msg := range history {
		messages = append(messages, provider.Message{Role: msg.Role, Content: msg.Content})
	}
	messages = append(messages, provider.Message{Role: "user", Content: body.Message})

	chatReq := &provider.ChatRequest{Messages: messages}

	// Add tool definitions if tool-calling is available.
	toolDefs := h.buildToolDefinitions()
	if len(toolDefs) > 0 {
		chatReq.Tools = toolDefs
		chatReq.ToolChoice = "auto"
	}

	// Set up SSE writer.
	sse := NewSSEWriter(w)

	// Emit thread_id as first SSE event so client can persist it.
	if sse != nil && threadID != "" {
		data, _ := json.Marshal(map[string]any{"type": "thread_id", "thread_id": threadID})
		fmt.Fprintf(w, "data: %s\n\n", string(data))
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}

	// Stream or non-stream.
	var finalResp *provider.ChatResponse
	streamProv, canStream := llmProvider.(provider.StreamingProvider)

	if sse == nil {
		// Non-SSE fallback: plain JSON with tool-calling loop.
		resp, chatErr := h.chatWithToolLoop(r.Context(), llmProvider, chatReq, detail)
		if chatErr != nil {
			writeError(w, http.StatusBadGateway, "llm_error", chatErr.Error())
			return
		}
		finalResp = resp
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"content":   resp.Content,
			"model":     resp.Model,
			"thread_id": threadID,
			"tokens":    map[string]int{"input": resp.InputTokens, "output": resp.OutputTokens},
		})
	} else if canStream {
		// Streaming: skip tool-use for now (streaming + tool-use is complex).
		// Remove tools from the request to avoid partial tool call chunks.
		streamReq := &provider.ChatRequest{Messages: chatReq.Messages}
		resp, chatErr := streamProv.StreamChat(r.Context(), streamReq, func(delta string) {
			sse.WriteDelta(delta)
		})
		if chatErr != nil {
			sse.WriteError("LLM request failed: " + chatErr.Error())
			return
		}
		finalResp = resp
		sse.WriteDone(resp.Model, resp.InputTokens, resp.OutputTokens)
	} else {
		// Non-streaming provider with SSE wrapper: use tool-calling loop.
		resp, chatErr := h.chatWithToolLoop(r.Context(), llmProvider, chatReq, detail)
		if chatErr != nil {
			sse.WriteError("LLM request failed: " + chatErr.Error())
			return
		}
		finalResp = resp
		sse.WriteDelta(resp.Content)
		sse.WriteDone(resp.Model, resp.InputTokens, resp.OutputTokens)
	}

	// Save to thread.
	if h.convStore != nil && threadID != "" && finalResp != nil {
		userTokens := len(body.Message) / 4
		_ = h.convStore.AppendMessage(r.Context(), threadID, orgID, "user", body.Message, userTokens)
		assistantTokens := finalResp.OutputTokens
		if assistantTokens == 0 {
			assistantTokens = len(finalResp.Content) / 4
		}
		_ = h.convStore.AppendMessage(r.Context(), threadID, orgID, "assistant", finalResp.Content, assistantTokens)
		_ = h.convStore.Touch(r.Context(), threadID)
	}
}

// chatWithToolLoop executes the LLM chat with a tool-calling loop.
// If the LLM requests tool calls, it executes them and feeds results back,
// looping up to maxToolIterations times until the LLM produces a final text response.
func (h *IncidentAIHandler) chatWithToolLoop(
	ctx context.Context,
	llm provider.Provider,
	req *provider.ChatRequest,
	detail *incident.IncidentDetail,
) (*provider.ChatResponse, error) {
	// If no tools are configured, just do a single call.
	if h.toolRegistry == nil || len(req.Tools) == 0 {
		return llm.Chat(ctx, req)
	}

	// Copy messages so we don't mutate the original slice.
	messages := make([]provider.Message, len(req.Messages))
	copy(messages, req.Messages)

	var lastResp *provider.ChatResponse
	totalInputTokens := 0
	totalOutputTokens := 0

	for i := 0; i < maxToolIterations; i++ {
		iterReq := &provider.ChatRequest{
			Messages:    messages,
			MaxTokens:   req.MaxTokens,
			Temperature: req.Temperature,
			Model:       req.Model,
			Tools:       req.Tools,
			ToolChoice:  req.ToolChoice,
		}

		resp, err := llm.Chat(ctx, iterReq)
		if err != nil {
			return nil, err
		}

		totalInputTokens += resp.InputTokens
		totalOutputTokens += resp.OutputTokens
		lastResp = resp

		// If no tool calls, the LLM is done — return the final response.
		if len(resp.ToolCalls) == 0 {
			resp.InputTokens = totalInputTokens
			resp.OutputTokens = totalOutputTokens
			return resp, nil
		}

		// Append the assistant message with tool calls (content may be empty).
		messages = append(messages, provider.Message{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		})

		// Execute each tool call and append results as tool messages.
		for _, tc := range resp.ToolCalls {
			log.Printf("tool call: %s (id=%s)", tc.Name, tc.ID)
			result, execErr := h.executeToolCall(ctx, tc, detail)
			if execErr != nil {
				result = fmt.Sprintf(`{"error":%q}`, execErr.Error())
			}
			messages = append(messages, provider.Message{
				Role:       "tool",
				Content:    result,
				ToolCallID: tc.ID,
			})
		}
	}

	// Max iterations reached — return whatever we have.
	if lastResp != nil {
		lastResp.InputTokens = totalInputTokens
		lastResp.OutputTokens = totalOutputTokens
		// If the last response was a tool call with no content, make a final call without tools
		// to force the LLM to produce a text summary.
		if lastResp.Content == "" && len(lastResp.ToolCalls) > 0 {
			finalReq := &provider.ChatRequest{
				Messages:    messages,
				MaxTokens:   req.MaxTokens,
				Temperature: req.Temperature,
				Model:       req.Model,
				// No tools — force text output.
			}
			finalResp, err := llm.Chat(ctx, finalReq)
			if err != nil {
				return lastResp, nil // Return what we have rather than error.
			}
			finalResp.InputTokens = totalInputTokens + finalResp.InputTokens
			finalResp.OutputTokens = totalOutputTokens + finalResp.OutputTokens
			return finalResp, nil
		}
		return lastResp, nil
	}

	return nil, fmt.Errorf("tool loop completed with no response")
}

// GetChatHistory returns the message history for a conversation thread.
// GET /api/v1/incidents/{id}/chat/history?thread_id=xxx
func (h *IncidentAIHandler) GetChatHistory(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	incidentID := extractIncidentIDForAI(r.URL.Path, "/chat/history")
	if incidentID == "" {
		BadRequest(w, "incident ID required")
		return
	}

	threadID := r.URL.Query().Get("thread_id")
	if threadID == "" {
		BadRequest(w, "thread_id required")
		return
	}

	if h.convStore == nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]any{})
		return
	}

	history, err := h.convStore.GetHistory(r.Context(), threadID, orgID, 0)
	if err != nil {
		Internal(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(history)
}

// DeleteChatThread deletes a conversation thread.
// DELETE /api/v1/incidents/{id}/chat/thread/{thread_id}
func (h *IncidentAIHandler) DeleteChatThread(w http.ResponseWriter, r *http.Request) {
	orgID, ok := middleware.OrgFromContext(r.Context())
	if !ok {
		Unauthorized(w, "missing org context")
		return
	}

	// Extract thread_id from path: /api/v1/incidents/{id}/chat/thread/{thread_id}
	path := r.URL.Path
	const threadPrefix = "/chat/thread/"
	idx := strings.LastIndex(path, threadPrefix)
	if idx < 0 {
		BadRequest(w, "thread_id required in path")
		return
	}
	threadID := strings.TrimSuffix(path[idx+len(threadPrefix):], "/")
	if threadID == "" {
		BadRequest(w, "thread_id required in path")
		return
	}

	if h.convStore == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if err := h.convStore.DeleteThread(r.Context(), threadID, orgID); err != nil {
		log.Printf("WARN: delete thread %s: %v", threadID, err)
		Internal(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// getProvider creates an LLM provider for the given org.
// Bridges the string orgID used throughout the codebase to uuid.UUID used by SettingsStore.
func (h *IncidentAIHandler) getProvider(ctx context.Context, orgIDStr string) (provider.Provider, error) {
	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		return nil, fmt.Errorf("invalid org ID %q: %w", orgIDStr, err)
	}

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

// parseReasoning extracts the <reasoning>...</reasoning> block from LLM content.
// Returns the reasoning text and the content with the block removed and trimmed.
func parseReasoning(content string) (reasoning, cleanContent string) {
	start := strings.Index(content, "<reasoning>")
	end := strings.Index(content, "</reasoning>")
	if start == -1 || end == -1 || end <= start {
		return "", content
	}
	reasoning = strings.TrimSpace(content[start+len("<reasoning>") : end])
	cleanContent = strings.TrimSpace(content[:start] + content[end+len("</reasoning>"):])
	return reasoning, cleanContent
}

// parseRiskScore extracts the risk score and justification from the LLM response.
// Looks for "### Risk Score: X/10" or "## Risk Score: X/10" in the content.
var riskScoreRe = regexp.MustCompile(`(?m)^#{2,3}\s*Risk\s+Score:\s*(\d{1,2})\s*/\s*10`)

func parseRiskScore(content string) (int, string) {
	matches := riskScoreRe.FindStringSubmatchIndex(content)
	if matches == nil {
		return 0, ""
	}

	scoreStr := content[matches[2]:matches[3]]
	score, err := strconv.Atoi(scoreStr)
	if err != nil || score < 1 {
		return 0, ""
	}
	if score > 10 {
		score = 10
	}

	// Extract justification: text after the header line until the next ## or ### header.
	afterHeader := content[matches[1]:]
	afterHeader = strings.TrimLeft(afterHeader, " \t\r\n")

	// Find the next section header.
	nextHeader := regexp.MustCompile(`(?m)^#{2,3}\s+\S`)
	nextIdx := nextHeader.FindStringIndex(afterHeader)
	justification := afterHeader
	if nextIdx != nil {
		justification = afterHeader[:nextIdx[0]]
	}
	justification = strings.TrimSpace(justification)

	// Cap justification length for JSON response.
	if len(justification) > 500 {
		justification = justification[:500] + "..."
	}

	return score, justification
}

// buildLLMPayloadWithLevel creates a token-optimized JSON representation
// using either standard or deep caps. See llm_payload.go for implementation.
func buildLLMPayloadWithLevel(detail *incident.IncidentDetail, level string) string {
	if level == "deep" {
		return buildLLMPayloadDeep(detail)
	}
	return buildLLMPayload(detail)
}

// extractIncidentIDForAI extracts the incident ID from paths like /api/v1/incidents/{id}/explain
func extractIncidentIDForAI(path, suffix string) string {
	path = strings.TrimSuffix(path, suffix)
	const prefix = "/api/v1/incidents/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := path[len(prefix):]
	id = strings.TrimSuffix(id, "/")
	return id
}

// extractFindingIDForAI extracts the finding ID from paths like /api/v1/findings/{id}/explain
// The ID may be URL-encoded due to slashes in finding IDs (e.g. ai.unauthorized_exec:uuid:/usr/bin/ssh)
func extractFindingIDForAI(path string) string {
	path = strings.TrimSuffix(path, "/explain")
	const prefix = "/api/v1/findings/"
	if !strings.HasPrefix(path, prefix) {
		return ""
	}
	id := path[len(prefix):]
	id = strings.TrimSuffix(id, "/")
	if decoded, err := url.PathUnescape(id); err == nil {
		id = decoded
	}
	return id
}

// formatMicroContext converts a ContextSummary into human-readable text
// instead of raw JSON. This is ~30% fewer tokens and easier for the LLM to reason about.
func formatMicroContext(mc *intelligence.ContextSummary) string {
	if mc == nil {
		return "  No data available.\n"
	}

	var sb strings.Builder

	// Activity pattern
	if mc.ActivityPattern != "" {
		sb.WriteString(fmt.Sprintf("  Activity: %s\n", mc.ActivityPattern))
	}

	// Process summary
	if mc.ProcessExecCount > 0 {
		binList := strings.Join(mc.UniqueBinaries, ", ")
		if binList == "" {
			binList = "unknown"
		}
		sb.WriteString(fmt.Sprintf("  Processes: %d executions (%s)\n", mc.ProcessExecCount, binList))
	} else {
		sb.WriteString("  Processes: 0 executions\n")
	}

	// File summary
	if mc.FileOpenCount > 0 {
		sb.WriteString(fmt.Sprintf("  Files: %d opens", mc.FileOpenCount))
		if mc.FileExistsCount > 0 || mc.FileNotFoundCount > 0 {
			sb.WriteString(fmt.Sprintf(" (%d exist, %d not-found)", mc.FileExistsCount, mc.FileNotFoundCount))
		}
		sb.WriteString("\n")
	}

	// Network
	if mc.NetConnectCount > 0 {
		sb.WriteString(fmt.Sprintf("  Network: %d connections\n", mc.NetConnectCount))
	}

	// DNS
	if mc.DNSQueryCount > 0 {
		sb.WriteString(fmt.Sprintf("  DNS: %d queries\n", mc.DNSQueryCount))
	}

	// Findings
	if mc.FindingsGenerated > 0 {
		sb.WriteString(fmt.Sprintf("  Findings: %d generated, %d suppressed\n", mc.FindingsGenerated, mc.FindingsSuppressed))
	}

	// Credential accesses
	if mc.CredentialAccesses > 0 {
		sb.WriteString(fmt.Sprintf("  Credential accesses: %d\n", mc.CredentialAccesses))
	}

	// Sensitive files
	if len(mc.SensitiveFiles) > 0 {
		sb.WriteString(fmt.Sprintf("  Sensitive files touched: %s\n", strings.Join(mc.SensitiveFiles, ", ")))
	}

	return sb.String()
}
