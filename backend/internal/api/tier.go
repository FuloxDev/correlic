package api

import (
	"encoding/json"
	"net/http"

	"github.com/correlic/correlic-backend/internal/tier"
)

// TierHandler exposes current tier + limits for UI gating.
type TierHandler struct{}

func NewTierHandler() *TierHandler { return &TierHandler{} }

func (h *TierHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		MethodNotAllowed(w, http.MethodGet)
		return
	}
	t := tier.Current()
	out := map[string]any{
		"tier":   string(t),
		"limits": tier.LimitsFor(t),
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
