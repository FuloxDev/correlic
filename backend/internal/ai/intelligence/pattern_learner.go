package intelligence

import (
	"context"
	"log"
	"path/filepath"
	"strings"
	"time"
)

type PatternLearner struct {
	store *Store
}

func NewPatternLearner(store *Store) *PatternLearner {
	return &PatternLearner{store: store}
}

// RecordFindingAction updates the learned pattern when a user takes action on a finding.
// Called in real-time from the findings handler when status changes.
func (l *PatternLearner) RecordFindingAction(ctx context.Context, orgID string, findingContext map[string]any, action string) {
	patternKey := extractPatternKey(findingContext)
	if patternKey == "" {
		return
	}

	// Get or create the pattern
	existing, err := l.store.GetPattern(ctx, orgID, patternKey)
	if err != nil {
		log.Printf("WARN: pattern learner get failed: %v", err)
		return
	}

	now := time.Now()
	var pattern LearnedPattern
	if existing != nil {
		pattern = *existing
	} else {
		pattern = LearnedPattern{
			PatternKey: patternKey,
			Evidence:   Evidence{},
			FirstSeen:  now,
		}
	}
	pattern.LastSeen = now

	// Update evidence based on action
	switch action {
	case "dismissed":
		pattern.Evidence.Dismissed++
	case "allowed", "auto_resolved":
		pattern.Evidence.Allowed++
	case "investigating":
		pattern.Evidence.Investigated++
	case "blocked":
		pattern.Evidence.Blocked++
	}
	pattern.Evidence.TotalSeen++

	// Calculate verdict and confidence
	pattern.Verdict, pattern.Confidence = calculateVerdict(pattern.Evidence)

	if err := l.store.UpsertPattern(ctx, orgID, pattern); err != nil {
		log.Printf("WARN: pattern learner upsert failed for %s: %v", patternKey, err)
	} else {
		log.Printf("AI learned pattern updated: %s → %s (%.0f%% confidence, seen %d times)",
			patternKey, pattern.Verdict, pattern.Confidence*100, pattern.Evidence.TotalSeen)
	}
}

// extractPatternKey creates a unique key from finding context.
// Format: "signal_type:ai_type:binary_or_pattern:context_hint"
func extractPatternKey(ctx map[string]any) string {
	signalType, _ := ctx["signal_type"].(string)
	aiType, _ := ctx["ai_type"].(string)
	binary, _ := ctx["binary"].(string)
	pattern, _ := ctx["pattern"].(string)
	filePath, _ := ctx["file_path"].(string)
	domain, _ := ctx["domain"].(string)
	lowContext, _ := ctx["low_context"].(bool)

	if signalType == "" {
		return ""
	}

	var parts []string
	parts = append(parts, signalType)

	if aiType != "" {
		parts = append(parts, aiType)
	} else {
		parts = append(parts, "any")
	}

	// Use the most specific identifier available
	switch {
	case binary != "":
		base := filepath.Base(binary)
		parts = append(parts, strings.ToLower(base))
	case filePath != "":
		// Use directory + filename for file patterns
		dir := filepath.Dir(filePath)
		base := filepath.Base(filePath)
		parts = append(parts, strings.ToLower(filepath.Base(dir)+"/"+base))
	case domain != "":
		parts = append(parts, strings.ToLower(domain))
	case pattern != "":
		// Truncate long patterns
		p := pattern
		if len(p) > 50 {
			p = p[:50]
		}
		parts = append(parts, strings.ToLower(p))
	default:
		return "" // can't create a meaningful key
	}

	// Add context hint for disambiguation
	if lowContext {
		parts = append(parts, "low_context")
	}

	return strings.Join(parts, ":")
}

// calculateVerdict determines the verdict and confidence from accumulated evidence.
func calculateVerdict(e Evidence) (string, float64) {
	if e.TotalSeen == 0 {
		return "unknown", 0.5
	}

	// Block signal is strongest — even one block means suspicious
	if e.Blocked > 0 {
		return "always_malicious", 0.95
	}

	// Investigation signal is strong
	if e.Investigated > 0 {
		// Mix of investigated and dismissed
		investigateRatio := float64(e.Investigated) / float64(e.TotalSeen)
		if investigateRatio > 0.5 {
			return "suspicious", 0.7 + investigateRatio*0.2
		}
		// Mostly dismissed with a few investigations
		return "likely_benign", 0.6
	}

	// All dismissed or allowed — benign
	benignCount := e.Dismissed + e.Allowed
	if benignCount == e.TotalSeen {
		if e.TotalSeen >= 10 {
			return "always_benign", 0.99
		}
		if e.TotalSeen >= 5 {
			return "always_benign", 0.95
		}
		if e.TotalSeen >= 3 {
			return "likely_benign", 0.85
		}
		return "likely_benign", 0.7
	}

	// Mixed signals
	benignRatio := float64(benignCount) / float64(e.TotalSeen)
	if benignRatio > 0.8 {
		return "likely_benign", benignRatio
	}
	return "unknown", 0.5
}

// GetVerdictForFinding checks if a finding matches a known learned pattern.
// Returns the verdict and confidence, or ("unknown", 0.5) if not found.
func (l *PatternLearner) GetVerdictForFinding(ctx context.Context, orgID string, findingContext map[string]any) (string, float64) {
	patternKey := extractPatternKey(findingContext)
	if patternKey == "" {
		return "unknown", 0.5
	}

	pattern, err := l.store.GetPattern(ctx, orgID, patternKey)
	if err != nil || pattern == nil {
		return "unknown", 0.5
	}

	return pattern.Verdict, pattern.Confidence
}
