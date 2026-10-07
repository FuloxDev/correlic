package ai

import (
	"context"
	"log"
	"math/rand"
	"time"

	"github.com/correlic/correlic-backend/internal/ai/conversation"
	"github.com/correlic/correlic-backend/internal/ai/dossier"
)

// ProactiveSummarizer is a background goroutine that pre-builds dossiers for
// new incidents so that the first chat request is fast.
// It also purges stale conversation threads to keep the DB tidy.
type ProactiveSummarizer struct {
	dossierStore   *dossier.Store
	dossierBuilder *dossier.DossierBuilder
	convStore      *conversation.Store // optional — may be nil
	done           chan struct{}
	interval       time.Duration
}

// NewProactiveSummarizer creates a new ProactiveSummarizer.
func NewProactiveSummarizer(dossierStore *dossier.Store, dossierBuilder *dossier.DossierBuilder) *ProactiveSummarizer {
	return &ProactiveSummarizer{
		dossierStore:   dossierStore,
		dossierBuilder: dossierBuilder,
		done:           make(chan struct{}),
		interval:       2 * time.Minute,
	}
}

// SetConversationStore wires in the conversation store for thread purging.
// Must be called before Start() if thread purging is desired.
func (p *ProactiveSummarizer) SetConversationStore(cs *conversation.Store) {
	p.convStore = cs
}

// Start runs the summarizer loop. Should be called in a goroutine.
// Adds ±20s jitter to avoid thundering herd on multi-instance deployments.
func (p *ProactiveSummarizer) Start() {
	// Jitter: wait 0-20 seconds before first tick.
	jitter := time.Duration(rand.Intn(20)) * time.Second //nolint:gosec
	select {
	case <-p.done:
		return
	case <-time.After(jitter):
	}

	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ticker.C:
			p.runOnce()
		}
	}
}

// Stop signals the summarizer loop to exit.
func (p *ProactiveSummarizer) Stop() {
	close(p.done)
}

// runOnce performs one build-and-purge cycle.
func (p *ProactiveSummarizer) runOnce() {
	ctx := context.Background()

	// List incidents that need a dossier built.
	items, err := p.dossierStore.ListNeedingBuild(ctx, 5)
	if err != nil {
		log.Printf("WARN: proactive_summarizer list_needing_build: %v", err)
		return
	}

	for _, item := range items {
		// Check if we were stopped between items.
		select {
		case <-p.done:
			return
		default:
		}

		buildCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
		data, bErr := p.dossierBuilder.Build(buildCtx, item.OrgID, item.IncidentID)
		cancel()

		if bErr != nil {
			log.Printf("WARN: proactive_summarizer build %s: %v", item.IncidentID, bErr)
			continue
		}

		text := dossier.FormatDossier(data)
		if sErr := p.dossierStore.Save(ctx, item.OrgID, item.IncidentID, text); sErr != nil {
			log.Printf("WARN: proactive_summarizer save %s: %v", item.IncidentID, sErr)
			continue
		}

		log.Printf("proactive_summarizer: built dossier for incident %s (org %s)", item.IncidentID, item.OrgID)

		// Sleep briefly between builds to avoid hammering Neo4j.
		select {
		case <-p.done:
			return
		case <-time.After(3 * time.Second):
		}
	}

	// Purge stale conversation threads.
	if p.convStore != nil {
		if pErr := p.convStore.PurgeOldThreads(ctx); pErr != nil {
			log.Printf("WARN: proactive_summarizer purge_threads: %v", pErr)
		}
	}
}
