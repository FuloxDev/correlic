package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"expvar"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/correlic/correlic-backend/internal/ai"
	"github.com/correlic/correlic-backend/internal/ai/attribution"
	"github.com/correlic/correlic-backend/internal/ai/intelligence"
	"github.com/correlic/correlic-backend/internal/api"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/config"
	"github.com/correlic/correlic-backend/internal/correlation"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/detection/ai_pack"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/notification"
	"github.com/correlic/correlic-backend/internal/ingest"
	"github.com/correlic/correlic-backend/internal/maintenance"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
	"github.com/correlic/correlic-backend/internal/storage/neo4j"
	"github.com/correlic/correlic-backend/internal/telemetry"
)

// tlsConfigFromEnv reads the TLS_CERT_FILE, TLS_KEY_FILE, and MTLS_CA_FILE environment variables
func tlsConfigFromEnv() (enabled bool, certFile, keyFile string, cfg *tls.Config, err error) {
	certFile = os.Getenv("TLS_CERT_FILE")
	keyFile = os.Getenv("TLS_KEY_FILE")
	if certFile == "" && keyFile == "" {
		return false, "", "", nil, nil
	}
	if certFile == "" || keyFile == "" {
		return false, "", "", nil, fmt.Errorf("both TLS_CERT_FILE and TLS_KEY_FILE must be set")
	}

	cfg = &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if caFile := os.Getenv("MTLS_CA_FILE"); caFile != "" {
		pem, readErr := os.ReadFile(caFile)
		if readErr != nil {
			return false, "", "", nil, fmt.Errorf("read MTLS_CA_FILE: %w", readErr)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(pem); !ok {
			return false, "", "", nil, fmt.Errorf("parse MTLS_CA_FILE: no certs found")
		}
		cfg.ClientCAs = pool
		// Allow unauthenticated webhook traffic (GitHub cannot present a client cert),
		// while still verifying client certs if provided.
		// Agent endpoints remain mTLS-only via the RequireMTLS middleware guard.
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
	}

	return true, certFile, keyFile, cfg, nil
}

func main() {
	if err := config.LoadDotEnvIfPresent(".env"); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	dbURL := "postgres://correlic:correlic@localhost:5432/correlic"
	if env := os.Getenv("DATABASE_URL"); env != "" {
		dbURL = env
	}

	db, err := sql.Open("pgx", dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// storage wiring
	apiKeyStore := storage.NewPostgresAPIKeyStore(db)
	telemetryStore := storage.NewPostgresTelemetryStore(db)
	canonicalEventStore := eventstore.NewPostgresEventStore(db)
	agentCertStore := storage.NewPostgresAgentCertStore(db)
	clientCertStore := storage.NewPostgresClientCertStore(db)

	// Neo4j connection (optional - gracefully degrades if unavailable)
	var eventBuffer *correlation.EventBuffer
	var eventSampler *ingest.Sampler
	var processTreeWriter *correlation.ProcessTreeWriter
	neo4jURI := os.Getenv("NEO4J_URI")
	if neo4jURI == "" {
		neo4jURI = "bolt://localhost:7687"
	}
	neo4jUser := os.Getenv("NEO4J_USERNAME")
	if neo4jUser == "" {
		neo4jUser = "neo4j"
	}
	neo4jPass := os.Getenv("NEO4J_PASSWORD")
	if neo4jPass == "" {
		neo4jPass = "correlic123"
	}

	var neo4jClient *neo4j.Client
	if neo4jURI == "disabled" || neo4jURI == "none" {
		log.Println("Neo4j disabled by configuration — detection rules and graph features unavailable")
	} else {
		var err error
		neo4jClient, err = neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
		if err != nil {
			log.Printf("WARNING: Neo4j connection failed (graph persistence disabled): %v", err)
		} else {
			graphStore := neo4j.NewGraphStore(neo4jClient)
			if err := graphStore.InitializeSchema(context.Background()); err != nil {
				log.Printf("WARNING: Neo4j schema initialization failed: %v", err)
			} else {
				// Load AI patterns for labeling AI agent processes in the graph
				if err := graphStore.LoadAIPatterns(db); err != nil {
					log.Printf("WARNING: Failed to load AI patterns for graph: %v", err)
				} else {
					log.Println("AI agent patterns loaded for graph labeling")
				}
				graphPersister := neo4j.NewGraphPersister(graphStore)
				log.Println("Neo4j graph persistence enabled")

				// Streaming correlation: event buffer + worker
				bufferSize := 10000
				eventBuffer = correlation.NewEventBuffer(bufferSize)

				windowSize := 5 * time.Minute
				flushInterval := 30 * time.Second
				correlationWorker := correlation.NewWorker(eventBuffer, graphPersister, windowSize, flushInterval)

				// Start worker in background
				workerCtx, workerCancel := context.WithCancel(context.Background())
				defer workerCancel()
				correlationWorker.Start(workerCtx)

				log.Printf("Tier 2: Streaming correlation enabled (buffer: %d, window: %v, flush: %v)", bufferSize, windowSize, flushInterval)

				// Tier 1: Real-time process tree writer
				ptNeo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
				ptGraphStore := neo4j.NewGraphStore(ptNeo4jClient)
				if err := ptGraphStore.LoadAIPatterns(db); err != nil {
					log.Printf("WARNING: Failed to load AI patterns for ProcessTreeWriter: %v", err)
				}
				processTreeWriter = correlation.NewProcessTreeWriter(ptGraphStore)
				log.Println("Tier 1: Real-time process tree writer enabled")
			}
		}
	}

	// Event sampling: reduce load by intelligently filtering events
	samplingEnabled := os.Getenv("SAMPLING_ENABLED") != "false" // Enabled by default
	if samplingEnabled {
		samplingRules := ingest.DefaultSamplingRules()
		eventSampler = ingest.NewSampler(samplingRules)
		log.Println("Event sampling enabled (always-keep: process_exec, process_exit, container_start)")
	}

	// Common middleware chain for authenticated endpoints.
	// Order matters:
	// - rate limiter can reject quickly based on the provided key
	// - auth injects org_id and actor into the request context
	// - audit runs after auth so it can log org_id
	// - role guard runs after auth so it can check the actor
	limitPerMin := 300
	if os.Getenv("CORRELIC_DISABLE_RATE_LIMIT") == "1" || os.Getenv("CORRELIC_DISABLE_RATE_LIMIT") == "true" {
		limitPerMin = 0
	}
	if s := os.Getenv("CORRELIC_RATE_LIMIT_PER_MIN"); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			limitPerMin = n
		}
	}
	rateLimiter := middleware.NewRateLimiter(limitPerMin, time.Minute)
	auth := middleware.NewAuthMiddleware(apiKeyStore, clientCertStore, nil, db)
	mtlsFP := middleware.NewMTLSFingerprintMiddleware()

	// Wrap the handler with the middleware chain.
	wrapAuthed := func(h http.Handler) http.Handler {
		return rateLimiter.Wrap(
			middleware.RequireMTLS(mtlsFP.Wrap(auth.Wrap(middleware.Audit(h)))),
		)
	}

	// Phase 2: Detection engine + behavioral baseline
	detectionEngine := detection.NewEngine()
	detectionEngine.RegisterPack(ai_pack.NewAIPack())
	log.Printf("Detection engine enabled: %d rules registered", detectionEngine.RuleCount())

	var detectionQuerier detection.GraphQuerier
	if neo4jClient != nil {
		dqNeo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
		detectionQuerier = detection.NewNeo4jGraphQuerier(dqNeo4jClient)
		log.Println("Detection graph querier enabled (Neo4j)")
	}

	baselineCollector := detection.NewBaselineCollector(db)
	defer baselineCollector.Stop()
	findingStore := storage.NewFindingStore(db)
	safeDomainStore := storage.NewSafeDomainStore(db)
	ruleExceptionStore := storage.NewRuleExceptionStore(db)
	defer ruleExceptionStore.Stop()
	ruleSettingsStore := storage.NewRuleSettingsStore(db)
	defer ruleSettingsStore.Stop()
	neverBaselineStore := storage.NewNeverBaselineStore(db)
	defer neverBaselineStore.Stop()
	baselineCollector.SetNeverBaselineChecker(neverBaselineStore)
	cooldown := detection.NewFindingCooldown()
	defer cooldown.Stop()
	chainCorrelator := detection.NewChainCorrelator()
	defer chainCorrelator.Stop()

	log.Println("Behavioral baseline collector enabled")

	// Phase 4: Incident mapping
	incidentStore := incident.NewIncidentStore(db)
	incidentCorrelator := incident.NewIncidentCorrelator(incidentStore, findingStore)
	summaryStore := ai.NewIncidentSummaryStore(db)
	incidentCorrelator.SetSummaryInvalidator(summaryStore)
	log.Println("Incident mapping enabled")

	// Phase 6: Notification engine
	telNotifStore := notification.NewNotificationStore(db)
	telDeliveryStore := notification.NewDeliveryStore(db)
	telEndpointStore := notification.NewEndpointStore(db)
	telNotifManager := notification.NewManager(telNotifStore, telDeliveryStore, telEndpointStore)
	incidentCorrelator.SetNotificationEmitter(telNotifManager)
	telDeliveryWorker := notification.NewDeliveryWorker(telDeliveryStore, telEndpointStore)
	if telDeliveryWorker != nil {
		go telDeliveryWorker.Start()
		defer telDeliveryWorker.Stop()
	}
	log.Println("Notification engine enabled")

	// Register the handlers with the mux.
	attributionStore := attribution.NewPostgresStore(db)
	attributionService := attribution.NewService(attributionStore)
	mux.Handle("/health", api.HealthHandler(detectionQuerier != nil))
	mux.Handle("/readiness", api.ReadinessHandler(db))
	mux.Handle("/ingest/events", wrapAuthed(api.NewLiveIngestHandler(telemetryStore, canonicalEventStore, eventBuffer, eventSampler, attributionService, processTreeWriter, detectionEngine, baselineCollector, findingStore, detectionQuerier, safeDomainStore, ruleExceptionStore, ruleSettingsStore, cooldown, chainCorrelator, incidentCorrelator, telNotifManager, neverBaselineStore)))
	mux.Handle("/telemetry", wrapAuthed(telemetry.NewIngestHandler(telemetryStore, agentCertStore, attributionService)))
	mux.Handle("/telemetry/recent", wrapAuthed(telemetry.NewRecentHandler(telemetryStore)))

	// Agent block rule sync + block event reporting
	blockRuleStore := storage.NewBlockRuleStore(db)
	defer blockRuleStore.Stop()
	blockEventStore := storage.NewBlockEventStore(db)
	agentBlockRulesHandler := api.NewAgentBlockRulesHandler(blockRuleStore)
	mux.Handle("/agent/block-rules", wrapAuthed(http.HandlerFunc(agentBlockRulesHandler.GetBlockRules)))
	blockEventsHandler := api.NewBlockEventsHandler(blockEventStore, blockRuleStore)
	mux.Handle("/agent/block-events", wrapAuthed(http.HandlerFunc(blockEventsHandler.ReportBlockEvents)))

	// AI Intelligence worker — builds context windows, system profiles, and rollups
	intelligenceWorker := intelligence.NewWorker(db)
	defer intelligenceWorker.Stop()
	go intelligenceWorker.Start()

	// Query API routes (findings, baselines, settings, exceptions, incidents) are
	// served exclusively by the API plane (cmd/api). The telemetry plane only handles
	// agent ingestion — no query endpoints exposed to reduce attack surface.

	if os.Getenv("ENABLE_DEBUG_ENDPOINTS") == "true" {
		mux.Handle("/debug/vars", wrapAuthed(expvar.Handler()))
		mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
			wrapAuthed(http.HandlerFunc(pprof.Index)).ServeHTTP(w, r)
		})
		mux.HandleFunc("/debug/pprof/cmdline", func(w http.ResponseWriter, r *http.Request) {
			wrapAuthed(http.HandlerFunc(pprof.Cmdline)).ServeHTTP(w, r)
		})
		mux.HandleFunc("/debug/pprof/profile", func(w http.ResponseWriter, r *http.Request) {
			wrapAuthed(http.HandlerFunc(pprof.Profile)).ServeHTTP(w, r)
		})
		mux.HandleFunc("/debug/pprof/symbol", func(w http.ResponseWriter, r *http.Request) {
			wrapAuthed(http.HandlerFunc(pprof.Symbol)).ServeHTTP(w, r)
		})
		mux.HandleFunc("/debug/pprof/trace", func(w http.ResponseWriter, r *http.Request) {
			wrapAuthed(http.HandlerFunc(pprof.Trace)).ServeHTTP(w, r)
		})
		log.Println("debug endpoints enabled: /debug/vars, /debug/pprof/*")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	maintenance.StartRetentionCleanup(ctx, db, maintenance.LoadRetentionConfig())

	log.Println("Correlic telemetry plane listening on :8081")
	srv := &http.Server{
		Addr:              ":8081",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	tlsEnabled, certFile, keyFile, tlsCfg, err := tlsConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	if !tlsEnabled {
		log.Fatal("mTLS is required: set TLS_CERT_FILE, TLS_KEY_FILE, and MTLS_CA_FILE")
	}

	srv.TLSConfig = tlsCfg
	// Require a CA so presented client certs can be verified;
	// agent endpoints are still enforced as mTLS-only by middleware.RequireMTLS.
	if tlsCfg == nil || tlsCfg.ClientCAs == nil || tlsCfg.ClientAuth != tls.VerifyClientCertIfGiven {
		log.Fatal("MTLS_CA_FILE is required (agent endpoints are mTLS-only; webhooks are HMAC-only)")
	}
	log.Printf("TLS enabled (agent endpoints require mTLS; webhooks are HMAC-only). cert=%s key=%s", certFile, keyFile)

	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go func() {
		if err := srv.ListenAndServeTLS(certFile, keyFile); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	<-shutdownCtx.Done()
	log.Println("shutdown signal received, draining connections...")

	drainCtx, drainCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer drainCancel()
	if err := srv.Shutdown(drainCtx); err != nil {
		log.Printf("graceful shutdown failed: %v", err)
	}
	log.Println("server stopped")
}
