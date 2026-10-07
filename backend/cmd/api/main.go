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
	"strings"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/correlic/correlic-backend/internal/ai"
	"github.com/correlic/correlic-backend/internal/ai/attribution"
	"github.com/correlic/correlic-backend/internal/ai/conversation"
	aidossier "github.com/correlic/correlic-backend/internal/ai/dossier"
	"github.com/correlic/correlic-backend/internal/ai/intelligence"
	"github.com/correlic/correlic-backend/internal/ai/provider"
	"github.com/correlic/correlic-backend/internal/api"
	"github.com/correlic/correlic-backend/internal/api/middleware"
	"github.com/correlic/correlic-backend/internal/config"
	"github.com/correlic/correlic-backend/internal/correlation"
	"github.com/correlic/correlic-backend/internal/detection"
	"github.com/correlic/correlic-backend/internal/detection/ai_pack"
	"github.com/correlic/correlic-backend/internal/incident"
	"github.com/correlic/correlic-backend/internal/ingest"
	"github.com/correlic/correlic-backend/internal/notification"
	"github.com/correlic/correlic-backend/internal/query"
	"github.com/correlic/correlic-backend/internal/service"
	"github.com/correlic/correlic-backend/internal/storage"
	"github.com/correlic/correlic-backend/internal/storage/eventstore"
	"github.com/correlic/correlic-backend/internal/storage/neo4j"
)

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
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return true, certFile, keyFile, cfg, nil
}

func main() {
	if err := config.LoadDotEnvIfPresent(".env"); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()

	// postgres connection string
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
	store := storage.NewPostgresAgentStore(db)
	agentCertStore := storage.NewPostgresAgentCertStore(db)
	identityStore := storage.NewPostgresAgentIdentityStore(db)
	orgStore := storage.NewPostgresOrgStore(db)
	userStore := storage.NewPostgresUserStore(db)
	auditStore := storage.NewPostgresAuditStore(db)
	telemetryStore := storage.NewPostgresTelemetryStore(db)
	canonicalEventStore := eventstore.NewPostgresEventStore(db)

	// Neo4j connection (optional - gracefully degrades if unavailable)
	var graphPersister *neo4j.GraphPersister
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
				if err := graphStore.LoadAIPatterns(db); err != nil {
					log.Printf("WARNING: Failed to load AI patterns into GraphStore: %v", err)
				} else {
					log.Println("Loaded AI patterns into GraphStore")
				}
				graphPersister = neo4j.NewGraphPersister(graphStore)
				log.Println("Neo4j graph persistence enabled")
			}
		}
	}

	timelineBuilder := &correlation.Builder{
		Store:      canonicalEventStore,
		GraphStore: graphPersister,
	}
	queryService := query.NewService(canonicalEventStore)

	// Neo4j timeline and investigation services (if Neo4j is available)
	var timelineService *query.TimelineService
	var investigationService *query.InvestigationService
	if graphPersister != nil {
		neo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
		graphStore := neo4j.NewGraphStore(neo4jClient)
		timelineService = query.NewTimelineService(neo4jClient, graphStore, db)
		investigationService = query.NewInvestigationService(neo4jClient)
		log.Println("Neo4j query services enabled")
	}

	// Tier 1: Real-time process tree writer (if Neo4j is available)
	var processTreeWriter *correlation.ProcessTreeWriter
	if graphPersister != nil {
		// Create a dedicated GraphStore for the process tree writer
		ptNeo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
		ptGraphStore := neo4j.NewGraphStore(ptNeo4jClient)
		if err := ptGraphStore.LoadAIPatterns(db); err != nil {
			log.Printf("WARNING: Failed to load AI patterns for ProcessTreeWriter: %v", err)
		}
		processTreeWriter = correlation.NewProcessTreeWriter(ptGraphStore)
		log.Println("Tier 1: Real-time process tree writer enabled")
	}

	// Tier 2: Streaming correlation (batched activity events) - event buffer + worker
	var eventBuffer *correlation.EventBuffer
	var correlationWorker *correlation.Worker
	if graphPersister != nil {
		bufferSize := 10000
		eventBuffer = correlation.NewEventBuffer(bufferSize)

		windowSize := 5 * time.Minute
		flushInterval := 30 * time.Second
		correlationWorker = correlation.NewWorker(eventBuffer, graphPersister, windowSize, flushInterval)

		// Start worker in background
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		correlationWorker.Start(ctx)

		log.Printf("Tier 2: Streaming correlation enabled (buffer: %d, window: %v, flush: %v)", bufferSize, windowSize, flushInterval)
	}

	// Phase 2: Detection engine + behavioral baseline
	detectionEngine := detection.NewEngine()
	detectionEngine.RegisterPack(ai_pack.NewAIPack())
	log.Printf("Detection engine enabled: %d rules registered", detectionEngine.RuleCount())

	var detectionQuerier detection.GraphQuerier
	if graphPersister != nil {
		dqNeo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
		detectionQuerier = detection.NewNeo4jGraphQuerier(dqNeo4jClient)
		log.Println("Detection graph querier enabled (Neo4j)")
	} else {
		log.Printf("WARN: Detection graph querier not available — ai.unexpected_network, " +
			"ai.data_exfiltration, and ai.excessive_writes will not fire. Set NEO4J_URI to enable.")
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
	blockRuleStore := storage.NewBlockRuleStore(db)
	defer blockRuleStore.Stop()
	blockEventStore := storage.NewBlockEventStore(db)
	cooldown := detection.NewFindingCooldown()
	defer cooldown.Stop()
	chainCorrelator := detection.NewChainCorrelator()
	defer chainCorrelator.Stop()
	log.Println("Behavioral baseline collector enabled")

	// Phase 4: Incident mapping
	incidentStore := incident.NewIncidentStore(db)
	incidentCorrelator := incident.NewIncidentCorrelator(incidentStore, findingStore)
	var graphStoreForIncidents *neo4j.GraphStore
	if graphPersister != nil {
		incNeo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
		graphStoreForIncidents = neo4j.NewGraphStore(incNeo4jClient)
	}
	contextAssembler := incident.NewContextAssembler(incidentStore, findingStore, graphStoreForIncidents, canonicalEventStore)
	summaryStore := ai.NewIncidentSummaryStore(db)
	incidentCorrelator.SetSummaryInvalidator(summaryStore)

	// Dossier builder and store (pre-computed LLM context for incidents)
	dossierStore := aidossier.NewStore(db)
	dossierBuilder := aidossier.NewDossierBuilder(contextAssembler, incidentStore, baselineCollector)
	convStore := conversation.NewStore(db)
	proactiveSummarizer := ai.NewProactiveSummarizer(dossierStore, dossierBuilder)
	proactiveSummarizer.SetConversationStore(convStore)
	go proactiveSummarizer.Start()
	defer proactiveSummarizer.Stop()
	incidentCorrelator.SetDossierInvalidator(dossierStore)
	log.Println("AI dossier + conversation thread system enabled")

	log.Println("Incident mapping enabled")

	// Phase 6: Notification engine
	endpointStore := notification.NewEndpointStore(db)
	notifStore := notification.NewNotificationStore(db)
	deliveryStore := notification.NewDeliveryStore(db)
	notifManager := notification.NewManager(notifStore, deliveryStore, endpointStore)
	incidentCorrelator.SetNotificationEmitter(notifManager)
	deliveryWorker := notification.NewDeliveryWorker(deliveryStore, endpointStore)
	if deliveryWorker != nil {
		go deliveryWorker.Start()
		defer deliveryWorker.Stop()
	}
	log.Println("Notification engine enabled")

	// Event sampling: reduce load by intelligently filtering events
	samplingEnabled := os.Getenv("SAMPLING_ENABLED") != "false" // Enabled by default
	var eventSampler *ingest.Sampler
	if samplingEnabled {
		samplingRules := ingest.DefaultSamplingRules()
		eventSampler = ingest.NewSampler(samplingRules)
		log.Println("Event sampling enabled (always-keep: process_exec, process_exit, container_start)")
	}

	heartbeatService := ingest.NewHeartbeatService(store)
	inventoryService := service.NewAgentInventoryService(store)

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
	apiKeyStore := storage.NewPostgresAPIKeyStore(db)
	clientCertStore := storage.NewPostgresClientCertStore(db)
	auth := middleware.NewAuthMiddleware(apiKeyStore, clientCertStore, userStore, db)
	mtlsFP := middleware.NewMTLSFingerprintMiddleware()
	roleGuard := middleware.NewRoleGuard(userStore)

	// Common middleware chain for authenticated endpoints.
	// Order matters:
	// - rate limiter can reject quickly based on the provided key
	// - auth injects org_id and actor into the request context
	// - audit runs after auth so it can log org_id
	// - role guard runs after auth so it can check the actor
	wrapAuthed := func(h http.Handler) http.Handler {
		return rateLimiter.Wrap(
			middleware.RequireMTLS(mtlsFP.Wrap(auth.Wrap(middleware.Audit(h)))),
		)
	}

	// Wrap with role guard (must run AFTER auth so actor is set in context)
	wrapAuthedWithRole := func(role string, h http.Handler) http.Handler {
		return wrapAuthed(roleGuard.RequireRole(role)(h))
	}

	// Wrap for unauthenticated endpoints (like login) - only rate limiting, no auth required
	wrapUnauthed := func(h http.Handler) http.Handler {
		return rateLimiter.Wrap(h)
	}

	mux.Handle("/heartbeat", wrapAuthed(api.NewHeartbeatHandler(heartbeatService, agentCertStore, apiKeyStore)))
	mux.Handle("/agents", wrapAuthed(api.NewListAgentsHandler(inventoryService)))
	mux.Handle("/orgs/", wrapAuthed(api.NewOrgsHandler(orgStore)))
	mux.Handle("/users", wrapAuthedWithRole("admin", api.NewUsersHandler(userStore, store, auditStore)))
	mux.Handle("/api-keys", wrapAuthedWithRole("admin", api.NewAPIKeysHandler(db, userStore, auditStore)))
	mux.Handle("/agent-tokens", wrapAuthed(api.NewAgentTokensHandler(db, userStore, auditStore)))
	mux.Handle("/auth/sessions", wrapUnauthed(api.NewSessionsHandler(userStore, auditStore)))          // Allow unauthenticated for login
	mux.Handle("/auth/password/reset", wrapAuthed(api.NewPasswordResetHandler(userStore, auditStore))) // Requires auth (session or API key)

	// User profile (self-service)
	profileHandler := api.NewProfileHandler(userStore)
	mux.Handle("/auth/profile", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			profileHandler.GetProfile(w, r)
		case http.MethodPut:
			profileHandler.UpdateProfile(w, r)
		default:
			api.MethodNotAllowed(w, "GET, PUT")
		}
	})))

	// Google OAuth sign-in
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	mux.Handle("/auth/google", wrapUnauthed(api.NewGoogleAuthHandler(userStore, googleClientID)))

	// Email verification
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "https://localhost:3000"
	}
	emailVerifHandler := api.NewEmailVerificationHandler(userStore, frontendURL)
	mux.Handle("/auth/email/send-verification", wrapUnauthed(http.HandlerFunc(emailVerifHandler.SendVerification)))
	mux.Handle("/auth/email/verify", wrapUnauthed(http.HandlerFunc(emailVerifHandler.VerifyEmail)))

	// AI Attribution service for tracking distinct AI agents (must be before telemetry handler)
	attributionStore := attribution.NewPostgresStore(db)
	attributionService := attribution.NewService(attributionStore)

	// Load AI patterns from database as the single source of truth
	if needles := attributionService.GetPatternNeedles(); len(needles) > 0 {
		api.SetAIProcessNeedles(needles)
		log.Printf("Loaded %d AI process patterns from database", len(needles))
	}

	mux.Handle("/telemetry", wrapAuthed(api.NewTelemetryHandler(telemetryStore, attributionService)))
	mux.Handle("/network/summary", wrapAuthed(api.NewNetworkSummaryHandler(telemetryStore)))
	mux.Handle("/network/domain", wrapAuthed(api.NewNetworkDomainHandler(telemetryStore)))
	mux.Handle("/network/destination", wrapAuthed(api.NewNetworkDestinationHandler(telemetryStore)))
	mux.Handle("/ports/summary", wrapAuthed(api.NewPortsSummaryHandler(telemetryStore)))
	mux.Handle("/ports/service", wrapAuthed(api.NewPortsServiceHandler(telemetryStore)))
	mux.Handle("/ai/proof", wrapAuthed(api.NewAIProofHandler(telemetryStore)))

	mux.Handle("/dashboard/stats", wrapAuthed(api.NewDashboardHandler(telemetryStore, store, attributionService, timelineService, findingStore, incidentStore, db)))
	mux.Handle("/dashboard/trends", wrapAuthed(api.NewDashboardTrendsHandler(db)))

	// Intelligence store (used by findings handler + AI tools)
	intelligenceStore := intelligence.NewStore(db)
	patternLearner := intelligence.NewPatternLearner(intelligenceStore)

	// BYOK LLM AI endpoints
	llmEncryptionKey := os.Getenv("LLM_ENCRYPTION_KEY")
	if llmEncryptionKey == "" {
		log.Fatal("LLM_ENCRYPTION_KEY is required: it encrypts stored LLM provider keys. " +
			"Generate one with `openssl rand -hex 32`. Installs that previously relied on the " +
			"built-in default must set it to \"correlic-default-key-change-in-prod!\" to keep " +
			"existing provider settings readable, then rotate.")
	}
	if llmSettingsStore, err := provider.NewSettingsStore(db, llmEncryptionKey); err != nil {
		log.Printf("WARNING: LLM settings store initialization failed: %v", err)
	} else {
		var graphStoreForAI *neo4j.GraphStore
		if graphPersister != nil {
			neo4jClient, _ := neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
			graphStoreForAI = neo4j.NewGraphStore(neo4jClient)
		}
		aiHandler := api.NewAIHandler(llmSettingsStore, telemetryStore, graphStoreForAI, attributionService)
		aiHandler.RegisterRoutes(mux, wrapAuthed)

		// Incident + Finding AI endpoints (explain, ask, chat)
		incidentAIHandler := api.NewIncidentAIHandler(llmSettingsStore, contextAssembler, findingStore, summaryStore, dossierStore, dossierBuilder, convStore, queryService, graphStoreForIncidents, intelligenceStore)
		mux.Handle("POST /api/v1/incidents/{id}/explain", wrapAuthed(http.HandlerFunc(incidentAIHandler.ExplainIncident)))
		mux.Handle("POST /api/v1/incidents/{id}/ask/stream", wrapAuthed(http.HandlerFunc(incidentAIHandler.StreamAskAboutIncident)))
		mux.Handle("POST /api/v1/incidents/{id}/ask", wrapAuthed(http.HandlerFunc(incidentAIHandler.AskAboutIncident)))
		mux.Handle("POST /api/v1/findings/{id}/explain", wrapAuthed(http.HandlerFunc(incidentAIHandler.ExplainFinding)))
		// New dossier-based threaded chat endpoints
		mux.Handle("/api/v1/incidents/{id}/chat", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				incidentAIHandler.ChatAboutIncident(w, r)
			} else {
				api.MethodNotAllowed(w, "POST")
			}
		})))
		mux.Handle("/api/v1/incidents/{id}/chat/history", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				incidentAIHandler.GetChatHistory(w, r)
			} else {
				api.MethodNotAllowed(w, "GET")
			}
		})))
		mux.Handle("/api/v1/incidents/{id}/chat/thread/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodDelete {
				incidentAIHandler.DeleteChatThread(w, r)
			} else {
				api.MethodNotAllowed(w, "DELETE")
			}
		})))
		log.Println("BYOK LLM AI endpoints enabled: /api/v1/ai/*, /api/v1/incidents/{id}/{explain,ask,ask/stream,chat}, /api/v1/findings/{id}/explain")
	}

	mux.Handle("/health", api.HealthHandler(detectionQuerier != nil))
	mux.Handle("/readiness", api.ReadinessHandler(db))
	mux.Handle("/ingest/events", wrapAuthed(api.NewLiveIngestHandler(telemetryStore, canonicalEventStore, eventBuffer, eventSampler, attributionService, processTreeWriter, detectionEngine, baselineCollector, findingStore, detectionQuerier, safeDomainStore, ruleExceptionStore, ruleSettingsStore, cooldown, chainCorrelator, incidentCorrelator, notifManager, neverBaselineStore)))

	// Detection findings API
	findingsHandler := api.NewFindingsHandler(findingStore, baselineCollector, incidentStore)
	findingsHandler.SetSafeDomainStore(safeDomainStore)
	if neo4jClient != nil {
		findingsHandler.SetNeo4jClient(neo4jClient)
	}
	findingsHandler.SetPatternLearner(patternLearner)
	mux.Handle("/api/v1/findings", wrapAuthed(http.HandlerFunc(findingsHandler.ListFindings)))
	mux.Handle("/api/v1/findings/suppressed-summary", wrapAuthed(http.HandlerFunc(findingsHandler.SuppressedSummary)))
	mux.Handle("/api/v1/findings/reconcile", wrapAuthed(http.HandlerFunc(findingsHandler.ReconcileFindings)))
	mux.Handle("/api/v1/findings/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Route: POST .../resolve-domain vs GET (GetFinding) vs PATCH (ResolveFinding)
		const suffix = "/resolve-domain"
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, suffix) {
			findingsHandler.ResolveDomain(w, r)
			return
		}
		if r.Method == http.MethodGet {
			findingsHandler.GetFinding(w, r)
			return
		}
		findingsHandler.ResolveFinding(w, r)
	})))

	// Detection rule settings API (per-org tunable thresholds)
	ruleSettingsHandler := api.NewRuleSettingsHandler(ruleSettingsStore)
	mux.Handle("/api/v1/detection/settings", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			ruleSettingsHandler.ListSettings(w, r)
		} else {
			api.MethodNotAllowed(w, "GET")
		}
	})))
	mux.Handle("/api/v1/detection/settings/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			ruleSettingsHandler.UpsertSetting(w, r)
		case http.MethodDelete:
			ruleSettingsHandler.DeleteSetting(w, r)
		default:
			api.MethodNotAllowed(w, "PUT, DELETE")
		}
	})))

	// Per-rule exceptions API
	exceptionsHandler := api.NewExceptionsHandler(ruleExceptionStore)
	mux.Handle("/api/v1/exceptions", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			exceptionsHandler.ListExceptions(w, r)
		case http.MethodPost:
			exceptionsHandler.CreateException(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/exceptions/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			exceptionsHandler.DeleteException(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))

	// Behavioral baselines API
	baselinesHandler := api.NewBaselinesHandler(db, baselineCollector, safeDomainStore, findingStore, incidentStore, neverBaselineStore)
	mux.Handle("/api/v1/baselines", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			baselinesHandler.ListBaselines(w, r)
		case http.MethodPost:
			baselinesHandler.CreateBaseline(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/baselines/summary", wrapAuthed(http.HandlerFunc(baselinesHandler.BaselineSummary)))
	neverBaselinesHandler := api.NewNeverBaselinesHandler(neverBaselineStore)
	mux.Handle("/api/v1/baselines/never-baselines", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			neverBaselinesHandler.ListNeverBaselines(w, r)
		case http.MethodPost:
			neverBaselinesHandler.CreateNeverBaseline(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/baselines/never-baselines/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			neverBaselinesHandler.DeleteNeverBaseline(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))
	mux.Handle("/api/v1/baselines/exclusions", wrapAuthed(http.HandlerFunc(baselinesHandler.ListExclusions)))
	mux.Handle("/api/v1/baselines/exclusions/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			baselinesHandler.DeleteExclusion(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))
	mux.Handle("/api/v1/baselines/noise-filters", wrapAuthed(http.HandlerFunc(baselinesHandler.NoiseFilters)))
	mux.Handle("/api/v1/baselines/safe-domains", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			baselinesHandler.ListSafeDomains(w, r)
		case http.MethodPost:
			baselinesHandler.AddSafeDomain(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/baselines/safe-domains/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			baselinesHandler.DeleteSafeDomain(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))
	// --- Block Rules ---
	blockRulesHandler := api.NewBlockRulesHandler(blockRuleStore)
	blockEventsHandler := api.NewBlockEventsHandler(blockEventStore, blockRuleStore)
	mux.Handle("/api/v1/block-rules", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			blockRulesHandler.ListBlockRules(w, r)
		case http.MethodPost:
			blockRulesHandler.CreateBlockRule(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/block-rules/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			blockRulesHandler.UpdateBlockRule(w, r)
		case http.MethodDelete:
			blockRulesHandler.DeleteBlockRule(w, r)
		default:
			api.MethodNotAllowed(w, "PUT, DELETE")
		}
	})))
	mux.Handle("/api/v1/block-events", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			blockEventsHandler.ListBlockEvents(w, r)
		} else {
			api.MethodNotAllowed(w, "GET")
		}
	})))
	mux.Handle("/api/v1/block-events/stats", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			blockEventsHandler.GetBlockEventStats(w, r)
		} else {
			api.MethodNotAllowed(w, "GET")
		}
	})))

	mux.Handle("/api/v1/baselines/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/confirm") {
			baselinesHandler.ConfirmBaseline(w, r)
			return
		}
		switch r.Method {
		case http.MethodDelete:
			baselinesHandler.DeleteBaseline(w, r)
		case http.MethodPatch:
			baselinesHandler.SuspendBaseline(w, r)
		default:
			api.MethodNotAllowed(w, "DELETE, PATCH, POST")
		}
	})))
	// Enrichment API (IP → domain/ASN resolution)
	mux.Handle("/api/v1/enrich/ip", wrapAuthed(http.HandlerFunc(api.ResolveIP)))
	mux.Handle("/api/v1/enrich/ips", wrapAuthed(http.HandlerFunc(api.ResolveBulkIPs)))

	// Notifications API (Phase 6)
	notifHandler := api.NewNotificationHandler(notifStore, endpointStore, deliveryStore)
	// In-app notifications
	mux.Handle("/api/v1/notifications", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			notifHandler.ListNotifications(w, r)
		} else {
			api.MethodNotAllowed(w, "GET")
		}
	})))
	mux.Handle("/api/v1/notifications/count", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			notifHandler.CountUnread(w, r)
		} else {
			api.MethodNotAllowed(w, "GET")
		}
	})))
	mux.Handle("/api/v1/notifications/read-all", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			notifHandler.MarkAllRead(w, r)
		} else {
			api.MethodNotAllowed(w, "POST")
		}
	})))
	mux.Handle("/api/v1/notifications/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			notifHandler.MarkRead(w, r)
		case http.MethodDelete:
			notifHandler.DismissNotification(w, r)
		default:
			api.MethodNotAllowed(w, "PATCH, DELETE")
		}
	})))
	// Notification endpoints (channel config)
	mux.Handle("/api/v1/notification-endpoints", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			notifHandler.ListEndpoints(w, r)
		case http.MethodPost:
			notifHandler.CreateEndpoint(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/notification-endpoints/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/test") {
			if r.Method == http.MethodPost {
				notifHandler.TestEndpoint(w, r)
			} else {
				api.MethodNotAllowed(w, "POST")
			}
			return
		}
		switch r.Method {
		case http.MethodPut:
			notifHandler.UpdateEndpoint(w, r)
		case http.MethodDelete:
			notifHandler.DeleteEndpoint(w, r)
		default:
			api.MethodNotAllowed(w, "PUT, DELETE")
		}
	})))
	// Delivery history
	mux.Handle("/api/v1/notification-deliveries", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			notifHandler.ListDeliveries(w, r)
		} else {
			api.MethodNotAllowed(w, "GET")
		}
	})))

	// Incidents API (Phase 4)
	incidentsHandler := api.NewIncidentsHandler(contextAssembler, incidentStore, findingStore, baselineCollector, summaryStore)
	mux.Handle("/api/v1/incidents", wrapAuthed(http.HandlerFunc(incidentsHandler.ListIncidents)))
	mux.Handle("/api/v1/incidents/", wrapAuthed(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			if strings.HasSuffix(r.URL.Path, "/timeline") {
				incidentsHandler.GetIncidentTimeline(w, r)
			} else {
				incidentsHandler.GetIncident(w, r)
			}
		case http.MethodPatch:
			incidentsHandler.UpdateIncidentStatus(w, r)
		default:
			api.MethodNotAllowed(w, "GET, PATCH")
		}
	})))

	mux.Handle("/timeline", api.TimelineHandler(timelineBuilder))

	// Neo4j-powered endpoints (fast graph queries)
	if timelineService != nil {
		mux.Handle("/neo4j/timeline", api.TimelineNeo4jHandler(timelineService))
		mux.Handle("/neo4j/process-tree", api.ProcessTreeHandler(timelineService))
		mux.Handle("/neo4j/attack-path", api.AttackPathHandler(timelineService))
		// Interactive process timeline (new UI)
		mux.Handle("/processes/tree", wrapAuthed(api.ProcessTimelineHandler(timelineService)))
		mux.Handle("/processes/activity", wrapAuthed(api.ProcessActivityHandler(timelineService)))
		mux.Handle("/processes/summary", wrapAuthed(api.ProcessNetworkSummaryHandler(timelineService)))
		// Agent activity stream (human-readable action feed)
		mux.Handle("/agents/activity", wrapAuthed(api.AgentActivityHandler(timelineService)))
		log.Println("Neo4j timeline endpoints enabled: /neo4j/timeline, /neo4j/process-tree, /neo4j/attack-path")
		log.Println("Process timeline endpoints enabled: /processes/tree, /processes/activity, /processes/summary")
		log.Println("Agent activity endpoint enabled: /agents/activity")
	}
	if investigationService != nil {
		mux.Handle("/neo4j/investigation/", api.InvestigationHandler(investigationService))
		log.Println("Neo4j investigation endpoints enabled: /neo4j/investigation/*")
	}

	mux.Handle("/query/containers", api.QueryContainersHandler(queryService))
	mux.Handle("/query/ports", api.QueryPortsHandler(queryService))
	mux.Handle("/query/connections", api.QueryConnectionsHandler(queryService))
	mux.Handle("/query/inbound", api.QueryInboundHandler(queryService))
	mux.Handle("/query/processes", api.QueryProcessesHandler(queryService))
	mux.Handle("/process/lifecycles", api.ProcessLifecyclesHandler(canonicalEventStore))

	mux.Handle(
		"/agents/",
		wrapAuthed(api.NewAgentsRouter(inventoryService, identityStore)),
	)
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

	log.Println("Correlic backend listening on :8080")
	srv := &http.Server{
		Addr:              ":8080",
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
	// Require mTLS for agent endpoints.
	if tlsCfg == nil || tlsCfg.ClientAuth != tls.RequireAndVerifyClientCert {
		log.Fatal("mTLS is required: set MTLS_CA_FILE")
	}
	log.Printf("TLS enabled (mTLS required). cert=%s key=%s", certFile, keyFile)

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
