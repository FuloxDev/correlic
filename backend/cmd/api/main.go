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
	// Neo4j is opt-in: no NEO4J_URI means no graph (no localhost or password defaults).
	// Detection still runs without it — rules take AI attribution from event tags.
	// One driver is created per process and shared by every graph consumer below.
	neo4jURI := os.Getenv("NEO4J_URI")
	neo4jUser := os.Getenv("NEO4J_USERNAME")
	neo4jPass := os.Getenv("NEO4J_PASSWORD")

	var neo4jClient *neo4j.Client
	if neo4jURI == "" || neo4jURI == "disabled" || neo4jURI == "none" {
		log.Println("Neo4j disabled (NEO4J_URI not set) — running without graph context; detection remains enabled")
	} else {
		var err error
		neo4jClient, err = neo4j.NewClient(neo4jURI, neo4jUser, neo4jPass)
		if err != nil {
			log.Printf("WARNING: Neo4j connection failed, running without graph (uri=%s): %v", neo4jURI, err)
			neo4jClient = nil
		} else {
			defer neo4jClient.Close(context.Background())
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
		graphStore := neo4j.NewGraphStore(neo4jClient)
		timelineService = query.NewTimelineService(neo4jClient, graphStore, db)
		investigationService = query.NewInvestigationService(neo4jClient)
		log.Println("Neo4j query services enabled")
	}

	// Tier 1: Real-time process tree writer (if Neo4j is available)
	var processTreeWriter *correlation.ProcessTreeWriter
	if graphPersister != nil {
		// Dedicated GraphStore (own pattern cache) on the shared Neo4j driver
		ptGraphStore := neo4j.NewGraphStore(neo4jClient)
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

	// AI attribution for detection comes from event tags (ai_session_id / is_ai) and a
	// bounded (host,pid) cache shared across batches; Neo4j only adds look-back context.
	attributionCache := detection.NewAttributionCache(0, 0)
	var detectionQuerier detection.GraphQuerier
	if graphPersister != nil {
		detectionQuerier = detection.NewNeo4jGraphQuerier(neo4jClient)
		log.Println("Detection graph querier enabled (Neo4j)")
	} else {
		log.Printf("Detection graph querier disabled — rules use event attribution tags; " +
			"look-back rules (ai.data_exfiltration, ai.excessive_writes) need NEO4J_URI.")
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
		graphStoreForIncidents = neo4j.NewGraphStore(neo4jClient)
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
	sessionStore := storage.NewPostgresSessionStore(db)
	auth := middleware.NewAuthMiddleware(apiKeyStore, clientCertStore, userStore, db)
	mtlsFP := middleware.NewMTLSFingerprintMiddleware()
	roleGuard := middleware.NewRoleGuard(userStore)

	// Common middleware chain for authenticated endpoints.
	// Order matters:
	// - rate limiter can reject quickly based on the provided key
	// - auth injects org_id, actor and role into the request context
	// - audit runs after auth so it can log the actor
	// - role guards run after auth so they can check the actor
	//
	// Route policy (see middleware.RoleAgent):
	// - wrapAgent: agent, member and admin. Only for routes agents need
	//   (heartbeat, telemetry, ingest, pattern list).
	// - wrapAuthed: member and admin; the agent role gets 403.
	// - wrapAdminWrites: like wrapAuthed, but non-GET methods are admin only.
	// - wrapAdmin: admin only, every method.
	wrapAgent := func(h http.Handler) http.Handler {
		return rateLimiter.Wrap(
			middleware.RequireMTLS(mtlsFP.Wrap(auth.Wrap(middleware.Audit(h)))),
		)
	}
	wrapAuthed := func(h http.Handler) http.Handler {
		return wrapAgent(middleware.DenyRole(middleware.RoleAgent)(h))
	}
	wrapAdminWrites := func(h http.Handler) http.Handler {
		return wrapAuthed(middleware.AdminForWrites()(h))
	}
	wrapAdmin := func(h http.Handler) http.Handler {
		return wrapAuthed(roleGuard.RequireRole(middleware.RoleAdmin)(h))
	}

	// Wrap for unauthenticated endpoints (like login): rate limited by client
	// IP only, no auth required.
	wrapUnauthed := func(h http.Handler) http.Handler {
		return rateLimiter.WrapUnauthenticated(h)
	}

	mux.Handle("/heartbeat", wrapAgent(api.NewHeartbeatHandler(heartbeatService, agentCertStore, apiKeyStore)))
	mux.Handle("/agents", wrapAuthed(api.NewListAgentsHandler(inventoryService)))
	mux.Handle("/orgs/", wrapAdminWrites(api.NewOrgsHandler(orgStore)))
	mux.Handle("/users", wrapAdminWrites(api.NewUsersHandler(userStore, store, auditStore)))
	mux.Handle("/api-keys", wrapAdminWrites(api.NewAPIKeysHandler(db, userStore, auditStore)))
	mux.Handle("/agent-tokens", wrapAdminWrites(api.NewAgentTokensHandler(db, userStore, auditStore)))
	// Login (POST) and logout (DELETE, revokes the presented token) are
	// unauthenticated routes: rate limited per client IP, no auth middleware.
	mux.Handle("/auth/sessions", wrapUnauthed(api.NewSessionsHandler(userStore, sessionStore, auditStore)))
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

	// Google OAuth sign-in. Registered only when a client ID is configured:
	// without one the token audience cannot be verified.
	if googleClientID := strings.TrimSpace(os.Getenv("GOOGLE_CLIENT_ID")); googleClientID != "" {
		mux.Handle("/auth/google", wrapUnauthed(api.NewGoogleAuthHandler(userStore, googleClientID)))
		log.Println("Google sign-in enabled: /auth/google")
	} else {
		log.Println("Google sign-in disabled (GOOGLE_CLIENT_ID not set)")
	}

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

	mux.Handle("/telemetry", wrapAgent(api.NewTelemetryHandler(telemetryStore, agentCertStore, attributionService)))
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
	// A bad key must not silently drop the AI routes (the agent fetches its
	// pattern list from /api/v1/ai/patterns), so this is fatal.
	if llmSettingsStore, err := provider.NewSettingsStore(db, llmEncryptionKey); err != nil {
		log.Fatalf("LLM settings store initialization failed: %v", err)
	} else {
		var graphStoreForAI *neo4j.GraphStore
		if graphPersister != nil {
			graphStoreForAI = neo4j.NewGraphStore(neo4jClient)
		}
		aiHandler := api.NewAIHandler(llmSettingsStore, telemetryStore, graphStoreForAI, attributionService)
		aiHandler.RegisterRoutes(mux, wrapAuthed, wrapAgent, wrapAdminWrites)

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

	mux.Handle("/health", api.HealthHandler(detectionEngine != nil, detectionQuerier != nil))
	mux.Handle("/readiness", api.ReadinessHandler(db))
	mux.Handle("/ingest/events", wrapAgent(api.NewLiveIngestHandler(telemetryStore, canonicalEventStore, agentCertStore, eventBuffer, eventSampler, attributionService, processTreeWriter, detectionEngine, baselineCollector, findingStore, detectionQuerier, attributionCache, safeDomainStore, ruleExceptionStore, ruleSettingsStore, cooldown, chainCorrelator, incidentCorrelator, notifManager, neverBaselineStore)))

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
	mux.Handle("/api/v1/detection/settings", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			ruleSettingsHandler.ListSettings(w, r)
		} else {
			api.MethodNotAllowed(w, "GET")
		}
	})))
	mux.Handle("/api/v1/detection/settings/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	mux.Handle("/api/v1/exceptions", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			exceptionsHandler.ListExceptions(w, r)
		case http.MethodPost:
			exceptionsHandler.CreateException(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/exceptions/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			exceptionsHandler.DeleteException(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))

	// Behavioral baselines API
	baselinesHandler := api.NewBaselinesHandler(db, baselineCollector, safeDomainStore, findingStore, incidentStore, neverBaselineStore)
	mux.Handle("/api/v1/baselines", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			baselinesHandler.ListBaselines(w, r)
		case http.MethodPost:
			baselinesHandler.CreateBaseline(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/baselines/summary", wrapAdminWrites(http.HandlerFunc(baselinesHandler.BaselineSummary)))
	neverBaselinesHandler := api.NewNeverBaselinesHandler(neverBaselineStore)
	mux.Handle("/api/v1/baselines/never-baselines", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			neverBaselinesHandler.ListNeverBaselines(w, r)
		case http.MethodPost:
			neverBaselinesHandler.CreateNeverBaseline(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/baselines/never-baselines/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			neverBaselinesHandler.DeleteNeverBaseline(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))
	mux.Handle("/api/v1/baselines/exclusions", wrapAdminWrites(http.HandlerFunc(baselinesHandler.ListExclusions)))
	mux.Handle("/api/v1/baselines/exclusions/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			baselinesHandler.DeleteExclusion(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))
	mux.Handle("/api/v1/baselines/noise-filters", wrapAdminWrites(http.HandlerFunc(baselinesHandler.NoiseFilters)))
	mux.Handle("/api/v1/baselines/safe-domains", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			baselinesHandler.ListSafeDomains(w, r)
		case http.MethodPost:
			baselinesHandler.AddSafeDomain(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/baselines/safe-domains/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			baselinesHandler.DeleteSafeDomain(w, r)
		} else {
			api.MethodNotAllowed(w, "DELETE")
		}
	})))
	// --- Block Rules ---
	blockRulesHandler := api.NewBlockRulesHandler(blockRuleStore)
	blockEventsHandler := api.NewBlockEventsHandler(blockEventStore, blockRuleStore)
	mux.Handle("/api/v1/block-rules", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			blockRulesHandler.ListBlockRules(w, r)
		case http.MethodPost:
			blockRulesHandler.CreateBlockRule(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/block-rules/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	mux.Handle("/api/v1/baselines/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	mux.Handle("/api/v1/notification-endpoints", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			notifHandler.ListEndpoints(w, r)
		case http.MethodPost:
			notifHandler.CreateEndpoint(w, r)
		default:
			api.MethodNotAllowed(w, "GET, POST")
		}
	})))
	mux.Handle("/api/v1/notification-endpoints/", wrapAdminWrites(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	mux.Handle("/timeline", wrapAuthed(api.TimelineHandler(timelineBuilder)))

	// Neo4j-powered endpoints (fast graph queries)
	if timelineService != nil {
		mux.Handle("/neo4j/timeline", wrapAuthed(api.TimelineNeo4jHandler(timelineService)))
		mux.Handle("/neo4j/process-tree", wrapAuthed(api.ProcessTreeHandler(timelineService)))
		mux.Handle("/neo4j/attack-path", wrapAuthed(api.AttackPathHandler(timelineService)))
		// Interactive process timeline (new UI)
		mux.Handle("/processes/tree", wrapAuthed(api.ProcessTimelineHandler(timelineService)))
		mux.Handle("/processes/activity", wrapAuthed(api.ProcessActivityHandler(timelineService)))
		mux.Handle("/processes/summary", wrapAuthed(api.ProcessNetworkSummaryHandler(timelineService)))
		log.Println("Neo4j timeline endpoints enabled: /neo4j/timeline, /neo4j/process-tree, /neo4j/attack-path")
		log.Println("Process timeline endpoints enabled: /processes/tree, /processes/activity, /processes/summary")
	}
	// Agent activity stream (human-readable action feed). Always available: the
	// dashboard feed and the Agent Activity page depend on it. Served from the
	// graph when Neo4j is configured, else from the events table via the
	// agent's AI session tags.
	var activitySource query.AgentActivitySource = query.NewPostgresActivityStream(db)
	activityBackend := "postgres"
	if timelineService != nil {
		activitySource = timelineService
		activityBackend = "neo4j"
	}
	mux.Handle("/agents/activity", wrapAuthed(api.AgentActivityHandler(activitySource)))
	log.Printf("Agent activity endpoint enabled: /agents/activity (source: %s)", activityBackend)
	if investigationService != nil {
		mux.Handle("/neo4j/investigation/", wrapAuthed(api.InvestigationHandler(investigationService)))
		log.Println("Neo4j investigation endpoints enabled: /neo4j/investigation/*")
	}

	mux.Handle("/query/containers", wrapAuthed(api.QueryContainersHandler(queryService)))
	mux.Handle("/query/ports", wrapAuthed(api.QueryPortsHandler(queryService)))
	mux.Handle("/query/connections", wrapAuthed(api.QueryConnectionsHandler(queryService)))
	mux.Handle("/query/inbound", wrapAuthed(api.QueryInboundHandler(queryService)))
	mux.Handle("/query/processes", wrapAuthed(api.QueryProcessesHandler(queryService)))
	mux.Handle("/process/lifecycles", wrapAuthed(api.ProcessLifecyclesHandler(canonicalEventStore)))

	mux.Handle(
		"/agents/",
		wrapAuthed(api.NewAgentsRouter(inventoryService, identityStore)),
	)
	if os.Getenv("ENABLE_DEBUG_ENDPOINTS") == "true" {
		// Debug endpoints expose process internals: admin only.
		mux.Handle("/debug/vars", wrapAdmin(expvar.Handler()))
		mux.Handle("/debug/pprof/", wrapAdmin(http.HandlerFunc(pprof.Index)))
		mux.Handle("/debug/pprof/cmdline", wrapAdmin(http.HandlerFunc(pprof.Cmdline)))
		mux.Handle("/debug/pprof/profile", wrapAdmin(http.HandlerFunc(pprof.Profile)))
		mux.Handle("/debug/pprof/symbol", wrapAdmin(http.HandlerFunc(pprof.Symbol)))
		mux.Handle("/debug/pprof/trace", wrapAdmin(http.HandlerFunc(pprof.Trace)))
		log.Println("debug endpoints enabled (admin only): /debug/vars, /debug/pprof/*")
	}

	// LISTEN_ADDR overrides the bind address (default ":8080"); used by the
	// integration tests to run several stacks side by side.
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":8080"
	}
	log.Printf("Correlic backend listening on %s", listenAddr)
	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// LLM explain/chat and SSE streams legitimately take longer than the
		// 15s used by the telemetry plane; provider clients cap at 120s.
		WriteTimeout: 180 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	tlsEnabled, certFile, keyFile, tlsCfg, err := tlsConfigFromEnv()
	if err != nil {
		log.Fatal(err)
	}
	if !tlsEnabled {
		log.Fatal("mTLS is required: set TLS_CERT_FILE, TLS_KEY_FILE, and MTLS_CA_FILE")
	}

	srv.TLSConfig = tlsCfg
	// Response hygiene headers on every response; HSTS only because TLS is on.
	srv.Handler = middleware.SecurityHeaders(tlsEnabled)(mux)
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
