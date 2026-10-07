-- ============================================================================
-- Correlic Backend — Consolidated Schema
-- ============================================================================
-- This file replaces migrations 001-086 with a single idempotent schema.
-- All statements use CREATE ... IF NOT EXISTS so re-running is safe.
--
-- Generated from migrations 001-086, excluding dead tables:
--   - alerts, alerts_lifecycle (superseded by findings/incidents)
--   - detector_state         (legacy detector cursor tracking)
--   - notification_deliveries (replaced by notification_deliveries_v2)
--   - llm_usage              (created in migration 043, never used in code)
--
-- Tables created: 37 live tables actively used by the Go backend.
-- ============================================================================

-- ── Extensions ──────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- CORE: organizations, users, auth, RBAC, sessions
-- ============================================================================

CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    id                       UUID PRIMARY KEY,
    email                    TEXT NOT NULL UNIQUE,
    name                     TEXT NOT NULL DEFAULT '',
    password_hash            TEXT,
    password_reset_required  BOOLEAN NOT NULL DEFAULT false,
    email_verified           BOOLEAN NOT NULL DEFAULT false,
    username                 TEXT,
    avatar_url               TEXT NOT NULL DEFAULT '',
    is_service_account       BOOLEAN NOT NULL DEFAULT false,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS users_email_idx ON users (email);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_unique_idx
    ON users (username) WHERE username IS NOT NULL AND username != '';

CREATE TABLE IF NOT EXISTS org_users (
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT 'member',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id          UUID PRIMARY KEY,
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS sessions_token_hash_unique ON sessions (token_hash);

CREATE TABLE IF NOT EXISTS user_oauth_accounts (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     TEXT NOT NULL,
    provider_id  TEXT NOT NULL,
    email        TEXT NOT NULL,
    name         TEXT NOT NULL DEFAULT '',
    avatar_url   TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS user_oauth_provider_idx
    ON user_oauth_accounts (provider, provider_id);
CREATE INDEX IF NOT EXISTS user_oauth_user_idx
    ON user_oauth_accounts (user_id);

CREATE TABLE IF NOT EXISTS email_verification_tokens (
    id          UUID PRIMARY KEY,
    email       TEXT NOT NULL,
    token_hash  TEXT NOT NULL UNIQUE,
    expires_at  TIMESTAMPTZ NOT NULL,
    used_at     TIMESTAMPTZ NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS email_verification_tokens_email_idx
    ON email_verification_tokens (email);
CREATE INDEX IF NOT EXISTS email_verification_tokens_token_hash_idx
    ON email_verification_tokens (token_hash);
CREATE INDEX IF NOT EXISTS email_verification_tokens_expires_at_idx
    ON email_verification_tokens (expires_at) WHERE used_at IS NULL;

-- ============================================================================
-- API KEYS
-- ============================================================================

CREATE TABLE IF NOT EXISTS api_keys (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id      UUID REFERENCES users(id),
    key_hash     TEXT NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    key_type     TEXT NOT NULL DEFAULT 'service',
    expires_at   TIMESTAMPTZ NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS api_keys_key_hash_unique ON api_keys (key_hash);
CREATE INDEX IF NOT EXISTS api_keys_org_id_idx ON api_keys (org_id);
CREATE INDEX IF NOT EXISTS api_keys_org_id_active_idx
    ON api_keys (org_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS api_keys_key_type_idx ON api_keys (key_type);

-- ============================================================================
-- AGENTS & MTLS
-- ============================================================================

CREATE TABLE IF NOT EXISTS agents (
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id       TEXT NOT NULL,
    hostname       TEXT NOT NULL DEFAULT '',
    os             TEXT NOT NULL DEFAULT '',
    profile        TEXT NOT NULL DEFAULT '',
    version        TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL DEFAULT '',
    first_seen_at  TIMESTAMPTZ NOT NULL,
    last_seen_at   TIMESTAMPTZ NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (org_id, agent_id)
);

CREATE INDEX IF NOT EXISTS agents_org_last_seen_idx
    ON agents (org_id, last_seen_at DESC);

CREATE TABLE IF NOT EXISTS org_client_certs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS org_client_certs_org_fingerprint_unique
    ON org_client_certs (org_id, fingerprint);
CREATE INDEX IF NOT EXISTS org_client_certs_org_revoked_idx
    ON org_client_certs (org_id, revoked_at);
CREATE UNIQUE INDEX IF NOT EXISTS org_client_certs_fingerprint_active_unique
    ON org_client_certs (fingerprint) WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS org_agent_certs (
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id     TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at   TIMESTAMPTZ NULL,
    PRIMARY KEY (org_id, agent_id)
);

CREATE UNIQUE INDEX IF NOT EXISTS org_agent_certs_org_fingerprint_unique
    ON org_agent_certs (org_id, fingerprint);

CREATE TABLE IF NOT EXISTS org_agent_identities (
    org_id           UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id         TEXT NOT NULL,
    kind             TEXT NOT NULL,
    value            TEXT NOT NULL,
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    seen_count       BIGINT NOT NULL DEFAULT 1,
    last_event_id    UUID,
    last_event_type  TEXT,
    last_meta        JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (org_id, agent_id, kind, value)
);

CREATE INDEX IF NOT EXISTS org_agent_identities_org_agent_kind_idx
    ON org_agent_identities (org_id, agent_id, kind);

-- ============================================================================
-- AUDIT
-- ============================================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id           UUID PRIMARY KEY,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    actor_type   TEXT NOT NULL,
    actor_id     TEXT NOT NULL,
    action       TEXT NOT NULL,
    target_type  TEXT NOT NULL,
    target_id    TEXT NOT NULL,
    meta         JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS audit_events_org_idx
    ON audit_events (org_id, created_at DESC);

-- ============================================================================
-- TELEMETRY: raw agent ingest + canonical event store
-- ============================================================================

CREATE TABLE IF NOT EXISTS telemetry_events (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    event_ts     TIMESTAMPTZ NOT NULL,
    payload      JSONB NOT NULL,
    received_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS telemetry_events_org_ts_idx
    ON telemetry_events (org_id, event_ts DESC);
CREATE INDEX IF NOT EXISTS telemetry_events_org_agent_ts_idx
    ON telemetry_events (org_id, agent_id, event_ts DESC);
CREATE INDEX IF NOT EXISTS idx_telemetry_org_type_ts
    ON telemetry_events (org_id, event_type, event_ts DESC);

CREATE TABLE IF NOT EXISTS events (
    id              TEXT PRIMARY KEY,
    schema_version  INT NOT NULL,
    host_id         TEXT NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    source          TEXT NOT NULL,
    type            TEXT NOT NULL,
    actor           JSONB,
    target          JSONB,
    context         JSONB
);

CREATE INDEX IF NOT EXISTS idx_events_host_ts ON events (host_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (type);

-- ============================================================================
-- DETECTION: findings, incidents, AI summaries
-- ============================================================================

CREATE TABLE IF NOT EXISTS findings (
    id              TEXT PRIMARY KEY,
    org_id          TEXT,
    detection_id    TEXT NOT NULL,
    host_id         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    summary         TEXT,
    anchor_event    TEXT,
    related_events  TEXT[],
    context         JSONB,
    status          TEXT DEFAULT 'pending',
    resolution      TEXT,
    resolved_by     TEXT,
    resolved_at     TIMESTAMPTZ,
    suppressed      BOOLEAN DEFAULT FALSE,
    baseline_match  TEXT,
    confidence      FLOAT DEFAULT 0.0,
    incident_id     TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_findings_host ON findings (host_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings (status);
CREATE INDEX IF NOT EXISTS idx_findings_detection ON findings (detection_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings (severity);
CREATE INDEX IF NOT EXISTS idx_findings_created ON findings (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_confidence ON findings (confidence);
CREATE INDEX IF NOT EXISTS idx_findings_org_id ON findings (org_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_host ON findings (org_id, host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_incident ON findings (incident_id);
CREATE INDEX IF NOT EXISTS idx_findings_org_created ON findings (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_org_status_created ON findings (org_id, status, created_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    id                TEXT PRIMARY KEY,
    org_id            TEXT NOT NULL DEFAULT '',
    host_id           TEXT NOT NULL,
    severity          TEXT NOT NULL,
    confidence        FLOAT NOT NULL DEFAULT 0,
    title             TEXT NOT NULL,
    summary           TEXT,
    mitre_techniques  TEXT[],
    finding_ids       TEXT[] NOT NULL,
    chain_finding_id  TEXT,
    started_at        TIMESTAMPTZ NOT NULL,
    ended_at          TIMESTAMPTZ NOT NULL,
    context_summary   JSONB,
    status            TEXT NOT NULL DEFAULT 'open',
    resolution        TEXT,
    resolved_by       TEXT,
    resolved_at       TIMESTAMPTZ,
    dossier_text      TEXT,
    dossier_built_at  TIMESTAMPTZ,
    category          TEXT NOT NULL DEFAULT 'other',
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_incidents_org ON incidents (org_id);
CREATE INDEX IF NOT EXISTS idx_incidents_org_status ON incidents (org_id, status);
CREATE INDEX IF NOT EXISTS idx_incidents_host ON incidents (host_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS idx_incidents_created ON incidents (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_needs_dossier
    ON incidents (org_id, severity, created_at DESC)
    WHERE dossier_text IS NULL AND status IN ('open', 'investigating');
CREATE INDEX IF NOT EXISTS idx_incidents_category
    ON incidents (org_id, host_id, category, status, ended_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_org_created ON incidents (org_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_incidents_org_status_severity
    ON incidents (org_id, status, severity);

CREATE TABLE IF NOT EXISTS incident_ai_summaries (
    id              TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id          TEXT NOT NULL DEFAULT '',
    incident_id     TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    summary         TEXT NOT NULL,
    model           TEXT NOT NULL,
    input_tokens    INTEGER NOT NULL DEFAULT 0,
    output_tokens   INTEGER NOT NULL DEFAULT 0,
    generated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    invalidated_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_ai_summaries_org ON incident_ai_summaries (org_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_ai_summaries_org_incident
    ON incident_ai_summaries (org_id, incident_id);

-- ============================================================================
-- BEHAVIORAL: baselines, exclusions, never-baselines, rule exceptions
-- ============================================================================

CREATE TABLE IF NOT EXISTS behavioral_baselines (
    id           SERIAL PRIMARY KEY,
    org_id       TEXT NOT NULL DEFAULT '',
    host_id      TEXT NOT NULL,
    ai_type      TEXT NOT NULL DEFAULT '',
    signal_type  TEXT NOT NULL,
    pattern      TEXT NOT NULL,
    source       TEXT DEFAULT 'observed',
    hit_count    INT DEFAULT 1,
    expires_at   TIMESTAMPTZ,
    first_seen   TIMESTAMPTZ DEFAULT NOW(),
    last_seen    TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_baselines_host ON behavioral_baselines (host_id, ai_type);
CREATE INDEX IF NOT EXISTS idx_baselines_signal ON behavioral_baselines (signal_type);
CREATE INDEX IF NOT EXISTS idx_baselines_last_seen ON behavioral_baselines (last_seen);
CREATE INDEX IF NOT EXISTS idx_baselines_org_id ON behavioral_baselines (org_id);
CREATE INDEX IF NOT EXISTS idx_baselines_org_host_seen
    ON behavioral_baselines (org_id, host_id, last_seen DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_baselines_org_host_signal_pattern
    ON behavioral_baselines (org_id, host_id, ai_type, signal_type, pattern);

CREATE TABLE IF NOT EXISTS baseline_exclusions (
    id           SERIAL PRIMARY KEY,
    org_id       TEXT NOT NULL DEFAULT '',
    host_id      TEXT NOT NULL,
    ai_type      TEXT NOT NULL DEFAULT '',
    signal_type  TEXT NOT NULL,
    pattern      TEXT NOT NULL,
    created_by   TEXT NOT NULL DEFAULT 'system',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, host_id, ai_type, signal_type, pattern)
);

CREATE INDEX IF NOT EXISTS idx_baseline_exclusions_org ON baseline_exclusions (org_id);

CREATE TABLE IF NOT EXISTS org_never_baselines (
    id           SERIAL PRIMARY KEY,
    org_id       TEXT NOT NULL,
    signal_type  TEXT NOT NULL,
    pattern      TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    created_by   TEXT NOT NULL DEFAULT 'user',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, signal_type, pattern)
);

CREATE INDEX IF NOT EXISTS idx_org_never_baselines_org ON org_never_baselines (org_id);

CREATE TABLE IF NOT EXISTS rule_exceptions (
    id             BIGSERIAL PRIMARY KEY,
    org_id         TEXT NOT NULL,
    detection_id   TEXT NOT NULL,
    host_id        TEXT NOT NULL DEFAULT '*',
    context_key    TEXT NOT NULL DEFAULT '',
    context_value  TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT '',
    match_mode     TEXT NOT NULL DEFAULT 'exact',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rule_exceptions_org ON rule_exceptions (org_id);
CREATE INDEX IF NOT EXISTS idx_rule_exceptions_detection
    ON rule_exceptions (org_id, detection_id);

CREATE TABLE IF NOT EXISTS detection_rule_settings (
    id             BIGSERIAL PRIMARY KEY,
    org_id         TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    setting_key    TEXT NOT NULL,
    setting_value  TEXT NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, rule_id, setting_key)
);

CREATE INDEX IF NOT EXISTS idx_detection_rule_settings_org
    ON detection_rule_settings (org_id);

-- ============================================================================
-- SAFE DOMAINS (for AI data exfiltration detection)
-- ============================================================================

CREATE TABLE IF NOT EXISTS safe_domains_list (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    domain      VARCHAR(255) UNIQUE NOT NULL,
    description TEXT,
    created_at  TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- BLOCK ENGINE: rules + audit trail
-- ============================================================================

CREATE TABLE IF NOT EXISTS block_rules (
    id           SERIAL PRIMARY KEY,
    org_id       TEXT NOT NULL,
    signal_type  TEXT NOT NULL,
    pattern      TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT TRUE,
    kill_tree    BOOLEAN NOT NULL DEFAULT FALSE,
    source       TEXT NOT NULL DEFAULT 'user',
    created_by   TEXT NOT NULL DEFAULT 'user',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, signal_type, pattern)
);

CREATE INDEX IF NOT EXISTS idx_block_rules_org ON block_rules (org_id);
CREATE INDEX IF NOT EXISTS idx_block_rules_org_enabled
    ON block_rules (org_id) WHERE enabled = TRUE;

CREATE TABLE IF NOT EXISTS block_events (
    id           TEXT PRIMARY KEY,
    org_id       TEXT NOT NULL,
    host_id      TEXT NOT NULL,
    agent_id     TEXT NOT NULL DEFAULT '',
    rule_id      INTEGER NOT NULL REFERENCES block_rules(id) ON DELETE SET NULL,
    signal_type  TEXT NOT NULL,
    pid          INTEGER NOT NULL,
    exe_path     TEXT NOT NULL DEFAULT '',
    cmdline      TEXT NOT NULL DEFAULT '',
    target       TEXT NOT NULL DEFAULT '',
    ai_type      TEXT NOT NULL DEFAULT '',
    success      BOOLEAN NOT NULL,
    error_msg    TEXT NOT NULL DEFAULT '',
    latency_us   INTEGER NOT NULL DEFAULT 0,
    blocked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_block_events_org
    ON block_events (org_id, blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_block_events_host
    ON block_events (host_id, blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_block_events_rule ON block_events (rule_id);

-- ============================================================================
-- NOTIFICATIONS: in-app + external channel delivery
-- ============================================================================

CREATE TABLE IF NOT EXISTS notification_endpoints (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    channel_type  TEXT NOT NULL CHECK (channel_type IN ('webhook', 'slack')),
    config        JSONB NOT NULL DEFAULT '{}',
    min_severity  TEXT NOT NULL DEFAULT 'medium'
                  CHECK (min_severity IN ('low','medium','high','critical')),
    enabled       BOOLEAN NOT NULL DEFAULT true,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notif_endpoints_org
    ON notification_endpoints (org_id, enabled);

CREATE TABLE IF NOT EXISTS notifications (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          UUID NOT NULL,
    category        TEXT NOT NULL CHECK (category IN ('finding','incident','system')),
    severity        TEXT NOT NULL,
    title           TEXT NOT NULL,
    summary         TEXT NOT NULL DEFAULT '',
    reference_type  TEXT,
    reference_id    TEXT,
    host_id         TEXT,
    context         JSONB NOT NULL DEFAULT '{}',
    read            BOOLEAN NOT NULL DEFAULT false,
    dismissed       BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notif_unread
    ON notifications (org_id, read, created_at DESC) WHERE NOT dismissed;
CREATE INDEX IF NOT EXISTS idx_notif_org
    ON notifications (org_id, created_at DESC);

CREATE TABLE IF NOT EXISTS notification_deliveries_v2 (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           UUID NOT NULL,
    endpoint_id      UUID NOT NULL REFERENCES notification_endpoints(id) ON DELETE CASCADE,
    reference_type   TEXT NOT NULL,
    reference_id     TEXT NOT NULL,
    payload          JSONB NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','delivered','failed','dead')),
    attempts         INT NOT NULL DEFAULT 0,
    max_attempts     INT NOT NULL DEFAULT 5,
    last_error       TEXT NOT NULL DEFAULT '',
    next_attempt_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    delivered_at     TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_deliveries_pending
    ON notification_deliveries_v2 (status, next_attempt_at) WHERE status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS idx_deliveries_dedup
    ON notification_deliveries_v2 (endpoint_id, reference_type, reference_id);
CREATE INDEX IF NOT EXISTS idx_deliveries_org
    ON notification_deliveries_v2 (org_id, created_at DESC);

-- ============================================================================
-- LLM PROVIDER SETTINGS (BYOK)
-- ============================================================================

CREATE TABLE IF NOT EXISTS llm_settings (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id                  UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id                 UUID REFERENCES users(id) ON DELETE SET NULL,
    provider                TEXT NOT NULL
                            CHECK (provider IN ('openai', 'gemini', 'anthropic', 'groq', 'xai')),
    model                   TEXT NOT NULL,
    api_key_encrypted       TEXT NOT NULL,
    enabled                 BOOLEAN DEFAULT true,
    max_tokens_per_request  INTEGER DEFAULT 4096,
    temperature             NUMERIC(3,2) DEFAULT 0.7,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    updated_at              TIMESTAMPTZ DEFAULT NOW(),
    last_used_at            TIMESTAMPTZ,
    UNIQUE (org_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_llm_settings_org ON llm_settings (org_id);
CREATE INDEX IF NOT EXISTS idx_llm_settings_provider
    ON llm_settings (org_id, provider);

-- ============================================================================
-- AI ATTRIBUTION & SESSIONS
-- ============================================================================

CREATE TABLE IF NOT EXISTS ai_agent_patterns (
    id           SERIAL PRIMARY KEY,
    pattern      TEXT NOT NULL UNIQUE,
    agent_type   TEXT NOT NULL,
    description  TEXT,
    created_at   TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_agent_sessions (
    id              TEXT PRIMARY KEY,
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    agent_id        TEXT NOT NULL,
    root_pid        BIGINT NOT NULL,
    root_comm       TEXT NOT NULL,
    agent_type      TEXT NOT NULL,
    started_at      TIMESTAMPTZ NOT NULL,
    last_seen_at    TIMESTAMPTZ NOT NULL,
    event_count     INT DEFAULT 1,
    ai_session_id   TEXT,
    UNIQUE (org_id, agent_id, root_pid)
);

CREATE INDEX IF NOT EXISTS idx_ai_sessions_org ON ai_agent_sessions (org_id);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_last_seen ON ai_agent_sessions (last_seen_at);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_agent_type ON ai_agent_sessions (agent_type);
CREATE INDEX IF NOT EXISTS idx_ai_sessions_ai_session_id
    ON ai_agent_sessions (ai_session_id);

-- ============================================================================
-- AI INTELLIGENCE LAYERS (system profiles, context windows, learned patterns)
-- ============================================================================

CREATE TABLE IF NOT EXISTS ai_system_profiles (
    id          SERIAL PRIMARY KEY,
    org_id      TEXT NOT NULL,
    host_id     TEXT NOT NULL,
    profile     JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, host_id)
);

CREATE TABLE IF NOT EXISTS ai_context_windows (
    id            SERIAL PRIMARY KEY,
    org_id        TEXT NOT NULL,
    host_id       TEXT NOT NULL,
    granularity   TEXT NOT NULL,
    window_start  TIMESTAMPTZ NOT NULL,
    window_end    TIMESTAMPTZ NOT NULL,
    summary       JSONB NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ctx_windows_lookup
    ON ai_context_windows (org_id, host_id, granularity, window_start DESC);
CREATE INDEX IF NOT EXISTS idx_ctx_windows_cleanup
    ON ai_context_windows (granularity, created_at);

CREATE TABLE IF NOT EXISTS ai_learned_patterns (
    id           SERIAL PRIMARY KEY,
    org_id       TEXT NOT NULL,
    pattern_key  TEXT NOT NULL,
    verdict      TEXT NOT NULL DEFAULT 'unknown',
    confidence   REAL NOT NULL DEFAULT 0.5,
    evidence     JSONB NOT NULL DEFAULT '{}',
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, pattern_key)
);

CREATE INDEX IF NOT EXISTS idx_learned_patterns_org
    ON ai_learned_patterns (org_id, verdict);

-- ============================================================================
-- AI CONVERSATION (threaded chat about incidents)
-- ============================================================================

CREATE TABLE IF NOT EXISTS ai_conversation_threads (
    id             TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    org_id         TEXT NOT NULL,
    incident_id    TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    message_count  INT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_threads_org_incident
    ON ai_conversation_threads (org_id, incident_id, last_active DESC);
CREATE INDEX IF NOT EXISTS idx_threads_last_active
    ON ai_conversation_threads (last_active);

CREATE TABLE IF NOT EXISTS ai_conversation_messages (
    id           TEXT PRIMARY KEY DEFAULT gen_random_uuid()::text,
    thread_id    TEXT NOT NULL REFERENCES ai_conversation_threads(id) ON DELETE CASCADE,
    org_id       TEXT NOT NULL,
    role         TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content      TEXT NOT NULL,
    token_count  INT NOT NULL DEFAULT 0,
    compressed   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_messages_thread_created
    ON ai_conversation_messages (thread_id, created_at);

-- ============================================================================
-- FUNCTIONS & TRIGGERS
-- ============================================================================

-- Telemetry retention cleanup (manual / pg_cron)
CREATE OR REPLACE FUNCTION cleanup_old_telemetry()
RETURNS void AS $$
BEGIN
    DELETE FROM telemetry_events WHERE received_at < NOW() - INTERVAL '7 days';
    RAISE NOTICE 'Telemetry cleanup completed at %', NOW();
END;
$$ LANGUAGE plpgsql;

-- llm_settings.updated_at auto-update
CREATE OR REPLACE FUNCTION update_llm_settings_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS llm_settings_updated_at ON llm_settings;
CREATE TRIGGER llm_settings_updated_at
    BEFORE UPDATE ON llm_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_llm_settings_updated_at();

-- incidents.updated_at auto-update
CREATE OR REPLACE FUNCTION update_incidents_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_incidents_updated_at ON incidents;
CREATE TRIGGER trg_incidents_updated_at
    BEFORE UPDATE ON incidents
    FOR EACH ROW
    EXECUTE FUNCTION update_incidents_updated_at();
