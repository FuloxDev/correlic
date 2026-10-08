-- ============================================================================
-- 005_hotfix_v1_0_1.sql
-- ============================================================================
-- v1.0.1 hotfix schema changes:
--
-- * agents.user_id            — the dashboard user an agent key was issued to
--                                (heartbeat links agents to the API key's user).
-- * telemetry_events(received_at), events(ts), sessions(expires_at) indexes —
--                                retention cleanup and session pruning scanned
--                                these tables sequentially.
-- * events.org_id             — canonical events were tenant-less; ingest now
--                                stamps the org so reads can be org-scoped.
-- * safe_domains_list.org_id, ai_agent_patterns.org_id — rows seeded by
--                                migrations keep NULL (built-in, read-only);
--                                rows created through the API carry the org.
-- * events(context->>'ai_session_id') — /agents/activity without Neo4j
--                                groups events by the agent's AI session tag
--                                and looks up each session's root process.
--
-- findings.org_id backfill is intentionally NOT attempted: pre-1.0.1 findings
-- with an empty org cannot be attributed to a tenant after the fact. The
-- store no longer reads or writes rows with an empty org, so they are
-- simply invisible until retention removes them.
--
-- Idempotent: safe to re-run.
-- ============================================================================

ALTER TABLE agents ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES users(id);

CREATE INDEX IF NOT EXISTS idx_telemetry_events_received_at ON telemetry_events (received_at);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions (expires_at);

ALTER TABLE events ADD COLUMN IF NOT EXISTS org_id UUID;
CREATE INDEX IF NOT EXISTS idx_events_org_host_ts ON events (org_id, host_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ai_session ON events ((context->>'ai_session_id'))
  WHERE context->>'ai_session_id' IS NOT NULL;

-- NULL org_id = built-in (seeded) row: visible to every org, never deletable via API.
ALTER TABLE safe_domains_list ADD COLUMN IF NOT EXISTS org_id UUID;
CREATE INDEX IF NOT EXISTS idx_safe_domains_list_org ON safe_domains_list (org_id);

ALTER TABLE ai_agent_patterns ADD COLUMN IF NOT EXISTS org_id UUID;
CREATE INDEX IF NOT EXISTS idx_ai_agent_patterns_org ON ai_agent_patterns (org_id);

-- The global UNIQUE constraints on domain / pattern would stop org A from adding a
-- domain org B already added. Replace them with per-org uniqueness; built-ins
-- (org_id IS NULL) stay unique among themselves.
ALTER TABLE safe_domains_list DROP CONSTRAINT IF EXISTS safe_domains_list_domain_key;
CREATE UNIQUE INDEX IF NOT EXISTS safe_domains_list_org_domain_uq
    ON safe_domains_list (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), domain);

ALTER TABLE ai_agent_patterns DROP CONSTRAINT IF EXISTS ai_agent_patterns_pattern_key;
CREATE UNIQUE INDEX IF NOT EXISTS ai_agent_patterns_org_pattern_uq
    ON ai_agent_patterns (COALESCE(org_id, '00000000-0000-0000-0000-000000000000'::uuid), pattern);
