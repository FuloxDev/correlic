-- ============================================================================
-- 004_baseline_suspension_and_block_event_fk.sql
-- ============================================================================
-- behavioral_baselines.expires_at used to carry two meanings: "allowed until"
-- (temporary allow created from a finding) and "suspended until" (user paused
-- the baseline). The matcher treated any future expires_at as a suspension, so
-- temporary allows never suppressed anything. Suspensions now live in their own
-- column.
--
-- block_events.rule_id was NOT NULL with ON DELETE SET NULL, so deleting a
-- block rule that had fired failed with a constraint violation.
--
-- Idempotent: safe to re-run.
-- ============================================================================

ALTER TABLE behavioral_baselines ADD COLUMN IF NOT EXISTS suspended_until TIMESTAMPTZ;

ALTER TABLE block_events ALTER COLUMN rule_id DROP NOT NULL;
