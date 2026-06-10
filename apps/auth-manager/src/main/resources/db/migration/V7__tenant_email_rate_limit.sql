-- ============================================================================
-- V7: Per-tenant email rate-limit overrides
--
-- Optional per-tenant overrides for the app-facing email send API's
-- fixed-window limits (EmailRateLimiter). NULL columns fall back to the
-- platform defaults (auth-manager.email.rate-limit.per-minute / .per-day),
-- so existing tenants keep today's behavior with no backfill.
-- ============================================================================
SET search_path = auth_manager, public;

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email_rl_per_minute INTEGER;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email_rl_per_day INTEGER;

COMMENT ON COLUMN tenants.email_rl_per_minute IS
  'Per-tenant override of the send-API per-minute burst limit; NULL falls back to auth-manager.email.rate-limit.per-minute';
COMMENT ON COLUMN tenants.email_rl_per_day IS
  'Per-tenant override of the send-API daily quota; NULL falls back to auth-manager.email.rate-limit.per-day';
