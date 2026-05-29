-- ============================================================================
-- V5: Per-tenant email config + SendGrid domain auth state
--
-- Adds optional per-tenant overrides for the realm's SMTP "From" / display /
-- reply-to fields. NULL columns fall back to the platform defaults
-- (auth-manager.smtp.from-address, tenant.displayName, KC default).
-- sendgrid_domain_id / sendgrid_domain_valid track the SendGrid domain-auth
-- workflow per-tenant so the UI can show authentication status without
-- re-querying SendGrid on every render.
-- ============================================================================
SET search_path = auth_manager, public;

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email_from_address TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email_from_display_name TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS email_reply_to_address TEXT;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS sendgrid_domain_id INTEGER;
ALTER TABLE tenants ADD COLUMN IF NOT EXISTS sendgrid_domain_valid BOOLEAN;

COMMENT ON COLUMN tenants.email_from_address IS
  'Per-tenant override; falls back to auth-manager.smtp.from-address';
COMMENT ON COLUMN tenants.email_from_display_name IS
  'Per-tenant override; falls back to tenant.display_name';
COMMENT ON COLUMN tenants.email_reply_to_address IS
  'Per-tenant Reply-To header; NULL means KC default (= from address)';
COMMENT ON COLUMN tenants.sendgrid_domain_id IS
  'SendGrid whitelabel domain id when this tenant has authenticated their own From domain';
COMMENT ON COLUMN tenants.sendgrid_domain_valid IS
  'Cached SendGrid validation state; refreshed by TenantDomainAuthService.status() / .revalidate()';
