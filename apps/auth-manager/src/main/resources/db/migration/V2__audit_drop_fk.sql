-- ============================================================================
-- V2: Remove FK from audit_events to tenants
--
-- Audit rows must survive after the referenced tenant is deleted, AND the
-- REQUIRES_NEW propagation on AuditService means the audit insert can run
-- before the outer tenant insert has committed. Dropping the FK fixes both.
-- The tenant_id column and idx_audit_tenant_time index remain (audit by
-- tenant is a common query).
-- ============================================================================
ALTER TABLE auth_manager.audit_events
    DROP CONSTRAINT IF EXISTS audit_events_tenant_id_fkey;
