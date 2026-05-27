-- ============================================================================
-- V4: Add per-tenant rich-login branding config
--
-- Adds a JSONB `branding_config` column on tenants storing the layout variant
-- + slot HTML map for the mcpmesh.flexible parent theme. NULL when the tenant
-- has not yet configured rich-login slots.
-- ============================================================================
SET search_path = auth_manager, public;

ALTER TABLE tenants ADD COLUMN IF NOT EXISTS branding_config JSONB;
