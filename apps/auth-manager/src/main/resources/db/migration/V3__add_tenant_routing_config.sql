-- ============================================================================
-- V3: Add per-tenant routing rules
--
-- Adds a JSONB `routing_config` column on tenants storing the rule list +
-- target map that OpenResty's route.lua consumes (mirrored to Redis as
-- `route:<slug>` by RoutingConfigService). Existing tenants are backfilled
-- with the conventional default (api -> backend REQUIRED, /* -> frontend
-- OPTIONAL) so the NOT NULL tightening at the end can succeed.
-- ============================================================================
SET search_path = auth_manager, public;

ALTER TABLE tenants ADD COLUMN routing_config JSONB;

-- Backfill existing tenants with the default rule set. Service names use the
-- conventional pattern <slug>-<role>.tenant-<slug>.svc.cluster.local.
UPDATE tenants SET routing_config = jsonb_build_object(
  'rules', jsonb_build_array(
    jsonb_build_object('path', '/api/*', 'authMode', 'REQUIRED', 'target', 'backend'),
    jsonb_build_object('path', '/*',     'authMode', 'OPTIONAL', 'target', 'frontend')
  ),
  'targets', jsonb_build_object(
    'backend',  slug || '-backend.tenant-' || slug || '.svc.cluster.local:8080',
    'frontend', slug || '-ui.tenant-'      || slug || '.svc.cluster.local:80'
  )
) WHERE routing_config IS NULL;

ALTER TABLE tenants ALTER COLUMN routing_config SET NOT NULL;
