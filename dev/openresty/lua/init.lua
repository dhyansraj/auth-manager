-- init.lua
-- Loads env-var-driven configuration once per worker. nginx must declare
-- each env var via `env FOO;` in the top-level conf for os.getenv to work
-- inside Lua under OpenResty.

local _M = {}

local function getenv(name, default)
    local v = os.getenv(name)
    if v == nil or v == "" then
        return default
    end
    return v
end

_M.redis_host = getenv("REDIS_HOST", "redis")
_M.redis_port = tonumber(getenv("REDIS_PORT", "6379"))

-- Redis Sentinel HA support. When enabled, redis_host:redis_port is the
-- sentinel endpoint (typically port 26379); redis_client resolves the
-- current master via `SENTINEL get-master-addr-by-name <master>` at runtime
-- and caches the answer for a few seconds. Disabled by default so the local
-- docker-compose stack (standalone redis) keeps working unchanged.
local function getbool(name, default)
    local v = os.getenv(name)
    if v == nil or v == "" then return default end
    v = v:lower()
    return v == "1" or v == "true" or v == "yes" or v == "on"
end

_M.redis_sentinel_enabled = getbool("REDIS_SENTINEL_ENABLED", false)
_M.redis_sentinel_master  = getenv("REDIS_SENTINEL_MASTER", "mymaster")

-- Cross-cutting platform targets. Defaults are sensible for the local
-- docker-compose stack (auth-manager runs on the host; keycloak runs in
-- the compose network).
_M.platform_admin_api_target = getenv("PLATFORM_ADMIN_API_TARGET", "host.docker.internal:8080")
_M.platform_admin_ui_target  = getenv("PLATFORM_ADMIN_UI_TARGET",  "host.docker.internal:8080")
_M.platform_kc_target        = getenv("PLATFORM_KC_TARGET",        "keycloak:8180")

-- Platform host (e.g. auth.mcp-mesh.io). Requests with this Host header
-- (after cross-cutting paths) route to admin-ui (SPA root) + auth-manager
-- (under /api/* and /actuator/*), instead of going through tenant lookup.
_M.platform_host             = getenv("PLATFORM_HOST",             "auth.mcp-mesh.io")

-- Shared-dict for caching per-tenant route JSON.
_M.cache_ttl_seconds = 30

-- Per-route body-size cap (megabytes). Routes that omit RoutingRule.maxBodyMb
-- fall back to this value. Hard upper bound is enforced by nginx's
-- `client_max_body_size 100m` (Cloudflare Free tunnel ceiling) regardless of
-- this setting; raising the default above 100 won't help.
_M.route_default_max_body_mb    = tonumber(getenv("ROUTE_DEFAULT_MAX_BODY_MB", "25"))
_M.route_default_max_body_bytes = _M.route_default_max_body_mb * 1024 * 1024

return _M
