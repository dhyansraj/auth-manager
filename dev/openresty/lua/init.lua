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

-- Cross-cutting platform targets. Defaults are sensible for the local
-- docker-compose stack (auth-manager runs on the host; keycloak runs in
-- the compose network).
_M.platform_admin_api_target = getenv("PLATFORM_ADMIN_API_TARGET", "host.docker.internal:8080")
_M.platform_admin_ui_target  = getenv("PLATFORM_ADMIN_UI_TARGET",  "host.docker.internal:8080")
_M.platform_kc_target        = getenv("PLATFORM_KC_TARGET",        "keycloak:8180")

-- Shared-dict for caching per-tenant route JSON.
_M.cache_ttl_seconds = 30

return _M
