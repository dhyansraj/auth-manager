-- redis_client.lua
-- Thin wrapper around lua-resty-redis. Opens a short-lived connection,
-- does one or two operations, returns the connection to the pool via
-- set_keepalive. Errors are returned to the caller; the router decides
-- whether to fail the request or fall through to defaults.
--
-- Sentinel HA: when config.redis_sentinel_enabled is true, config.redis_host
-- and config.redis_port are interpreted as a Sentinel endpoint. open()
-- discovers the current master via `SENTINEL get-master-addr-by-name`,
-- caches the (host, port) in ngx.shared.route_cache for MASTER_CACHE_TTL
-- seconds, and connects to the master. Callers that hit a READONLY error
-- (cached master just got demoted in a failover) should call
-- invalidate_master_cache() so the next open() re-queries Sentinel.

local redis = require "resty.redis"
local config = require "init"

local _M = {}

local CONN_TIMEOUT_MS = 500
local KEEPALIVE_TIMEOUT_MS = 60000
local KEEPALIVE_POOL_SIZE = 100

-- Sentinel discovery tunables. Reuse route_cache (already declared in
-- nginx.conf as a 10m shared dict) — sized for our cache footprint.
local SENTINEL_TIMEOUT_MS = 2000
local MASTER_CACHE_KEY = "redis:master_addr"
local MASTER_CACHE_TTL = 5  -- seconds; short so failover converges quickly

-- Ask any Sentinel for the current master address. Returns (host, port, err).
local function query_sentinel()
    local sentinel = redis:new()
    sentinel:set_timeout(SENTINEL_TIMEOUT_MS)
    local ok, cerr = sentinel:connect(config.redis_host, config.redis_port)
    if not ok then
        return nil, nil, "sentinel connect failed: " .. (cerr or "?")
    end
    -- lua-resty-redis exposes arbitrary commands via metatable dispatch:
    -- red:sentinel("get-master-addr-by-name", "mymaster") works for any
    -- non-built-in command name. Returns an array {ip, port} or ngx.null
    -- when no master is known under that name.
    local res, qerr = sentinel:sentinel("get-master-addr-by-name", config.redis_sentinel_master)
    -- Return connection to pool on success; close on protocol-level error.
    if res and not qerr then
        sentinel:set_keepalive(KEEPALIVE_TIMEOUT_MS, KEEPALIVE_POOL_SIZE)
    else
        sentinel:close()
    end
    if not res or qerr then
        return nil, nil, "sentinel query failed: " .. (qerr or "nil result")
    end
    if res == ngx.null or type(res) ~= "table" or #res < 2 then
        return nil, nil, "sentinel returned no master for '" .. config.redis_sentinel_master .. "'"
    end
    local mhost = res[1]
    local mport = tonumber(res[2])
    if not mhost or not mport then
        return nil, nil, "sentinel returned malformed master addr"
    end
    return mhost, mport, nil
end

-- Returns (host, port, err). When sentinel is disabled this is a no-op
-- pass-through of the configured host:port.
local function resolve_master()
    if not config.redis_sentinel_enabled then
        return config.redis_host, config.redis_port, nil
    end

    local cache = ngx.shared.route_cache
    local cached = cache and cache:get(MASTER_CACHE_KEY)
    if cached then
        local h, p = string.match(cached, "^(.+):(%d+)$")
        if h and p then
            return h, tonumber(p), nil
        end
        -- Malformed cache entry; fall through to re-query.
    end

    local mhost, mport, qerr = query_sentinel()
    if not mhost then
        return nil, nil, qerr
    end
    if cache then
        cache:set(MASTER_CACHE_KEY, mhost .. ":" .. mport, MASTER_CACHE_TTL)
    end
    return mhost, mport, nil
end

-- Force the next open() to re-discover the master from Sentinel. Callers
-- should invoke this on a READONLY error from any subsequent op (means our
-- cached master just got demoted during a failover).
function _M.invalidate_master_cache()
    local cache = ngx.shared.route_cache
    if cache then cache:delete(MASTER_CACHE_KEY) end
end

-- Inspect a redis op error string; if it looks like the server told us the
-- node is read-only (post-failover stale master), invalidate the cache so
-- the next open() re-queries Sentinel. The CURRENT op still fails — caller
-- decides whether to retry or surface the error.
function _M.maybe_invalidate_on_readonly(err)
    if not err or not config.redis_sentinel_enabled then return end
    if type(err) == "string" and string.find(err, "READONLY", 1, true) then
        _M.invalidate_master_cache()
    end
end

function _M.open()
    local mhost, mport, rerr = resolve_master()
    if not mhost then
        ngx.log(ngx.ERR, "redis_client: resolve_master failed: ", rerr)
        return nil, rerr or "no master available"
    end

    local red = redis:new()
    red:set_timeout(CONN_TIMEOUT_MS)
    local ok, err = red:connect(mhost, mport)
    if not ok then
        -- Cached master may have died between the cache write and this
        -- connect attempt; drop the cache so the next call re-queries.
        if config.redis_sentinel_enabled then
            _M.invalidate_master_cache()
        end
        ngx.log(ngx.ERR, "redis_client: connect to ", mhost, ":", mport, " failed: ", err)
        return nil, err
    end
    return red, nil
end

function _M.close(red)
    if red then
        red:set_keepalive(KEEPALIVE_TIMEOUT_MS, KEEPALIVE_POOL_SIZE)
    end
end

-- Returns (value, err). value is nil when key missing.
function _M.hget(red, key, field)
    local res, err = red:hget(key, field)
    if err then
        return nil, err
    end
    if res == ngx.null or res == nil or res == "" then
        return nil, nil
    end
    return res, nil
end

-- Returns (value, err). value is nil when key missing.
function _M.get(red, key)
    local res, err = red:get(key)
    if err then
        return nil, err
    end
    if res == ngx.null or res == nil or res == "" then
        return nil, nil
    end
    return res, nil
end

return _M
