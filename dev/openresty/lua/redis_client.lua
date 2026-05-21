-- redis_client.lua
-- Thin wrapper around lua-resty-redis. Opens a short-lived connection,
-- does one or two operations, returns the connection to the pool via
-- set_keepalive. Errors are returned to the caller; the router decides
-- whether to fail the request or fall through to defaults.

local redis = require "resty.redis"
local config = require "init"

local _M = {}

local CONN_TIMEOUT_MS = 500
local KEEPALIVE_TIMEOUT_MS = 60000
local KEEPALIVE_POOL_SIZE = 100

function _M.open()
    local red = redis:new()
    red:set_timeout(CONN_TIMEOUT_MS)
    local ok, err = red:connect(config.redis_host, config.redis_port)
    if not ok then
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
