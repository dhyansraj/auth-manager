local redis = require "resty.redis"

local function fail(status, msg)
    ngx.status = status
    ngx.header.content_type = "text/plain"
    ngx.say(msg)
    ngx.exit(status)
end

local red = redis:new()
red:set_timeout(500)  -- ms

local host  = os.getenv("REDIS_HOST") or "redis"
local port  = tonumber(os.getenv("REDIS_PORT") or "6379")

local ok, err = red:connect(host, port)
if not ok then
    ngx.log(ngx.ERR, "redis connect failed: ", err)
    return fail(502, "edge: redis unreachable\n")
end

local key = "host:" .. ngx.var.host
local res, err = red:hget(key, "backend")
if err then
    ngx.log(ngx.ERR, "redis hget failed: ", err)
    return fail(502, "edge: redis error\n")
end

-- Return the connection to the pool (keepalive for 60s, pool size 100).
red:set_keepalive(60000, 100)

if res == ngx.null or not res or res == "" then
    return fail(404,
        "edge: no route for host '" .. ngx.var.host .. "'\n" ..
        "Hint: HSET host:" .. ngx.var.host .. " backend <upstream:port>\n")
end

ngx.var.route_backend = res
