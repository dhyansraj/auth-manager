-- router.lua
-- Main access_by_lua entrypoint. Resolves request → backend in this order:
--   1. Cross-cutting platform paths (/auth/*, /.well-known/openid-configuration)
--      -- route by path alone, ignoring the Host header. These bypass tenant
--      lookup entirely (cross-cutting for OIDC discovery on any hostname).
--   2. Platform host (PLATFORM_HOST, e.g. auth.mcp-mesh.io) — when the request
--      Host matches, route /api/* and /actuator/* to auth-manager and
--      everything else to admin-ui (SPA), with OPTIONAL auth at the edge.
--   3. Otherwise: Host header → tenant slug via Redis HGET host:<host> tenant.
--   4. Tenant slug → ordered rule list via Redis GET route:<slug>
--      (with a 30s shared-dict cache).
--   5. First rule whose path glob matches ngx.var.uri wins.
--   6. Auth gating per rule.authMode (PUBLIC / REQUIRED / OPTIONAL).
--   7. Set ngx.var.route_backend for proxy_pass.

local cjson = require "cjson.safe"
local config = require "init"
local rclient = require "redis_client"
local matcher = require "matcher"

local function fail(status, msg)
    ngx.status = status
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode({ error = "routing_error", message = msg }))
    return ngx.exit(status)
end

-- Strip ":port" from a Host header for HGET host:<host> lookups.
local function strip_port(host)
    if not host then return nil end
    local colon = string.find(host, ":", 1, true)
    if colon then
        return string.sub(host, 1, colon - 1)
    end
    return host
end

-- Returns (backend, auth_mode, rewritten_uri_or_nil) if the request matches
-- a platform cross-cutting path. Returns (nil, nil, nil) otherwise.
--
-- The third return value is a rewritten URI to forward upstream when the
-- prefix must be stripped before the request reaches the platform service
-- (Keycloak 17+ runs at root, not at /auth). nil means "forward path as-is".
local function match_platform(path)
    if path == "/.well-known/openid-configuration" then
        return config.platform_kc_target, "PUBLIC", nil
    end
    if matcher.match("/auth/*", path) then
        -- Strip the "/auth" prefix so Keycloak (which serves /realms/... at root)
        -- gets the URI it expects. "/auth" alone becomes "/".
        local stripped
        if path == "/auth" then
            stripped = "/"
        else
            stripped = string.sub(path, 6)  -- drop "/auth"
        end
        return config.platform_kc_target, "OPTIONAL", stripped
    end
    return nil, nil, nil
end

-- Platform-host routing. When Host == PLATFORM_HOST (after cross-cutting paths
-- have been considered), route by path prefix:
--   /api/*       → auth-manager
--   /actuator/*  → auth-manager
--   /*           → admin-ui (SPA root + assets)
-- All paths pass through with OPTIONAL auth at the edge — backends enforce
-- auth themselves. No path rewriting.
local function match_platform_host(path)
    if matcher.match("/api/*", path) then
        return config.platform_admin_api_target, "OPTIONAL"
    end
    if matcher.match("/actuator/*", path) then
        return config.platform_admin_api_target, "OPTIONAL"
    end
    return config.platform_admin_ui_target, "OPTIONAL"
end

local function lookup_tenant(host)
    local red, err = rclient.open()
    if not red then
        ngx.log(ngx.ERR, "redis connect failed: ", err)
        return nil, "redis unreachable"
    end
    local tenant, lerr = rclient.hget(red, "host:" .. host, "tenant")
    rclient.close(red)
    if lerr then
        ngx.log(ngx.ERR, "redis hget host:", host, " failed: ", lerr)
        return nil, "redis error"
    end
    return tenant, nil
end

-- Returns rules_json (the raw JSON string from Redis) using the
-- shared-dict cache, populating it on miss.
local function load_routes(tenant)
    local cache = ngx.shared.route_cache
    local cached = cache:get("route:" .. tenant)
    if cached then
        return cached, nil
    end

    local red, err = rclient.open()
    if not red then
        ngx.log(ngx.ERR, "redis connect failed: ", err)
        return nil, "redis unreachable"
    end
    local json, lerr = rclient.get(red, "route:" .. tenant)
    rclient.close(red)
    if lerr then
        ngx.log(ngx.ERR, "redis get route:", tenant, " failed: ", lerr)
        return nil, "redis error"
    end
    if json then
        cache:set("route:" .. tenant, json, config.cache_ttl_seconds)
    end
    return json, nil
end

local function enforce_auth(auth_mode, tenant)
    if auth_mode == "PUBLIC" then
        -- Drop any Authorization header so backends can't accidentally
        -- gate on it for a path the platform considers public.
        ngx.req.clear_header("Authorization")
        return
    end
    if auth_mode == "REQUIRED" then
        local hdr = ngx.var.http_authorization
        if not hdr or hdr == "" then
            ngx.status = 401
            local realm = tenant or "platform"
            ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. realm .. '"'
            ngx.header.content_type = "application/json"
            ngx.say(cjson.encode({
                error = "unauthorized",
                message = "this path requires a token"
            }))
            return ngx.exit(401)
        end
        return
    end
    -- OPTIONAL: pass through whatever was sent (token or not).
end

-- ─── Main flow ───────────────────────────────────────────────────────────
local path = ngx.var.uri
local host = strip_port(ngx.var.http_host or ngx.var.host)

-- 0. KC admin host (kc.mcp-mesh.io): route everything to Keycloak. KC mounts
--    at root, so /admin/*, /resources/*, /realms/* etc. work as-is. The admin
--    console HTML embeds /auth/* prefixed URLs (because KC_HOSTNAME=.../auth);
--    those need the /auth prefix stripped so KC can serve them at root.
--    Auth is OPTIONAL here — KC's own admin login flow gates access, and the
--    Cloudflare WAF IP-restriction rule fronts this hostname.
if host and host == config.kc_admin_host then
    if matcher.match("/auth/*", path) then
        local stripped
        if path == "/auth" then
            stripped = "/"
        else
            stripped = string.sub(path, 6)  -- drop "/auth"
        end
        if stripped ~= path then
            ngx.req.set_uri(stripped, false)
        end
    end
    ngx.var.route_backend = config.platform_kc_target
    return
end

-- 1. Cross-cutting platform paths first.
local backend, auth_mode, rewritten = match_platform(path)
if backend then
    enforce_auth(auth_mode, nil)
    if rewritten and rewritten ~= path then
        -- Rewrite the URI in-place so proxy_pass forwards the stripped path.
        -- false → don't trigger location re-match.
        ngx.req.set_uri(rewritten, false)
    end
    ngx.var.route_backend = backend
    return
end

-- 2. Platform host (auth.mcp-mesh.io) routing — admin-ui + auth-manager.
if host and host == config.platform_host then
    local p_backend, p_auth = match_platform_host(path)
    enforce_auth(p_auth, nil)
    ngx.var.route_backend = p_backend
    return
end

-- 3. Host → tenant
if not host or host == "" then
    return fail(400, "missing Host header")
end
local tenant, terr = lookup_tenant(host)
if terr then
    return fail(502, terr)
end
if not tenant then
    return fail(404, "unknown host: " .. host)
end

-- 4. Tenant → routes
local rules_json, rerr = load_routes(tenant)
if rerr then
    return fail(502, rerr)
end
if not rules_json then
    return fail(404, "no routes configured for tenant: " .. tenant)
end

local routes, derr = cjson.decode(rules_json)
if not routes or derr then
    ngx.log(ngx.ERR, "failed to decode route:", tenant, " json: ", derr)
    return fail(500, "corrupt routing config for tenant: " .. tenant)
end

-- 5. Path → rule
local rule = matcher.find_rule(routes.rules, path)
if not rule then
    return fail(404, "no rule matched for path: " .. path)
end

local target_name = rule.target
local resolved = routes.targets and routes.targets[target_name] or nil
if not resolved or resolved == "" then
    ngx.log(ngx.ERR, "unresolved target '", target_name, "' for tenant ", tenant)
    return fail(500, "unresolved target: " .. (target_name or "(nil)"))
end

-- 6. Auth gating
enforce_auth(rule.authMode, tenant)

-- 7. Proxy
ngx.var.route_backend = resolved
