-- router.lua
-- Main access_by_lua entrypoint. Resolves request → backend in this order:
--   1. Cross-cutting platform paths (/auth/*, /.well-known/openid-configuration,
--      /admin/api/*, /admin/*) -- route by path alone, ignoring the Host header.
--      These bypass tenant lookup entirely. /admin/* is a cross-cutting path so
--      a tenant subdomain (e.g. app1.mcp-mesh.io/admin/) can serve the admin-ui
--      SPA; the SPA detects which tenant realm to authenticate against from
--      window.location.hostname.
--   2. Platform host (PLATFORM_HOST, e.g. auth.mcp-mesh.io) — when the request
--      Host matches, route /api/* and /actuator/* to auth-manager. Root '/'
--      302-redirects to /admin/ (admin-ui lives at /admin/* now).
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
--
-- Order matters: check longer prefixes first (/admin/api/* before /admin/*).
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
    -- /admin/api/* and /admin/* are platform cross-cutting paths. They route
    -- to platform services (auth-manager + admin-ui) regardless of host. The
    -- admin-ui detects the tenant to authenticate against from
    -- window.location.hostname (e.g. app1.mcp-mesh.io → realm t-app1).
    -- Longest-prefix-first: /admin/api/* MUST be checked before /admin/*.
    --
    -- The "/admin" prefix is stripped before forwarding to auth-manager
    -- (the backend serves /api/v1/* at root). The admin-ui SPA sees its
    -- own assets at /admin/* (vite base='/admin/') so no rewrite needed there.
    if matcher.match("/admin/api/*", path) then
        local stripped = string.sub(path, 7)  -- drop "/admin"
        if stripped == "" then stripped = "/" end
        return config.platform_admin_api_target, "OPTIONAL", stripped
    end
    if matcher.match("/admin/*", path) then
        return config.platform_admin_ui_target, "OPTIONAL", nil
    end
    return nil, nil, nil
end

-- Platform-host routing. When Host == PLATFORM_HOST (after cross-cutting paths
-- have been considered), route by path prefix:
--   /            → 302 → /admin/
--   /api/*       → auth-manager
--   /actuator/*  → auth-manager
-- Everything else 404s; the admin-ui SPA lives under /admin/* (handled in the
-- cross-cutting match_platform block above).
-- Returns (backend, auth_mode) for path-routed responses, or nil if the
-- caller should treat the request as already-handled (e.g. an issued redirect).
local function match_platform_host(path)
    if matcher.match("/api/*", path) then
        return config.platform_admin_api_target, "OPTIONAL"
    end
    if matcher.match("/actuator/*", path) then
        return config.platform_admin_api_target, "OPTIONAL"
    end
    return nil, nil
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

-- 2. Platform host (auth.mcp-mesh.io) routing — auth-manager only.
-- Root path redirects to /admin/ (the SPA lives at /admin/* and is served
-- via the cross-cutting block above regardless of host).
if host and host == config.platform_host then
    if path == "/" or path == "" then
        return ngx.redirect("/admin/", 302)
    end
    local p_backend, p_auth = match_platform_host(path)
    if not p_backend then
        return fail(404, "no platform route for path: " .. path)
    end
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
