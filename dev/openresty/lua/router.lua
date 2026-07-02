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
local bff     = require "bff"

-- Sentinel backend returned by match_platform for BFF endpoints whose
-- handler runs entirely in Lua and never falls through to proxy_pass.
-- It tells the main flow "stop here, response already emitted".
local BFF_HANDLED = "__bff_handled__"

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
    -- iOS Universal Links / Android App Links verification files for native
    -- apps. Generated per-tenant by auth-manager (resolves tenant from the
    -- forwarded Host header). PUBLIC because Apple/Google fetch them
    -- anonymously; nil forwards the literal /.well-known/... URI unchanged.
    if path == "/.well-known/apple-app-site-association" then
        return config.platform_admin_api_target, "PUBLIC", nil
    end
    if path == "/.well-known/assetlinks.json" then
        return config.platform_admin_api_target, "PUBLIC", nil
    end
    -- BFF (cookie-based browser auth) endpoints. Underscore prefix so they
    -- cannot collide with tenant routes. Handled entirely in Lua except
    -- /_bff/me which mutates the request and forwards to admin-api.
    -- Longest-prefix-first: /_bff/* must be matched before /auth/*.
    if matcher.match("/_bff/*", path) then
        if path == "/_bff/login" then
            bff.handle_login()
            return BFF_HANDLED, "PUBLIC", nil
        end
        if path == "/_bff/callback" then
            bff.handle_callback()
            return BFF_HANDLED, "PUBLIC", nil
        end
        if path == "/_bff/logout" then
            bff.handle_logout()
            return BFF_HANDLED, "PUBLIC", nil
        end
        if path == "/_bff/backchannel-logout" then
            -- PUBLIC: called by KC (server-to-server, no cookies/Bearer).
            -- The handler validates the logout_token JWT structure + iss.
            bff.handle_backchannel_logout()
            return BFF_HANDLED, "PUBLIC", nil
        end
        if path == "/_bff/csrf" then
            bff.handle_csrf()
            return BFF_HANDLED, "PUBLIC", nil
        end
        if path == "/_bff/me" then
            local ok = bff.prepare_me_proxy()
            if not ok then
                return BFF_HANDLED, "PUBLIC", nil
            end
            -- Request URI is now /api/v1/me and Authorization is set.
            -- BFF_BEARER_INJECTED so enforce_auth does not strip the header.
            return config.platform_admin_api_target, "BFF_BEARER_INJECTED", "/api/v1/me"
        end
        return BFF_HANDLED, "PUBLIC", nil  -- unknown /_bff/* path; handler emits 404 if you add one
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
    -- The "/admin" prefix is stripped before forwarding upstream. Both
    -- services serve at root: auth-manager at /api/v1/*, admin-ui's nginx
    -- at /assets/* + /index.html. Vite's base='/admin/' only affects URLs
    -- emitted INTO index.html (so the browser asks for /admin/assets/...);
    -- the actual files in the image are still at /assets/..., so we MUST
    -- strip /admin before nginx tries to find them.
    if matcher.match("/admin/api/*", path) then
        local stripped = string.sub(path, 7)  -- drop "/admin"
        if stripped == "" then stripped = "/" end
        return config.platform_admin_api_target, "OPTIONAL", stripped
    end
    if matcher.match("/admin/*", path) then
        local stripped
        if path == "/admin" then
            stripped = "/"
        else
            stripped = string.sub(path, 7)  -- drop "/admin"
            if stripped == "" then stripped = "/" end
        end
        return config.platform_admin_ui_target, "OPTIONAL", stripped
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

local function enforce_auth(auth_mode, tenant, rule_opts)
    -- CORS preflight is unauthenticated BY SPEC: the browser sends an OPTIONS
    -- with Access-Control-Request-Method and never attaches credentials, so a
    -- REQUIRED 401 here would block every header-authenticated cross-origin
    -- request (e.g. fetch-based SSE from capacitor://localhost with an
    -- Authorization: Bearer). Let the preflight pass through unauthenticated so
    -- the backend's CORS layer answers it (204 + Access-Control-* headers); the
    -- actual method that follows still carries the Bearer and is gated normally
    -- by the branches below. Auth-neutral: a preflight grants nothing.
    if ngx.req.get_method() == "OPTIONS"
        and ngx.var.http_access_control_request_method ~= nil then
        ngx.req.clear_header("Authorization")  -- preflight carries none anyway
        return
    end
    -- BFF_BEARER_INJECTED: caller (match_platform for /_bff/me) has already
    -- proven the session and set Authorization: do nothing here, in
    -- particular do NOT strip the header.
    if auth_mode == "BFF_BEARER_INJECTED" then
        return
    end
    if auth_mode == "PUBLIC" then
        -- Drop any Authorization header so backends can't accidentally
        -- gate on it for a path the platform considers public.
        ngx.req.clear_header("Authorization")
        return
    end
    if auth_mode == "REQUIRED" then
        local hdr = ngx.var.http_authorization
        local cookie_authed = false
        if not hdr or hdr == "" then
            -- BFF cookie path: try to authenticate via bff_sid cookie. On
            -- success, Authorization is injected and CSRF is enforced for
            -- non-idempotent methods. On failure, drop through to 401.
            local ok = bff.try_inject_bearer_from_cookie()
            if ok then
                cookie_authed = true
                hdr = ngx.var.http_authorization
            end
        end
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
        if cookie_authed then
            -- Double-submit CSRF: only on cookie-authed requests. Bearer
            -- callers (CLI / m2m / native apps) are exempt -- knowing the
            -- token is itself proof of intent.
            --
            -- Per-rule opt-out: routes pointing at embedded third-party UIs
            -- (Redis Commander, Grafana, ...) can set bypassCsrf=true so the
            -- upstream's own session/CSRF model isn't double-gated by ours.
            -- Platform cross-cutting paths never pass rule_opts, so /admin/*
            -- and friends always enforce CSRF.
            if not (rule_opts and rule_opts.bypassCsrf) then
                local ok = bff.enforce_csrf_if_cookie_auth()
                if not ok then return end  -- response already emitted (403)
            end
        end
        return
    end
    -- OPTIONAL: pass through whatever was sent. If a session cookie is
    -- present, inject Authorization so upstream OPTIONAL code can still
    -- personalise (e.g. read claims.sub). CSRF NOT enforced on OPTIONAL.
    local hdr = ngx.var.http_authorization
    if not hdr or hdr == "" then
        bff.try_inject_bearer_from_cookie()
    end
end

-- ─── Main flow ───────────────────────────────────────────────────────────
local path = ngx.var.uri
local host = strip_port(ngx.var.http_host or ngx.var.host)

-- 1. Cross-cutting platform paths first.
local backend, auth_mode, rewritten = match_platform(path)
if backend then
    -- BFF endpoints fully handled in Lua (response already emitted).
    if backend == BFF_HANDLED then
        return ngx.exit(ngx.status or 200)
    end
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
-- bypassCsrf is decoded as boolean from JSON; cjson sets missing fields to
-- nil, which is falsy in the rule_opts check inside enforce_auth.
enforce_auth(rule.authMode, tenant, { bypassCsrf = rule.bypassCsrf })

-- 6b. Per-rule permission gating. Only enforced when the rule actually
-- declares one AND auth was REQUIRED (so we have a JWT to inspect).
-- enforce_auth would have already short-circuited on missing/invalid auth.
if rule.authMode == "REQUIRED"
   and type(rule.requiredPermission) == "string"
   and rule.requiredPermission ~= "" then
    if not bff.has_permission(rule.requiredPermission) then
        ngx.status = 403
        ngx.header.content_type = "application/json"
        ngx.say(cjson.encode({
            error = "forbidden",
            message = "missing required permission: " .. rule.requiredPermission
        }))
        return ngx.exit(403)
    end
end

-- 6c. Per-rule prefix strip. For embedded third-party apps mounted under a
-- subpath whose internal links assume root (e.g. Redis Commander at
-- /ops/redis/* whose XHRs go to /apiv2/...). If the configured prefix is
-- not actually a prefix of the matched path, proxy as-is (operator
-- misconfig -- the matcher already let this rule win on a longer prefix
-- match, so a rewrite that breaks the path would be worse than a no-op).
-- type() guard handles cjson.null when the JSON omits the field or sends null.
if type(rule.stripPrefix) == "string" and rule.stripPrefix ~= "" then
    local stripped
    if path == rule.stripPrefix or path == rule.stripPrefix .. "/" then
        stripped = "/"
    elseif path:sub(1, #rule.stripPrefix + 1) == rule.stripPrefix .. "/" then
        stripped = path:sub(#rule.stripPrefix + 1)  -- keeps leading slash
    else
        stripped = path  -- prefix doesn't match; leave URI alone
    end
    if stripped ~= path then
        ngx.req.set_uri(stripped, false)  -- false = don't re-match locations
    end
end

-- 6d. Per-rule body-size cap. Reject oversize bodies up front so we don't
-- ship a useless multi-MB upload to the backend just for it to 413 (or
-- worse, OOM). Only checked on body-carrying methods AND only when the
-- client sent a Content-Length header — chunked uploads (no Content-Length)
-- fall through to nginx's client_max_body_size 100m backstop.
-- type() guard handles cjson.null / missing field; falls back to the
-- platform-wide default (ROUTE_DEFAULT_MAX_BODY_MB, default 25 MB).
local method = ngx.req.get_method()
if method == "POST" or method == "PUT" or method == "PATCH" or method == "DELETE" then
    local cl = tonumber(ngx.var.http_content_length)
    if cl then
        local cap_mb = rule.maxBodyMb
        if type(cap_mb) ~= "number" then
            cap_mb = config.route_default_max_body_mb
        end
        local cap_bytes = cap_mb * 1024 * 1024
        if cl > cap_bytes then
            ngx.status = 413
            ngx.header.content_type = "application/json"
            ngx.say(cjson.encode({
                error   = "payload_too_large",
                message = "Request body " .. cl .. " bytes exceeds route limit "
                          .. cap_bytes .. " bytes (" .. cap_mb .. " MB)"
            }))
            return ngx.exit(413)
        end
    end
end

-- 7. Proxy
ngx.var.route_backend = resolved
