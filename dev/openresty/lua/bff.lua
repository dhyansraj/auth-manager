-- bff.lua
-- Backend-For-Frontend module: cookie-based browser auth at the edge.
-- Coexists with the existing PKCE/Bearer flow.
--
-- Endpoints (all under /_bff/ prefix, underscore so it cannot collide
-- with any tenant route):
--   GET  /_bff/login    -- start PKCE, set tx cookie, 302 to KC /auth
--   GET  /_bff/callback -- KC redirects back here; exchange code for tokens,
--                         create session, set HttpOnly bff_sid + bff_csrf,
--                         302 to original landing page.
--   POST /_bff/logout   -- delete the Redis session, clear cookies, 204.
--   GET  /_bff/me       -- proxy to upstream /api/v1/me with the session's
--                         access_token injected as Bearer.
--   GET  /_bff/csrf     -- return {"csrfToken":"..."} (issuing a cookie if
--                         missing so SPAs can populate the X-CSRF-Token
--                         header before any state-changing call).
--
-- Cookie-to-bearer injection lives in router.lua (enforce_auth) -- this
-- module exposes a `inject_bearer_from_cookie(sid)` helper for that.
--
-- Token endpoint exchanges are done via ngx.location.capture into the
-- internal /_bff_int/kc_token location (proxy_pass to KC). Avoids the
-- lua-resty-http dependency.

local cjson  = require "cjson.safe"
local rclient = require "redis_client"
local random  = require "resty.random"
local sha256  = require "resty.sha256"
local str     = require "resty.string"

local _M = {}

-- ─── Tunables ────────────────────────────────────────────────────────────

-- KC client id for the platform/admin SPA. Same id is registered in every
-- realm by the bootstrap (realm-per-tenant convention).
local CLIENT_ID = "usermanagement"

-- Session TTL (seconds). Mirrors KC's default 30min refresh-token lifetime.
-- Whole-key EXPIRE so an idle browser eventually re-auths.
local SESSION_TTL = 1800

-- Short-lived tx key TTL (login → callback round-trip).
local TX_TTL = 300

-- Refresh the access_token when it has <= REFRESH_WINDOW seconds left.
local REFRESH_WINDOW = 30

-- Cookie names. Keep them short, prefixed, and stable across releases.
local COOKIE_SID  = "bff_sid"
local COOKIE_CSRF = "bff_csrf"

-- Methods that require CSRF protection when authenticated via cookie.
local UNSAFE_METHODS = { POST = true, PUT = true, PATCH = true, DELETE = true }

-- ─── Small helpers ───────────────────────────────────────────────────────

local function log_err(...)
    ngx.log(ngx.ERR, "[bff] ", ...)
end

local function log_info(...)
    ngx.log(ngx.INFO, "[bff] ", ...)
end

local function json_response(status, body)
    ngx.status = status
    ngx.header.content_type = "application/json"
    ngx.say(cjson.encode(body))
    return ngx.exit(status)
end

-- base64url(no padding) for the result of ngx.encode_base64(bytes).
local function b64url(bytes)
    if not bytes then return nil end
    local s = ngx.encode_base64(bytes)
    s = s:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
    return s
end

-- 32 bytes of cryptographically strong randomness, base64url-encoded
-- (~43 chars). resty.random's second arg=true forces /dev/urandom.
local function random_token()
    local bytes = random.bytes(32, true)
    return b64url(bytes)
end

-- PKCE: code_challenge = base64url(SHA256(code_verifier))
local function pkce_challenge(verifier)
    local sha = sha256:new()
    sha:update(verifier)
    return b64url(sha:final())
end

-- urlencode a plain string for query strings.
local function urlencode(s)
    if s == nil then return "" end
    return ngx.escape_uri(s)
end

-- Strip ":port" off Host.
local function strip_port(host)
    if not host then return nil end
    local colon = string.find(host, ":", 1, true)
    if colon then return string.sub(host, 1, colon - 1) end
    return host
end

-- Derive KC realm from Host using the same convention as admin-ui's
-- createOidcConfig: auth.mcp-mesh.io → 'dev'; otherwise t-<first-label>.
-- localhost in dev maps to 'dev'.
local function realm_from_host(host)
    if not host or host == "" then return "dev" end
    if host == "auth.mcp-mesh.io" then return "dev" end
    if host == "localhost" or host == "127.0.0.1" then return "dev" end

    -- Authoritative source: Redis host:<host> hash, populated when a tenant
    -- registers a hostname via auth-manager's tenant-create / routes API.
    -- This decouples realm name from hostname structure — tenant slug 'safesound'
    -- can own hostname 'safeandsoundhouses.com' and the realm is still
    -- 't-safesound', not 't-safeandsoundhouses'.
    local red, rerr = rclient.open()
    if red then
        local tenant, lerr = rclient.hget(red, "host:" .. host, "tenant")
        rclient.close(red)
        if not lerr and tenant and tenant ~= ngx.null and tenant ~= "" then
            return "t-" .. tenant
        end
        if lerr then
            ngx.log(ngx.WARN, "realm_from_host: redis hget host:", host, " failed: ", lerr, " — falling back to hostname split")
        end
    else
        ngx.log(ngx.WARN, "realm_from_host: redis connect failed: ", rerr, " — falling back to hostname split")
    end

    -- Fallback: legacy convention <slug>.<zone> → t-<slug>. Preserves dev
    -- workflows where a hostname is hit before being registered in Redis.
    local first = string.match(host, "^([^.]+)")
    if not first or first == "" then return "dev" end
    ngx.log(ngx.WARN, "realm_from_host: no Redis mapping for host:", host, " — using fallback realm t-", first)
    return "t-" .. first
end

-- Build the issuer URL (origin + /auth/realms/<realm>). MUST always use the
-- canonical KC public host (auth.mcp-mesh.io), NOT the calling host —
-- otherwise KC sets session cookies on the calling host's domain, then
-- after the Google IdP round-trip the browser lands on auth.mcp-mesh.io
-- (KC_HOSTNAME) and the cookies aren't sent → cookie_not_found.
local KC_BROWSER_HOST = "auth.mcp-mesh.io"
local function browser_authority(host, realm)
    return "https://" .. KC_BROWSER_HOST .. "/auth/realms/" .. realm
end

-- ─── Cookie parsing / building ───────────────────────────────────────────

-- Parse the Cookie header into a flat table. Last value wins for dupes
-- (browsers don't normally send dupes; defensive).
local function parse_cookies()
    local hdr = ngx.var.http_cookie
    local out = {}
    if not hdr then return out end
    for kv in string.gmatch(hdr, "([^;]+)") do
        local k, v = string.match(kv, "^%s*([^=]+)=(.*)$")
        if k and v then
            out[k] = v
        end
    end
    return out
end

-- Build a Set-Cookie value. opts table:
--   max_age (number, seconds; 0 to delete; nil = session cookie)
--   http_only (bool)
--   secure (bool)
--   same_site ("Strict"|"Lax"|"None")
--   path (string; defaults to "/")
local function build_cookie(name, value, opts)
    opts = opts or {}
    local parts = { name .. "=" .. (value or "") }
    parts[#parts + 1] = "Path=" .. (opts.path or "/")
    if opts.max_age ~= nil then
        parts[#parts + 1] = "Max-Age=" .. tostring(opts.max_age)
    end
    if opts.http_only then parts[#parts + 1] = "HttpOnly" end
    if opts.secure    then parts[#parts + 1] = "Secure" end
    if opts.same_site then parts[#parts + 1] = "SameSite=" .. opts.same_site end
    return table.concat(parts, "; ")
end

-- Append one Set-Cookie header without overwriting existing ones.
local function add_set_cookie(value)
    local existing = ngx.header["Set-Cookie"]
    if existing == nil then
        ngx.header["Set-Cookie"] = value
    elseif type(existing) == "table" then
        existing[#existing + 1] = value
        ngx.header["Set-Cookie"] = existing
    else
        ngx.header["Set-Cookie"] = { existing, value }
    end
end

local function clear_session_cookies()
    add_set_cookie(build_cookie(COOKIE_SID, "", {
        max_age = 0, http_only = true, secure = true, same_site = "Strict",
    }))
    add_set_cookie(build_cookie(COOKIE_CSRF, "", {
        max_age = 0, http_only = false, secure = true, same_site = "Strict",
    }))
end

-- ─── Redis session helpers ───────────────────────────────────────────────

-- Returns (session_table, err). session_table is nil when key missing.
local function load_session(sid)
    if not sid or sid == "" then return nil, nil end
    local red, err = rclient.open()
    if not red then return nil, err end
    local res, herr = red:hgetall("bff:session:" .. sid)
    rclient.close(red)
    if herr then return nil, herr end
    if res == ngx.null or not res or #res == 0 then return nil, nil end
    -- hgetall returns a flat array {k1,v1,k2,v2,...}; convert.
    local out = {}
    for i = 1, #res, 2 do out[res[i]] = res[i + 1] end
    if not out.access_token then return nil, nil end
    return out, nil
end

local function delete_session(sid)
    if not sid or sid == "" then return end
    local red, err = rclient.open()
    if not red then log_err("delete_session: redis open failed: ", err); return end
    red:del("bff:session:" .. sid)
    rclient.close(red)
end

local function save_session(sid, fields, ttl)
    local red, err = rclient.open()
    if not red then return false, err end
    -- Lay out args for HSET: key, k1, v1, k2, v2 ...
    local args = { "bff:session:" .. sid }
    for k, v in pairs(fields) do
        if v ~= nil then
            args[#args + 1] = k
            args[#args + 1] = tostring(v)
        end
    end
    local _, herr = red:hset(unpack(args))
    if herr then rclient.close(red); return false, herr end
    red:expire("bff:session:" .. sid, ttl)
    rclient.close(red)
    return true, nil
end

local function save_tx(state, fields)
    local red, err = rclient.open()
    if not red then return false, err end
    local args = { "bff:tx:" .. state }
    for k, v in pairs(fields) do
        args[#args + 1] = k
        args[#args + 1] = tostring(v)
    end
    local _, herr = red:hset(unpack(args))
    if herr then rclient.close(red); return false, herr end
    red:expire("bff:tx:" .. state, TX_TTL)
    rclient.close(red)
    return true, nil
end

local function load_and_delete_tx(state)
    if not state or state == "" then return nil end
    local red, err = rclient.open()
    if not red then return nil, err end
    local res, herr = red:hgetall("bff:tx:" .. state)
    if herr then rclient.close(red); return nil, herr end
    red:del("bff:tx:" .. state)
    rclient.close(red)
    if res == ngx.null or not res or #res == 0 then return nil, nil end
    local out = {}
    for i = 1, #res, 2 do out[res[i]] = res[i + 1] end
    return out, nil
end

-- ─── KC token endpoint via internal subrequest ───────────────────────────

-- POST x-www-form-urlencoded to /_bff_int/kc_token/<realm>/token.
-- Returns (decoded_json, status, err).
local function kc_token_call(realm, form)
    local body_parts = {}
    for k, v in pairs(form) do
        body_parts[#body_parts + 1] = urlencode(k) .. "=" .. urlencode(v)
    end
    local body = table.concat(body_parts, "&")
    local res = ngx.location.capture("/_bff_int/kc_token/" .. realm .. "/token", {
        method = ngx.HTTP_POST,
        body = body,
    })
    if not res then return nil, 502, "subrequest failed" end
    if res.status >= 500 then
        return nil, res.status, "kc token endpoint error: " .. (res.body or "")
    end
    local decoded, derr = cjson.decode(res.body or "")
    if not decoded then
        return nil, res.status, "decode failed: " .. tostring(derr)
    end
    return decoded, res.status, nil
end

-- ─── Endpoint: GET /_bff/login ───────────────────────────────────────────

function _M.handle_login()
    if ngx.req.get_method() ~= "GET" then
        return json_response(405, { error = "method_not_allowed" })
    end
    local host = strip_port(ngx.var.http_host or ngx.var.host)
    if not host then return json_response(400, { error = "missing_host" }) end
    local realm = realm_from_host(host)

    -- Build redirect_back from ?redirect_back= query (the SPA convention,
    -- matches bffClient.ts's signinRedirect helper). Falls back to "/" when
    -- absent. Also accept legacy ?redirect= for any older callers.
    local args = ngx.req.get_uri_args() or {}
    local redirect_back = args.redirect_back or args.redirect or "/"
    -- Defensive: redirect_back must start with "/" to avoid open-redirect.
    if type(redirect_back) ~= "string"
       or redirect_back == ""
       or redirect_back:sub(1, 1) ~= "/" then
        redirect_back = "/"
    end

    local code_verifier = random_token()         -- ~43 chars, b64url
    local state         = random_token()
    local nonce         = random_token()
    local challenge     = pkce_challenge(code_verifier)

    local ok, terr = save_tx(state, {
        code_verifier = code_verifier,
        nonce         = nonce,
        redirect_back = redirect_back,
        realm         = realm,
        created_at    = ngx.time(),
    })
    if not ok then
        log_err("login: save_tx failed: ", terr)
        return json_response(502, { error = "tx_save_failed" })
    end

    local authority   = browser_authority(host, realm)
    local redirect_uri = "https://" .. host .. "/_bff/callback"
    local q = table.concat({
        "response_type=code",
        "client_id=" .. urlencode(CLIENT_ID),
        "redirect_uri=" .. urlencode(redirect_uri),
        "scope=" .. urlencode("openid profile email"),
        "state=" .. urlencode(state),
        "nonce=" .. urlencode(nonce),
        "code_challenge=" .. urlencode(challenge),
        "code_challenge_method=S256",
    }, "&")
    local kc_url = authority .. "/protocol/openid-connect/auth?" .. q
    return ngx.redirect(kc_url, 302)
end

-- ─── Endpoint: GET /_bff/callback ────────────────────────────────────────

function _M.handle_callback()
    if ngx.req.get_method() ~= "GET" then
        return json_response(405, { error = "method_not_allowed" })
    end
    local args = ngx.req.get_uri_args() or {}
    local code = args.code
    local state = args.state
    if not code or code == "" or not state or state == "" then
        return json_response(400, { error = "missing_code_or_state" })
    end

    local tx, terr = load_and_delete_tx(state)
    if terr then
        log_err("callback: load_tx failed: ", terr)
        return json_response(502, { error = "tx_lookup_failed" })
    end
    if not tx then
        return json_response(400, { error = "invalid_state" })
    end

    local host = strip_port(ngx.var.http_host or ngx.var.host)
    local realm = tx.realm or realm_from_host(host)
    local redirect_uri = "https://" .. host .. "/_bff/callback"

    local tok, status, kerr = kc_token_call(realm, {
        grant_type    = "authorization_code",
        code          = code,
        redirect_uri  = redirect_uri,
        client_id     = CLIENT_ID,
        code_verifier = tx.code_verifier or "",
    })
    if not tok then
        log_err("callback: token exchange failed (status=", status, "): ", kerr)
        return json_response(502, { error = "token_exchange_failed" })
    end
    if status ~= 200 or not tok.access_token then
        log_err("callback: KC rejected code: ", tok.error or "(unknown)", " desc=", tok.error_description or "")
        return json_response(400, { error = "code_exchange_rejected", kc_error = tok.error })
    end

    -- Derive sub/email from id_token without verifying signature (KC just
    -- minted it; upstream services validate signature on their own calls).
    local sub, email = "", ""
    if tok.id_token then
        local parts = {}
        for p in string.gmatch(tok.id_token, "[^.]+") do parts[#parts + 1] = p end
        if #parts >= 2 then
            -- JWT payload is base64url; ngx.decode_base64 expects standard.
            local payload = parts[2]:gsub("-", "+"):gsub("_", "/")
            local pad = #payload % 4
            if pad > 0 then payload = payload .. string.rep("=", 4 - pad) end
            local raw = ngx.decode_base64(payload)
            if raw then
                local claims = cjson.decode(raw)
                if claims then
                    sub = claims.sub or ""
                    email = claims.email or ""
                end
            end
        end
    end

    -- Extract KC's session id (`sid` claim) from the access_token. This is
    -- the key we use to look up sessions for back-channel logout: when KC
    -- POSTs to /_bff/backchannel-logout the logout_token's `sid` claim
    -- matches whatever we store here. KC 26 emits `sid` in access tokens by
    -- default; if absent we just store "" and back-channel match will fail
    -- (logged) but local cookie logout still works.
    local kc_sid = ""
    if tok.access_token then
        local parts = {}
        for p in string.gmatch(tok.access_token, "[^.]+") do parts[#parts + 1] = p end
        if #parts >= 2 then
            local payload = parts[2]:gsub("-", "+"):gsub("_", "/")
            local pad = #payload % 4
            if pad > 0 then payload = payload .. string.rep("=", 4 - pad) end
            local raw = ngx.decode_base64(payload)
            if raw then
                local claims = cjson.decode(raw)
                if claims then
                    kc_sid = claims.sid or ""
                end
            end
        end
    end

    local sid       = random_token()
    local csrf      = random_token()
    local now       = ngx.time()
    local expires_in = tonumber(tok.expires_in) or 300
    local expires_at = now + expires_in

    local ok, serr = save_session(sid, {
        access_token  = tok.access_token,
        refresh_token = tok.refresh_token or "",
        id_token      = tok.id_token or "",
        expires_at    = expires_at,
        sub           = sub,
        email         = email,
        realm         = realm,
        csrf          = csrf,
        sid           = kc_sid,
        created_at    = now,
        last_seen_at  = now,
    }, SESSION_TTL)
    if not ok then
        log_err("callback: save_session failed: ", serr)
        return json_response(502, { error = "session_save_failed" })
    end

    add_set_cookie(build_cookie(COOKIE_SID, sid, {
        max_age = SESSION_TTL, http_only = true, secure = true, same_site = "Strict",
    }))
    add_set_cookie(build_cookie(COOKIE_CSRF, csrf, {
        max_age = SESSION_TTL, http_only = false, secure = true, same_site = "Strict",
    }))

    local back = tx.redirect_back or "/"
    log_info("callback: session created sid=", sid:sub(1, 8), "... sub=", sub, " realm=", realm)
    return ngx.redirect(back, 302)
end

-- ─── Endpoint: POST /_bff/logout ─────────────────────────────────────────
--
-- Two-step logout:
--   1. POST to KC's /protocol/openid-connect/logout with the session's
--      refresh_token. This terminates KC's SSO session and triggers
--      back-channel logout to every other client (sibling PKCE SPAs).
--   2. Delete the Redis session + clear cookies. Done unconditionally —
--      if KC's end-session call fails we still want local cleanup so the
--      user is at least signed out HERE.
function _M.handle_logout()
    if ngx.req.get_method() ~= "POST" then
        return json_response(405, { error = "method_not_allowed" })
    end
    local cookies = parse_cookies()
    local sid = cookies[COOKIE_SID]
    if sid and sid ~= "" then
        local sess = load_session(sid)
        if sess and sess.refresh_token and sess.refresh_token ~= "" and sess.realm and sess.realm ~= "" then
            -- KC end-session via internal subrequest. KC returns 204 on
            -- success. Best-effort: log and continue on failure.
            local body = "client_id=" .. urlencode(CLIENT_ID)
                .. "&refresh_token=" .. urlencode(sess.refresh_token)
            local res = ngx.location.capture("/_bff_int/kc_logout/" .. sess.realm, {
                method = ngx.HTTP_POST,
                body = body,
            })
            if not res then
                log_err("logout: KC end-session subrequest failed (proceeding with local cleanup)")
            elseif res.status ~= 204 and res.status ~= 200 then
                log_err("logout: KC end-session returned ", res.status,
                    " body=", (res.body or ""):sub(1, 200),
                    " (proceeding with local cleanup)")
            else
                log_info("logout: KC SSO session terminated sid=", sid:sub(1, 8))
            end
        end
        delete_session(sid)
    end
    clear_session_cookies()
    ngx.status = 204
    return ngx.exit(204)
end

-- ─── Endpoint: POST /_bff/backchannel-logout ─────────────────────────────
--
-- Called by Keycloak when an SSO session ends through some OTHER path
-- (e.g. a sibling PKCE SPA navigated to KC's end-session, or a session
-- admin-revoke). KC POSTs `logout_token=<JWT>` form-encoded; the JWT's
-- `sid` claim identifies the KC session whose BFF cookie sessions we now
-- need to purge.
--
-- We do NOT do full JWT signature verification here — proper JWKS lookup
-- would require lua-resty-http + caching. Instead we (1) parse structure,
-- (2) check iss is a KC realm under our public KC host, (3) require sid
-- present. The endpoint is only reachable from KC's own outbound request
-- (KC knows the URL because we configured backchannel.logout.url on the
-- client) and the worst case of a forged call is purging a session we
-- would have purged anyway when its refresh_token expired.
function _M.handle_backchannel_logout()
    if ngx.req.get_method() ~= "POST" then
        return json_response(405, { error = "method_not_allowed" })
    end
    ngx.req.read_body()
    local args = ngx.req.get_post_args() or {}
    local logout_token = args.logout_token
    if not logout_token or logout_token == "" then
        return json_response(400, { error = "missing_logout_token" })
    end

    -- Split on "." — JWS compact serialization is header.payload.signature.
    local parts = {}
    for p in string.gmatch(logout_token, "[^.]+") do parts[#parts + 1] = p end
    if #parts ~= 3 then
        return json_response(400, { error = "malformed_jwt" })
    end

    -- base64url decode the payload (convert -/_ → +//, pad to multiple of 4).
    local payload_b64 = parts[2]:gsub("-", "+"):gsub("_", "/")
    local pad = #payload_b64 % 4
    if pad > 0 then payload_b64 = payload_b64 .. string.rep("=", 4 - pad) end
    local payload_json = ngx.decode_base64(payload_b64)
    if not payload_json then
        return json_response(400, { error = "bad_payload_b64" })
    end
    local payload, derr = cjson.decode(payload_json)
    if not payload then
        log_err("backchannel_logout: payload decode failed: ", derr)
        return json_response(400, { error = "bad_payload_json" })
    end

    local iss = payload.iss or ""
    local kc_sid = payload.sid or ""
    if not iss:match("^https://" .. KC_BROWSER_HOST:gsub("%.", "%%.") .. "/auth/realms/") then
        log_err("backchannel_logout: bad iss=", iss)
        return json_response(400, { error = "invalid_iss" })
    end
    if kc_sid == "" then
        log_err("backchannel_logout: missing sid claim")
        return json_response(400, { error = "missing_sid" })
    end

    -- SCAN bff:session:* and purge entries whose `sid` field matches. SCAN
    -- is O(N) over the keyspace; for the current single-realm dev scale
    -- (<1000 sessions) this is fine. If sessions grow large, replace with
    -- a Redis SET index keyed `bff:kcsid:<sid>` populated at callback time.
    local red, rerr = rclient.open()
    if not red then
        log_err("backchannel_logout: redis open failed: ", rerr)
        return json_response(502, { error = "redis_unreachable" })
    end
    local cursor = "0"
    local purged = 0
    repeat
        local res, serr = red:scan(cursor, "MATCH", "bff:session:*", "COUNT", 100)
        if not res or res == ngx.null then
            log_err("backchannel_logout: scan failed: ", serr)
            break
        end
        cursor = res[1]
        local keys = res[2] or {}
        for _, key in ipairs(keys) do
            local session_sid, herr = red:hget(key, "sid")
            if herr then
                log_err("backchannel_logout: hget ", key, " failed: ", herr)
            elseif session_sid and session_sid ~= ngx.null and session_sid == kc_sid then
                red:del(key)
                purged = purged + 1
            end
        end
    until cursor == "0"
    rclient.close(red)

    log_info("backchannel_logout: purged ", purged, " sessions for kc_sid=", kc_sid)
    -- Per OIDC back-channel logout spec, return 200 with no body even when
    -- no matching session was found (the call is idempotent).
    return json_response(200, { purged = purged })
end

-- ─── Endpoint: GET /_bff/csrf ────────────────────────────────────────────

function _M.handle_csrf()
    if ngx.req.get_method() ~= "GET" then
        return json_response(405, { error = "method_not_allowed" })
    end
    local cookies = parse_cookies()
    local sid = cookies[COOKIE_SID]
    if not sid or sid == "" then
        return json_response(401, { error = "no_session" })
    end
    local sess, serr = load_session(sid)
    if serr then
        log_err("csrf: load_session failed: ", serr)
        return json_response(502, { error = "session_lookup_failed" })
    end
    if not sess then
        clear_session_cookies()
        return json_response(401, { error = "no_session" })
    end
    local csrf = sess.csrf
    if not csrf or csrf == "" then
        -- Should never happen post-callback but be defensive.
        csrf = random_token()
        save_session(sid, { csrf = csrf }, SESSION_TTL)
    end
    -- (Re-)set the cookie so a SPA that lost it can recover.
    add_set_cookie(build_cookie(COOKIE_CSRF, csrf, {
        max_age = SESSION_TTL, http_only = false, secure = true, same_site = "Strict",
    }))
    return json_response(200, { csrfToken = csrf })
end

-- ─── Endpoint: GET /_bff/me ──────────────────────────────────────────────
-- Returns the upstream /api/v1/me response with the session's access_token
-- injected as Bearer. Handled by setting Authorization, rewriting URI to
-- /api/v1/me, and forwarding to the platform admin API backend via
-- proxy_pass (caller in router.lua sets ngx.var.route_backend).

-- Returns (ok, status_code, err_body). ok=true means router should let the
-- normal proxy_pass flow take over (URI + Authorization already mutated).
function _M.prepare_me_proxy()
    if ngx.req.get_method() ~= "GET" then
        json_response(405, { error = "method_not_allowed" })
        return false
    end
    local cookies = parse_cookies()
    local sid = cookies[COOKIE_SID]
    if not sid or sid == "" then
        json_response(401, { error = "no_session" })
        return false
    end
    local sess, serr = load_session(sid)
    if serr then
        log_err("me: load_session failed: ", serr)
        json_response(502, { error = "session_lookup_failed" })
        return false
    end
    if not sess then
        clear_session_cookies()
        json_response(401, { error = "no_session" })
        return false
    end

    -- Silent refresh if we're inside the window.
    local at = _M.maybe_refresh(sid, sess)
    if not at then
        -- Refresh failed; session deleted, cookies cleared inside.
        json_response(401, { error = "refresh_failed" })
        return false
    end

    ngx.req.set_header("Authorization", "Bearer " .. at)
    -- Forward upstream as /api/v1/me. The router will set route_backend
    -- to the platform admin API.
    ngx.req.set_uri("/api/v1/me", false)
    return true
end

-- ─── Refresh-token silent renewal ────────────────────────────────────────

-- Returns the (possibly refreshed) access_token, or nil on failure (in
-- which case the session has been deleted and cookies cleared).
function _M.maybe_refresh(sid, sess)
    local expires_at = tonumber(sess.expires_at) or 0
    local now = ngx.time()
    if expires_at > now + REFRESH_WINDOW then
        return sess.access_token
    end
    if not sess.refresh_token or sess.refresh_token == "" then
        log_err("refresh: no refresh_token in session sid=", sid:sub(1, 8))
        delete_session(sid)
        clear_session_cookies()
        return nil
    end
    local realm = sess.realm or realm_from_host(strip_port(ngx.var.http_host or ngx.var.host))
    local tok, status, kerr = kc_token_call(realm, {
        grant_type    = "refresh_token",
        refresh_token = sess.refresh_token,
        client_id     = CLIENT_ID,
    })
    if not tok then
        log_err("refresh: kc subrequest failed status=", status, " err=", kerr)
        delete_session(sid)
        clear_session_cookies()
        return nil
    end
    if status ~= 200 or not tok.access_token then
        log_err("refresh: KC rejected: ", tok.error or "(unknown)")
        delete_session(sid)
        clear_session_cookies()
        return nil
    end
    local new_expires_in = tonumber(tok.expires_in) or 300
    save_session(sid, {
        access_token  = tok.access_token,
        refresh_token = tok.refresh_token or sess.refresh_token,
        id_token      = tok.id_token or sess.id_token or "",
        expires_at    = now + new_expires_in,
        last_seen_at  = now,
    }, SESSION_TTL)
    log_info("refresh: rotated access_token sid=", sid:sub(1, 8))
    return tok.access_token
end

-- ─── Cookie → Bearer injection (called from router.enforce_auth) ─────────
--
-- Reads bff_sid; on hit, refreshes if needed and injects Authorization.
-- Returns (authed, sess_or_nil): authed=true means a Bearer was injected.
-- authed=false with sess=nil means no session cookie or invalid; caller
-- decides whether that's a 401 (REQUIRED) or a pass-through (OPTIONAL).
function _M.try_inject_bearer_from_cookie()
    local cookies = parse_cookies()
    local sid = cookies[COOKIE_SID]
    if not sid or sid == "" then return false, nil end
    local sess, serr = load_session(sid)
    if serr then
        log_err("inject_bearer: load_session failed: ", serr)
        return false, nil
    end
    if not sess then
        clear_session_cookies()
        return false, nil
    end
    local at = _M.maybe_refresh(sid, sess)
    if not at then return false, nil end
    ngx.req.set_header("Authorization", "Bearer " .. at)
    return true, sess
end

-- ─── CSRF enforcement (called from router.enforce_auth) ─────────────────
--
-- Returns true if the request passes CSRF (or doesn't need it). When false
-- the caller should NOT proceed; this function has already emitted a 403.
function _M.enforce_csrf_if_cookie_auth()
    local method = ngx.req.get_method()
    if not UNSAFE_METHODS[method] then return true end
    local cookies = parse_cookies()
    local sent = ngx.var.http_x_csrf_token
    local cookie_csrf = cookies[COOKIE_CSRF]
    if not cookie_csrf or cookie_csrf == "" or not sent or sent == "" or sent ~= cookie_csrf then
        json_response(403, { error = "csrf_mismatch" })
        return false
    end
    return true
end

-- ─── Permission check (called from router.lua after enforce_auth) ───────
--
-- Returns true iff `perm_id` appears in the caller's JWT (Authorization
-- header), checking both resource_access.<client>.roles[] (per-client) and
-- realm_access.roles[] (realm-level). The header is expected to have been
-- set by either an upstream Bearer client or try_inject_bearer_from_cookie.
--
-- No signature verification is performed: upstream services validate the
-- signature on their own calls and the router treats the JWT as truth for
-- the purpose of authz gating. The Authorization header itself is only
-- considered present after enforce_auth (REQUIRED) succeeded, so any
-- forged claim would have had to round-trip through KC's signed issuance.
function _M.has_permission(perm_id)
    if not perm_id or perm_id == "" then return true end
    local hdr = ngx.var.http_authorization
    if not hdr or hdr == "" then return false end
    local token = hdr:gsub("^Bearer ", "")
    local _, payload_b64 = token:match("^([^.]+)%.([^.]+)%.(.+)$")
    if not payload_b64 then return false end
    -- base64url -> base64 + pad
    payload_b64 = payload_b64:gsub("-", "+"):gsub("_", "/")
    local pad = #payload_b64 % 4
    if pad > 0 then payload_b64 = payload_b64 .. string.rep("=", 4 - pad) end
    local payload_json = ngx.decode_base64(payload_b64)
    if not payload_json then return false end
    local payload = cjson.decode(payload_json)
    if not payload then return false end
    if payload.resource_access then
        for _, client in pairs(payload.resource_access) do
            if type(client) == "table" and client.roles then
                for _, role in ipairs(client.roles) do
                    if role == perm_id then return true end
                end
            end
        end
    end
    if payload.realm_access and payload.realm_access.roles then
        for _, role in ipairs(payload.realm_access.roles) do
            if role == perm_id then return true end
        end
    end
    return false
end

-- ─── Constants exposed to router.lua ────────────────────────────────────
_M.COOKIE_SID  = COOKIE_SID
_M.COOKIE_CSRF = COOKIE_CSRF

return _M
