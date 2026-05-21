-- matcher.lua
-- Path-pattern matching for routing rules.
--
-- Supported glob patterns (first match wins, caller iterates in order):
--   exact:           "/health"           matches "/health" only
--   prefix wildcard: "/api/*"            matches "/api", "/api/", "/api/anything"
--   catch-all:       "/*"                matches everything (must be last)
--
-- Query strings and trailing slashes beyond the pattern are not normalised --
-- nginx hands us ngx.var.uri which is already path-only.

local _M = {}

-- Returns true if path matches the rule's glob pattern.
function _M.match(pattern, path)
    if pattern == nil or path == nil then
        return false
    end

    if pattern == "/*" then
        return true
    end

    -- Prefix wildcard, e.g. "/api/*"
    local suffix_start = string.find(pattern, "/*", 1, true)
    if suffix_start and suffix_start == #pattern - 1 then
        local prefix = string.sub(pattern, 1, suffix_start - 1)  -- "/api"
        if prefix == "" then
            return true  -- pattern was just "/*" (handled above), but be defensive
        end
        if path == prefix then
            return true
        end
        if string.sub(path, 1, #prefix + 1) == prefix .. "/" then
            return true
        end
        return false
    end

    -- Exact match
    return pattern == path
end

-- Iterate rules in order; return first matching rule or nil.
-- rules is the array from the route:<slug> JSON.
function _M.find_rule(rules, path)
    if rules == nil then
        return nil
    end
    for i = 1, #rules do
        local rule = rules[i]
        if rule and _M.match(rule.path, path) then
            return rule
        end
    end
    return nil
end

return _M
