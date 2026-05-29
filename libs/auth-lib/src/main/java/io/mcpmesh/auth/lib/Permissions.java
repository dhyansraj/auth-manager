package io.mcpmesh.auth.lib;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Aggregates a JWT's UMA permissions across one or more resource-server
 * audiences (Keycloak client IDs) into a flat, normalized
 * {@code Set<String>} suitable for driving UI visibility AND for
 * {@code @PreAuthorize("hasAuthority(...)")} checks.
 *
 * <p>Each entry has the shape {@code RSNAME_SCOPE}, uppercased and with
 * spaces/dashes converted to underscores — e.g. an "Orders" resource with
 * a "view" scope becomes {@code ORDERS_VIEW}. This matches the convention
 * used by {@link io.mcpmesh.auth.lib.security.PermissionService} so a
 * consumer who already wrote {@code @PreAuthorize("hasAuthority('PERMISSION_ORDER_VIEW')")}
 * can keep using it; the {@code Permissions} helper is for the {@code /me}
 * endpoint where we want the raw permission strings without the
 * {@code PERMISSION_} prefix (UI side).
 *
 * <h2>Caching</h2>
 * Per-{@code (jwt.sub, audience-set-hash)} for {@value #DEFAULT_TTL_SECONDS}
 * seconds, via the injected {@link PermissionsCache}. Default impl is
 * {@link InMemoryPermissionsCache}; tenants who add
 * {@code spring-boot-starter-data-redis} to their pom get
 * {@code RedisPermissionsCache} automatically.
 *
 * <p>Since 0.3.1 this class no longer references Spring Data Redis directly
 * — the Redis dep stays truly optional at the classpath level even when
 * {@link AuthLibProperties.Cache#enabled()} is true.
 *
 * <h2>Failure handling</h2>
 * UMA failures are tolerated per-audience: a 403 (no policy / authz services
 * disabled for that client) is logged at DEBUG and that audience contributes
 * zero permissions. Only when every audience fails do we log at WARN.
 */
public class Permissions {

    private static final Logger log = LoggerFactory.getLogger(Permissions.class);

    static final long DEFAULT_TTL_SECONDS = 60L;
    private static final String CACHE_KEY_PREFIX = "perms:";

    private final AuthLibProperties props;
    private final RestTemplate restTemplate;
    private final PermissionsCache cache;
    private final Duration ttl;

    public Permissions(AuthLibProperties props, RestTemplate restTemplate,
                       PermissionsCache cache) {
        this(props, restTemplate, cache, Duration.ofSeconds(DEFAULT_TTL_SECONDS));
    }

    /** Package-private ctor used by tests to shrink/zero the TTL. */
    Permissions(AuthLibProperties props, RestTemplate restTemplate,
                PermissionsCache cache, Duration ttl) {
        this.props = props;
        this.restTemplate = restTemplate;
        this.cache = cache;
        this.ttl = ttl;
    }

    /**
     * Aggregate UMA permissions across all configured audiences (see
     * {@link AuthLibProperties#audiences()}). Returns the union as flat
     * uppercased {@code RSNAME_SCOPE} strings. Never returns {@code null};
     * an empty set means "no permissions visible (or none granted)".
     */
    public Set<String> allFor(Jwt jwt) {
        if (jwt == null) return Set.of();
        List<String> audiences = props.audiences();
        String cacheKey = cacheKey(jwt.getSubject(), audiences);

        if (props.cache().enabled()) {
            Set<String> cached = cache.read(cacheKey);
            if (cached != null) {
                log.debug("Permissions: cache hit sub={} audiences={}", jwt.getSubject(), audiences);
                return cached;
            }
        }

        Set<String> aggregated = new LinkedHashSet<>();
        int failures = 0;
        for (String audience : audiences) {
            try {
                aggregated.addAll(fetchForAudience(jwt, audience));
            } catch (HttpStatusCodeException e) {
                log.debug("Permissions: UMA call for audience={} returned {} — skipping",
                    audience, e.getStatusCode());
                failures++;
            } catch (RuntimeException e) {
                log.debug("Permissions: UMA call for audience={} failed: {} — skipping",
                    audience, e.toString());
                failures++;
            }
        }
        if (failures > 0 && failures == audiences.size()) {
            log.warn("Permissions: ALL {} UMA audience calls failed for sub={}",
                audiences.size(), jwt.getSubject());
        }

        Set<String> result = Collections.unmodifiableSet(aggregated);
        if (props.cache().enabled()) {
            cache.write(cacheKey, result, ttl);
        }
        return result;
    }

    /** Convenience: check a single normalized permission. */
    public boolean has(Jwt jwt, String permission) {
        return permission != null && allFor(jwt).contains(permission);
    }

    // ---- internals ---------------------------------------------------------

    private Set<String> fetchForAudience(Jwt jwt, String audience) {
        String endpoint = props.issuerUri() + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBearerAuth(jwt.getTokenValue());

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        body.add("audience", audience);
        body.add("response_mode", "permissions");

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        @SuppressWarnings("unchecked")
        List<Map<String, Object>> resources = restTemplate.postForObject(endpoint, entity, List.class);
        if (resources == null) return Set.of();

        Set<String> out = new LinkedHashSet<>();
        for (Map<String, Object> r : resources) {
            Object rsname = r.get("rsname");
            Object scopesObj = r.get("scopes");
            if (rsname == null || !(scopesObj instanceof List<?> scopes)) continue;
            for (Object s : scopes) {
                if (s == null) continue;
                out.add(normalize(String.valueOf(rsname) + "_" + s));
            }
        }
        return out;
    }

    private static String normalize(String raw) {
        return raw.trim()
            .toUpperCase(Locale.ROOT)
            .replace(' ', '_')
            .replace('-', '_');
    }

    private String cacheKey(String sub, List<String> audiences) {
        // Order audiences for a stable hash regardless of config ordering.
        List<String> sorted = new ArrayList<>(audiences);
        Collections.sort(sorted);
        return CACHE_KEY_PREFIX + (sub == null ? "anon" : sub) + ":" + sorted.hashCode();
    }
}
