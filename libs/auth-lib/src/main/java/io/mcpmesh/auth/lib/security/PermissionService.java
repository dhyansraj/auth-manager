package io.mcpmesh.auth.lib.security;

import io.mcpmesh.auth.lib.AuthLibProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

/**
 * Fetches a user's permissions from Keycloak's UMA permission endpoint and
 * returns them as Spring Security {@link GrantedAuthority} instances named
 * {@code PERMISSION_<RESOURCE>_<SCOPE>}.
 *
 * <p>Caching: if a {@link StringRedisTemplate} bean is present AND the cache
 * is enabled, results are cached under {@code authlib:perms:<jti>} with the
 * configured TTL. Cached permissions are pre-joined newline-separated.
 */
public class PermissionService {

    private static final Logger log = LoggerFactory.getLogger(PermissionService.class);

    private static final String CACHE_KEY_PREFIX = "authlib:perms:";
    private static final String CACHE_DELIMITER = "\n";

    private final AuthLibProperties props;
    private final RestTemplate restTemplate;
    private final StringRedisTemplate redis;  // may be null if Redis not on classpath

    public PermissionService(AuthLibProperties props, RestTemplate restTemplate,
                             @Autowired(required = false) StringRedisTemplate redis) {
        this.props = props;
        this.restTemplate = restTemplate;
        this.redis = redis;
    }

    public Collection<GrantedAuthority> fetchPermissions(String accessToken, String jti) {
        if (cacheEnabled() && jti != null) {
            String cached = redis.opsForValue().get(CACHE_KEY_PREFIX + jti);
            if (cached != null && !cached.isBlank()) {
                log.debug("PermissionService: cache hit jti={}", jti);
                return parseAuthorities(cached);
            }
        }

        Collection<GrantedAuthority> authorities = doUmaCall(accessToken);

        if (cacheEnabled() && jti != null && !authorities.isEmpty()) {
            String joined = String.join(CACHE_DELIMITER,
                authorities.stream().map(GrantedAuthority::getAuthority).toList());
            redis.opsForValue().set(CACHE_KEY_PREFIX + jti, joined, props.cache().ttl());
        }
        return authorities;
    }

    private Collection<GrantedAuthority> doUmaCall(String accessToken) {
        String endpoint = props.issuerUri() + "/protocol/openid-connect/token";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setBearerAuth(accessToken);

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        body.add("audience", props.clientId());
        body.add("response_mode", "permissions");

        HttpEntity<MultiValueMap<String, String>> entity = new HttpEntity<>(body, headers);

        try {
            List<Map<String, Object>> resources = restTemplate.postForObject(endpoint, entity, List.class);
            if (resources == null) return List.of();

            List<GrantedAuthority> result = new ArrayList<>();
            for (var r : resources) {
                String rsname = (String) r.get("rsname");
                Object scopesObj = r.get("scopes");
                if (rsname == null || scopesObj == null) continue;
                if (scopesObj instanceof List<?> scopes) {
                    for (Object s : scopes) {
                        result.add(new SimpleGrantedAuthority(
                            "PERMISSION_" + rsname + "_" + s));
                    }
                }
            }
            return result;
        } catch (org.springframework.web.client.HttpStatusCodeException e) {
            // 403 from KC means "no permissions" -- not an error.
            log.debug("PermissionService: UMA call returned {}", e.getStatusCode());
            return List.of();
        }
    }

    private boolean cacheEnabled() {
        return props.cache() != null && props.cache().enabled() && redis != null;
    }

    private Collection<GrantedAuthority> parseAuthorities(String joined) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String s : joined.split(CACHE_DELIMITER)) {
            if (!s.isBlank()) out.add(new SimpleGrantedAuthority(s));
        }
        return out;
    }
}
