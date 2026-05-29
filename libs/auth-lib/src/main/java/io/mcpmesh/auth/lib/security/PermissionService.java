package io.mcpmesh.auth.lib.security;

import io.mcpmesh.auth.lib.AuthLibProperties;
import io.mcpmesh.auth.lib.PermissionsCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Fetches a user's permissions from Keycloak's UMA permission endpoint and
 * returns them as Spring Security {@link GrantedAuthority} instances named
 * {@code PERMISSION_<RESOURCE>_<SCOPE>}.
 *
 * <p>Caching: results go through the injected {@link PermissionsCache}
 * (in-memory by default; Redis if the tenant adds
 * {@code spring-boot-starter-data-redis} to their pom). Keyed by
 * {@code authlib:perms:<jti>} for the configured TTL.
 *
 * <p>Since 0.3.1 this class no longer references Spring Data Redis directly;
 * the classpath dep is truly optional.
 */
public class PermissionService {

    private static final Logger log = LoggerFactory.getLogger(PermissionService.class);

    private static final String CACHE_KEY_PREFIX = "authlib:perms:";

    private final AuthLibProperties props;
    private final RestTemplate restTemplate;
    private final PermissionsCache cache;

    public PermissionService(AuthLibProperties props, RestTemplate restTemplate,
                             PermissionsCache cache) {
        this.props = props;
        this.restTemplate = restTemplate;
        this.cache = cache;
    }

    public Collection<GrantedAuthority> fetchPermissions(String accessToken, String jti) {
        if (cacheEnabled() && jti != null) {
            Set<String> cached = cache.read(CACHE_KEY_PREFIX + jti);
            if (cached != null && !cached.isEmpty()) {
                log.debug("PermissionService: cache hit jti={}", jti);
                return toAuthorities(cached);
            }
        }

        Collection<GrantedAuthority> authorities = doUmaCall(accessToken);

        if (cacheEnabled() && jti != null && !authorities.isEmpty()) {
            Set<String> values = new LinkedHashSet<>();
            for (GrantedAuthority a : authorities) values.add(a.getAuthority());
            cache.write(CACHE_KEY_PREFIX + jti, values, props.cache().ttl());
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
            @SuppressWarnings("unchecked")
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
        return props.cache() != null && props.cache().enabled();
    }

    private Collection<GrantedAuthority> toAuthorities(Set<String> values) {
        List<GrantedAuthority> out = new ArrayList<>();
        for (String s : values) {
            if (!s.isBlank()) out.add(new SimpleGrantedAuthority(s));
        }
        return out;
    }
}
