package io.mcpmesh.auth.lib;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link Permissions}, focused on the three behaviors that
 * matter most for tenants composing {@code GET /api/me}:
 *
 * <ol>
 *   <li>UMA responses across multiple audiences are aggregated and normalized.</li>
 *   <li>A single audience failure is logged + skipped, not propagated.</li>
 *   <li>Cached results are reused on the next call (no second UMA hit).</li>
 * </ol>
 */
class PermissionsTest {

    private RestTemplate rest;
    private AuthLibProperties props;
    private Jwt jwt;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        rest = mock(RestTemplate.class);
        // Two audiences so we can verify aggregation + per-audience failure isolation.
        props = new AuthLibProperties(
            "http://kc.local/realms/test",
            "orders",
            "secret",
            List.of("orders", "invoices"),
            null
        );
        jwt = Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject("alice")
            .issuedAt(Instant.now())
            .expiresAt(Instant.now().plusSeconds(300))
            .claim("iss", "http://kc.local/realms/test")
            .build();
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_aggregates_and_normalizes_across_audiences() {
        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenAnswer(invocation -> {
                HttpEntity<MultiValueMap<String, String>> entity = invocation.getArgument(1);
                String audience = entity.getBody().getFirst("audience");
                if ("orders".equals(audience)) {
                    return List.of(
                        Map.of("rsname", "order", "scopes", List.of("view", "approve")),
                        Map.of("rsname", "shipment", "scopes", List.of("view"))
                    );
                }
                if ("invoices".equals(audience)) {
                    return List.of(
                        Map.of("rsname", "invoice", "scopes", List.of("view", "pay"))
                    );
                }
                throw new AssertionError("unexpected audience: " + audience);
            });

        Permissions permissions = new Permissions(props, rest, null);
        Set<String> result = permissions.allFor(jwt);

        assertThat(result).containsExactlyInAnyOrder(
            "ORDER_VIEW", "ORDER_APPROVE",
            "SHIPMENT_VIEW",
            "INVOICE_VIEW", "INVOICE_PAY"
        );
        assertThat(permissions.has(jwt, "ORDER_VIEW")).isTrue();
        assertThat(permissions.has(jwt, "ORDER_DELETE")).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_skips_failing_audience_at_debug() {
        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenAnswer(invocation -> {
                HttpEntity<MultiValueMap<String, String>> entity = invocation.getArgument(1);
                String audience = entity.getBody().getFirst("audience");
                if ("orders".equals(audience)) {
                    return List.of(Map.of("rsname", "order", "scopes", List.of("view")));
                }
                // invoices: no authz services enabled -> 403
                throw HttpClientErrorException.create(HttpStatus.FORBIDDEN,
                    "Forbidden", null, null, null);
            });

        Permissions permissions = new Permissions(props, rest, null);
        Set<String> result = permissions.allFor(jwt);

        // Only the orders permissions survive — invoices was skipped silently.
        assertThat(result).containsExactly("ORDER_VIEW");
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_returns_empty_when_all_audiences_fail() {
        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenThrow(HttpClientErrorException.create(HttpStatus.FORBIDDEN,
                "Forbidden", null, null, null));

        Permissions permissions = new Permissions(props, rest, null);
        assertThat(permissions.allFor(jwt)).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_caches_result_second_call_does_not_hit_uma() {
        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenAnswer(invocation -> {
                HttpEntity<MultiValueMap<String, String>> entity = invocation.getArgument(1);
                String audience = entity.getBody().getFirst("audience");
                if ("orders".equals(audience)) {
                    return List.of(Map.of("rsname", "order", "scopes", List.of("view")));
                }
                return List.of(Map.of("rsname", "invoice", "scopes", List.of("view")));
            });

        Permissions permissions = new Permissions(props, rest, null,
            Duration.ofSeconds(60));
        Set<String> first = permissions.allFor(jwt);
        Set<String> second = permissions.allFor(jwt);

        assertThat(first).isEqualTo(second);
        // One call per audience on the first invocation, none on the second.
        verify(rest, times(2)).postForObject(any(String.class), any(HttpEntity.class), eq(List.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_cache_expires_after_ttl() throws InterruptedException {
        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenReturn(List.of(Map.of("rsname", "order", "scopes", List.of("view"))));

        Permissions permissions = new Permissions(props, rest, null,
            Duration.ofMillis(20));
        permissions.allFor(jwt);
        Thread.sleep(40);
        permissions.allFor(jwt);

        // Two audiences x two invocations because cache TTL elapsed between calls.
        verify(rest, times(4)).postForObject(any(String.class), any(HttpEntity.class), eq(List.class));
    }

    @Test
    void allFor_returns_empty_for_null_jwt() {
        Permissions permissions = new Permissions(props, rest, null);
        assertThat(permissions.allFor(null)).isEmpty();
        verify(rest, never()).postForObject(any(String.class), any(HttpEntity.class), any(Class.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_falls_back_to_inmemory_when_redis_throws() {
        // Redis blows up on every op. The request must still succeed by
        // falling through to the in-memory cache path — no exception bubbles
        // up to the auth filter chain.
        StringRedisTemplate redis = mock(StringRedisTemplate.class);
        ValueOperations<String, String> ops = mock(ValueOperations.class);
        when(redis.opsForValue()).thenReturn(ops);
        when(ops.get(any(String.class)))
            .thenThrow(new RedisConnectionFailureException("simulated redis down"));
        org.mockito.Mockito.doThrow(new RedisConnectionFailureException("simulated redis down"))
            .when(ops).set(any(String.class), any(String.class), any(Duration.class));

        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenAnswer(invocation -> {
                HttpEntity<MultiValueMap<String, String>> entity = invocation.getArgument(1);
                String audience = entity.getBody().getFirst("audience");
                if ("orders".equals(audience)) {
                    return List.of(Map.of("rsname", "order", "scopes", List.of("view")));
                }
                return List.of(Map.of("rsname", "invoice", "scopes", List.of("view")));
            });

        Permissions permissions = new Permissions(props, rest, redis,
            Duration.ofSeconds(60));

        // First call: redis.get throws → UMA path runs → redis.set throws →
        // result still served + cached in-memory.
        Set<String> first = permissions.allFor(jwt);
        assertThat(first).containsExactlyInAnyOrder("ORDER_VIEW", "INVOICE_VIEW");

        // Second call: redis.get throws again → in-memory cache wins → no
        // extra UMA hits beyond the two from the first call.
        Set<String> second = permissions.allFor(jwt);
        assertThat(second).isEqualTo(first);
        verify(rest, times(2)).postForObject(any(String.class), any(HttpEntity.class), eq(List.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_skips_cache_when_disabled() {
        // cache.enabled=false → cache is bypassed entirely, every call hits UMA.
        AuthLibProperties disabled = new AuthLibProperties(
            "http://kc.local/realms/test",
            "orders",
            "secret",
            List.of("orders", "invoices"),
            new AuthLibProperties.Cache(false, Duration.ofMinutes(5))
        );
        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenReturn(List.of(Map.of("rsname", "order", "scopes", List.of("view"))));

        Permissions permissions = new Permissions(disabled, rest, null,
            Duration.ofSeconds(60));
        permissions.allFor(jwt);
        permissions.allFor(jwt);

        // 2 audiences x 2 calls = 4 UMA invocations (no caching at all).
        verify(rest, times(4)).postForObject(any(String.class), any(HttpEntity.class), eq(List.class));
    }

    @Test
    @SuppressWarnings("unchecked")
    void allFor_uses_uma_ticket_grant_with_correct_audience() {
        when(rest.postForObject(any(String.class), any(HttpEntity.class), eq(List.class)))
            .thenReturn(List.of());

        Permissions permissions = new Permissions(props, rest, null);
        permissions.allFor(jwt);

        ArgumentCaptor<HttpEntity<MultiValueMap<String, String>>> captor =
            ArgumentCaptor.forClass(HttpEntity.class);
        verify(rest, times(2)).postForObject(
            eq("http://kc.local/realms/test/protocol/openid-connect/token"),
            captor.capture(),
            eq(List.class));
        for (HttpEntity<MultiValueMap<String, String>> entity : captor.getAllValues()) {
            assertThat(entity.getBody().getFirst("grant_type"))
                .isEqualTo("urn:ietf:params:oauth:grant-type:uma-ticket");
            assertThat(entity.getBody().getFirst("response_mode")).isEqualTo("permissions");
            assertThat(entity.getHeaders().getFirst("Authorization")).isEqualTo("Bearer token");
        }
    }
}
