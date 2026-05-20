package io.mcpmesh.auth.client.sample.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Sample controller exercising auth-lib v2:
 * - {@link #whoami}: requires a valid token but no specific permission.
 * - {@link #viewOrders} / {@link #approveOrders}: gated by Keycloak-issued
 *   PERMISSION_ORDER_VIEW / PERMISSION_ORDER_APPROVE authorities.
 */
@RestController
@RequestMapping("/orders")
public class SampleController {

    @GetMapping("/whoami")
    public Map<String, Object> whoami(@AuthenticationPrincipal Jwt jwt, Authentication auth) {
        return Map.of(
            "subject", jwt.getSubject(),
            "preferred_username", jwt.getClaimAsString("preferred_username"),
            "email", jwt.getClaimAsString("email"),
            "issuer", String.valueOf(jwt.getIssuer()),
            "authorities", auth.getAuthorities().stream()
                .map(a -> a.getAuthority()).collect(Collectors.toList())
        );
    }

    @GetMapping
    @PreAuthorize("hasAuthority('PERMISSION_ORDER_VIEW')")
    public List<Map<String, Object>> viewOrders() {
        return List.of(
            Map.of("id", 1, "item", "Widget",  "qty", 3),
            Map.of("id", 2, "item", "Gizmo",   "qty", 1),
            Map.of("id", 3, "item", "Sprocket","qty", 5)
        );
    }

    @GetMapping("/approve")
    @PreAuthorize("hasAuthority('PERMISSION_ORDER_APPROVE')")
    public Map<String, Object> approveOrders() {
        return Map.of("approved", true, "ts", java.time.Instant.now().toString());
    }
}
