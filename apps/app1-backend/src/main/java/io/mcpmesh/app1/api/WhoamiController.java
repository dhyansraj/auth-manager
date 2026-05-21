package io.mcpmesh.app1.api;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.stream.Collectors;

/** Debugging endpoint — any valid token gets back its principal data. */
@RestController
public class WhoamiController {

    @GetMapping("/api/whoami")
    public Map<String, Object> whoami(@AuthenticationPrincipal Jwt jwt, Authentication auth) {
        return Map.of(
            "subject", jwt.getSubject(),
            "preferred_username", String.valueOf(jwt.getClaimAsString("preferred_username")),
            "email", String.valueOf(jwt.getClaimAsString("email")),
            "issuer", String.valueOf(jwt.getIssuer()),
            "authorities", auth.getAuthorities().stream()
                .map(a -> a.getAuthority()).collect(Collectors.toList())
        );
    }
}
