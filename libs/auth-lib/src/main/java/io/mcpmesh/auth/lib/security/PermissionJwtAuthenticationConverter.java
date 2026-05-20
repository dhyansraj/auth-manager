package io.mcpmesh.auth.lib.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.util.ArrayList;
import java.util.Collection;

/**
 * Builds authorities from two sources:
 * - JWT scopes (Spring's default extractor)
 * - PERMISSION_X_Y authorities fetched from Keycloak via {@link PermissionService}
 *
 * <p>The result is wrapped in a {@link JwtAuthenticationToken}.
 */
public class PermissionJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final PermissionService permissions;
    private final JwtGrantedAuthoritiesConverter scopesConverter = new JwtGrantedAuthoritiesConverter();

    public PermissionJwtAuthenticationConverter(PermissionService permissions) {
        this.permissions = permissions;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> merged = new ArrayList<>();
        merged.addAll(scopesConverter.convert(jwt));
        merged.addAll(permissions.fetchPermissions(jwt.getTokenValue(), jwt.getId()));
        return new JwtAuthenticationToken(jwt, merged, jwt.getSubject());
    }
}
