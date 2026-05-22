package io.mcpmesh.auth.manager.api.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import org.keycloak.representations.idm.UserRepresentation;

import java.time.Instant;
import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record UserResponse(
    String id,
    String username,
    String email,
    String firstName,
    String lastName,
    Boolean enabled,
    Boolean emailVerified,
    Instant createdAt,
    List<String> roles,       // client roles on usermanagement client
    List<String> realmRoles   // composite (custom) role names; only set by the slug-based UserRoles endpoint
) {
    public static UserResponse from(UserRepresentation u, List<String> roles) {
        return new UserResponse(
            u.getId(), u.getUsername(), u.getEmail(),
            u.getFirstName(), u.getLastName(),
            u.isEnabled(), u.isEmailVerified(),
            u.getCreatedTimestamp() == null ? null : Instant.ofEpochMilli(u.getCreatedTimestamp()),
            roles,
            null
        );
    }

    public static UserResponse from(UserRepresentation u, List<String> roles, List<String> realmRoles) {
        return new UserResponse(
            u.getId(), u.getUsername(), u.getEmail(),
            u.getFirstName(), u.getLastName(),
            u.isEnabled(), u.isEmailVerified(),
            u.getCreatedTimestamp() == null ? null : Instant.ofEpochMilli(u.getCreatedTimestamp()),
            roles,
            realmRoles
        );
    }
}
