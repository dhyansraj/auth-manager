package io.mcpmesh.auth.manager.idp;

/**
 * Per-tenant self-registration / invite-only posture.
 *
 * @param inviteOnly          true when only operator-provisioned users may sign
 *                            in (social sign-ups for unknown emails rejected,
 *                            self-registration form disabled)
 * @param registrationAllowed convenience inverse of {@code inviteOnly} —
 *                            mirrors the realm's {@code registrationAllowed} flag
 */
public record RegistrationStateDto(
    boolean inviteOnly,
    boolean registrationAllowed
) {}
