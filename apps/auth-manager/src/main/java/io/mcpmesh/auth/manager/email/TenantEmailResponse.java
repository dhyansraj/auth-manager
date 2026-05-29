package io.mcpmesh.auth.manager.email;

/**
 * Per-tenant email config view returned by {@link TenantEmailController}.
 *
 * <ul>
 *   <li>{@code fromAddress} — resolved value (tenant override if set, else
 *       the platform default). What KC actually sends with.</li>
 *   <li>{@code fromAddressOverride} — the raw tenant column or null. Lets
 *       the UI distinguish "operator set this explicitly" from "falling back
 *       to platform default".</li>
 *   <li>{@code fromDisplayName} — resolved display name (override OR tenant
 *       displayName).</li>
 *   <li>{@code replyToAddress} — explicit override, null if not set.</li>
 *   <li>{@code sendgridDomainId} / {@code sendgridDomainValid} — current
 *       SendGrid whitelabel domain state for this tenant.</li>
 *   <li>{@code domainAuthStatus} — one of NOT_STARTED, PENDING, VALID,
 *       FAILED — derived from the two SendGrid fields for UI consumption.</li>
 * </ul>
 */
public record TenantEmailResponse(
    String fromAddress,
    String fromAddressOverride,
    String fromDisplayName,
    String fromDisplayNameOverride,
    String replyToAddress,
    Integer sendgridDomainId,
    Boolean sendgridDomainValid,
    DomainAuthStatus domainAuthStatus
) {
    public enum DomainAuthStatus {
        NOT_STARTED, PENDING, VALID, FAILED
    }

    /**
     * Derives the UI-friendly status enum from the two cached SendGrid columns.
     * NULL id     → NOT_STARTED
     * id set, NULL valid → PENDING
     * id set, valid=true → VALID
     * id set, valid=false → FAILED
     */
    public static DomainAuthStatus deriveStatus(Integer domainId, Boolean valid) {
        if (domainId == null) return DomainAuthStatus.NOT_STARTED;
        if (valid == null) return DomainAuthStatus.PENDING;
        return valid ? DomainAuthStatus.VALID : DomainAuthStatus.FAILED;
    }
}
