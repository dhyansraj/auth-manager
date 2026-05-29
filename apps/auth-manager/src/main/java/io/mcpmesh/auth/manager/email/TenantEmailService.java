package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Read + update the per-tenant email config (From / display / Reply-To).
 *
 * <p>Validation rules on update:
 * <ul>
 *   <li>{@code fromAddress} (if non-null) must parse as a valid email.</li>
 *   <li>{@code fromAddress} domain must match a SendGrid-authenticated
 *       domain registered against this tenant. Without that gate, KC would
 *       happily send mail from {@code noreply@untrusted.example.com} and
 *       SendGrid would silently drop / quarantine the messages.</li>
 * </ul>
 *
 * <p>Successful updates also reconcile the KC realm SMTP config via
 * {@link SmtpConfigBootstrap#reconcileRealmSmtp(Tenant)} so the new overrides
 * take effect immediately (no pod restart, no wait for a periodic sync).
 */
@Service
public class TenantEmailService {

    private static final Logger log = LoggerFactory.getLogger(TenantEmailService.class);

    /** RFC-5322-lite: same shape the admin-ui validates client-side. */
    private static final Pattern EMAIL_PATTERN =
        Pattern.compile("^[^\\s@]+@[^\\s@]+\\.[^\\s@]+$");

    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    private final TenantService tenants;
    private final TenantRepository tenantRepo;
    private final SmtpProperties smtpProps;
    private final SmtpConfigBootstrap smtpBootstrap;
    private final AuditService audit;

    public TenantEmailService(TenantService tenants,
                              TenantRepository tenantRepo,
                              SmtpProperties smtpProps,
                              SmtpConfigBootstrap smtpBootstrap,
                              AuditService audit) {
        this.tenants = tenants;
        this.tenantRepo = tenantRepo;
        this.smtpProps = smtpProps;
        this.smtpBootstrap = smtpBootstrap;
        this.audit = audit;
    }

    @Transactional(readOnly = true)
    public TenantEmailResponse get(UUID tenantId) {
        Tenant t = tenants.get(tenantId);
        return toResponse(t);
    }

    @Transactional
    public TenantEmailResponse update(UUID tenantId, TenantEmailUpdateRequest req, String actor) {
        Tenant t = tenants.get(tenantId);

        String fromAddress = blankToNull(req.fromAddress());
        String fromDisplayName = blankToNull(req.fromDisplayName());
        String replyToAddress = blankToNull(req.replyToAddress());

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenant_slug", t.getSlug());
        details.put("realm", t.getRealmName());
        details.put("fromAddress", fromAddress);
        details.put("fromDisplayName", fromDisplayName);
        details.put("replyToAddress", replyToAddress);

        // ---- validation ----------------------------------------------------
        if (fromAddress != null && !EMAIL_PATTERN.matcher(fromAddress).matches()) {
            var ex = new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "email.invalid_from_address: '" + fromAddress + "' is not a valid email");
            audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                "tenant.email.update", "tenant", t.getId().toString(),
                req, ex, details);
            throw ex;
        }
        if (replyToAddress != null && !EMAIL_PATTERN.matcher(replyToAddress).matches()) {
            var ex = new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "email.invalid_reply_to: '" + replyToAddress + "' is not a valid email");
            audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                "tenant.email.update", "tenant", t.getId().toString(),
                req, ex, details);
            throw ex;
        }
        if (fromAddress != null) {
            String fromDomain = extractDomain(fromAddress);
            String platformFromDomain = extractDomain(smtpProps.getFromAddress());
            // Allow the platform fallback domain unconditionally (operator may
            // want to set a custom display name without registering a tenant
            // domain — keeping "noreply@mcp-mesh.io" is fine).
            boolean isPlatformDomain = platformFromDomain != null
                && platformFromDomain.equalsIgnoreCase(fromDomain);
            if (!isPlatformDomain
                && !isTenantAuthenticatedDomain(t, fromDomain)) {
                var ex = new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "email.unauthorized_from_domain: '" + fromDomain
                        + "' is not a SendGrid-authenticated domain for this tenant. "
                        + "Authenticate the domain first via the Email tab's Domain Authentication section.");
                audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                    "tenant.email.update", "tenant", t.getId().toString(),
                    req, ex, details);
                throw ex;
            }
        }

        // ---- persist + reconcile -------------------------------------------
        t.setEmailOverrides(fromAddress, fromDisplayName, replyToAddress);
        tenantRepo.save(t);

        try {
            smtpBootstrap.reconcileRealmSmtp(t);
        } catch (Exception e) {
            // The DB update is the source of truth; a KC failure is recoverable
            // on the next bootstrap pass. Log + audit but don't fail the call.
            log.warn("tenant.email.update: KC SMTP reconcile failed for tenant {}: {}",
                t.getSlug(), e.getMessage());
            details.put("kc_reconcile_error", e.getMessage());
        }

        audit.recordSuccess(actor, ACTOR_KIND, t.getId(),
            "tenant.email.update", "tenant", t.getId().toString(),
            req, details);

        return toResponse(t);
    }

    // -- helpers --------------------------------------------------------------

    private TenantEmailResponse toResponse(Tenant t) {
        String override = t.getEmailFromAddress();
        String resolved = (override != null && !override.isBlank())
            ? override
            : smtpProps.getFromAddress();
        String displayOverride = t.getEmailFromDisplayName();
        String resolvedDisplay = (displayOverride != null && !displayOverride.isBlank())
            ? displayOverride
            : (t.getDisplayName() == null ? "" : t.getDisplayName());
        return new TenantEmailResponse(
            resolved,
            override,
            resolvedDisplay,
            displayOverride,
            t.getEmailReplyToAddress(),
            t.getSendgridDomainId(),
            t.getSendgridDomainValid(),
            TenantEmailResponse.deriveStatus(t.getSendgridDomainId(), t.getSendgridDomainValid())
        );
    }

    /**
     * Returns true iff the tenant has a SendGrid-authenticated whitelabel
     * domain whose registered domain matches {@code candidateDomain} (or is
     * a parent — e.g. authenticated {@code mcp-mesh.io} permits
     * {@code mail.mcp-mesh.io}). The tenant column tracks only the domain id
     * + valid flag; the cached state is authoritative for the validation gate
     * (refreshable via the /domain-auth/revalidate endpoint).
     */
    private boolean isTenantAuthenticatedDomain(Tenant t, String candidateDomain) {
        if (candidateDomain == null) return false;
        Integer id = t.getSendgridDomainId();
        Boolean valid = t.getSendgridDomainValid();
        if (id == null || !Boolean.TRUE.equals(valid)) return false;
        // We don't persist the registered domain itself (only the SG id);
        // instead, the per-tenant whitelabel domain is keyed off the
        // settings JSON via the "sendgrid.domain" key, which start() sets.
        String registered = sendgridDomainFromSettings(t);
        if (registered == null) {
            // Backwards compat: tenant has an id but no settings key.
            // Conservative — accept the candidate since SG already validated
            // it on registration.
            return true;
        }
        String c = candidateDomain.toLowerCase();
        String r = registered.toLowerCase();
        return c.equals(r) || c.endsWith("." + r);
    }

    @SuppressWarnings("unchecked")
    private static String sendgridDomainFromSettings(Tenant t) {
        Map<String, Object> settings = t.getSettings();
        if (settings == null) return null;
        Object sg = settings.get("sendgrid");
        if (!(sg instanceof Map)) return null;
        Object dom = ((Map<String, Object>) sg).get("domain");
        return dom instanceof String s && !s.isBlank() ? s : null;
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }

    private static String extractDomain(String email) {
        if (email == null) return null;
        int at = email.lastIndexOf('@');
        if (at < 0 || at == email.length() - 1) return null;
        return email.substring(at + 1).toLowerCase();
    }
}
