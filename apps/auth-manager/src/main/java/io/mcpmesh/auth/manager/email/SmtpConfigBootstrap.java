package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reconciles SMTP server config on every active tenant Keycloak realm so
 * password-reset / verify-email / magic-link emails route through the
 * in-cluster {@code smtp-relay} service (which forwards to SendGrid).
 *
 * <p>Runs at startup as an {@link ApplicationRunner} to backfill every
 * already-provisioned realm. {@code TenantController} also invokes
 * {@link #reconcileRealmSmtp(Tenant)} immediately after a new tenant is
 * created so newly-provisioned realms don't have to wait for a pod restart.
 *
 * <p>Idempotent: a realm whose SMTP server already matches the desired config
 * gets no PUT call (compared by {@link Map#equals(Object)}). All KC errors are
 * caught per-realm and logged at WARN; a single bad realm never aborts the
 * batch or fails app startup.
 */
@Component
public class SmtpConfigBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(SmtpConfigBootstrap.class);

    private final Keycloak kcAdmin;
    private final TenantRepository tenants;
    private final SmtpProperties smtpProps;

    public SmtpConfigBootstrap(Keycloak kcAdmin,
                               TenantRepository tenants,
                               SmtpProperties smtpProps) {
        this.kcAdmin = kcAdmin;
        this.tenants = tenants;
        this.smtpProps = smtpProps;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!smtpProps.isEnabled()) {
            log.info("SmtpConfigBootstrap: disabled via config, skipping");
            return;
        }
        int updated = 0;
        int total = 0;
        try {
            var active = tenants.findAllByDeletedAtIsNullOrderByCreatedAtDesc();
            for (Tenant t : active) {
                if (t.getRealmName() == null || t.getRealmName().isBlank()) {
                    continue;
                }
                total++;
                try {
                    if (reconcileRealmSmtp(t)) updated++;
                } catch (Exception e) {
                    log.warn("SmtpConfigBootstrap: failed to set SMTP on realm {}: {}",
                        t.getRealmName(), e.getMessage());
                }
            }
        } catch (Exception e) {
            log.warn("SmtpConfigBootstrap: startup backfill aborted: {}", e.getMessage());
            return;
        }
        log.info("SmtpConfigBootstrap: reconciled SMTP config on {}/{} tenant realm(s)",
            updated, total);
    }

    /**
     * Ensures the given tenant's realm has the desired SMTP server config.
     * Returns true if a KC update was issued; false if the existing config
     * already matched (idempotent no-op).
     */
    public boolean reconcileRealmSmtp(Tenant t) {
        RealmResource realm = kcAdmin.realm(t.getRealmName());
        RealmRepresentation rep = realm.toRepresentation();
        Map<String, String> desired = buildSmtpConfig(t);
        if (mapsEqual(rep.getSmtpServer(), desired)) {
            return false;
        }
        rep.setSmtpServer(desired);
        realm.update(rep);
        log.info("SmtpConfigBootstrap: updated SMTP on realm {} from={} host={}",
            t.getRealmName(), desired.get("from"), desired.get("host"));
        return true;
    }

    Map<String, String> buildSmtpConfig(Tenant t) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("host", smtpProps.getHost());
        m.put("port", String.valueOf(smtpProps.getPort()));
        m.put("from", resolveFromAddress(t));
        m.put("fromDisplayName", resolveDisplayName(t));
        m.put("auth", "false");
        m.put("starttls", "false");
        m.put("ssl", "false");
        // Phase 2: per-tenant Reply-To. Only emit when an override is set —
        // KC defaults Reply-To to the From address otherwise.
        String replyTo = t.getEmailReplyToAddress();
        if (replyTo != null && !replyTo.isBlank()) {
            m.put("replyTo", replyTo);
        }
        return m;
    }

    /**
     * Resolves the From address: tenant override wins; falls back to the
     * platform default ({@code auth-manager.smtp.from-address}).
     */
    private String resolveFromAddress(Tenant t) {
        String override = t.getEmailFromAddress();
        if (override != null && !override.isBlank()) return override;
        return smtpProps.getFromAddress();
    }

    /**
     * Resolves the display name: tenant override wins; otherwise the template
     * is rendered against the tenant's display name (Phase 1 behavior).
     */
    private String resolveDisplayName(Tenant t) {
        String override = t.getEmailFromDisplayName();
        if (override != null && !override.isBlank()) return override;
        String template = smtpProps.getFromDisplayNameTemplate();
        String tenantDisplay = t.getDisplayName() == null ? "" : t.getDisplayName();
        return template.replace("{tenantDisplayName}", tenantDisplay);
    }

    private static boolean mapsEqual(Map<String, String> a, Map<String, String> b) {
        if (a == null || a.isEmpty()) return b == null || b.isEmpty();
        return a.equals(b);
    }
}
