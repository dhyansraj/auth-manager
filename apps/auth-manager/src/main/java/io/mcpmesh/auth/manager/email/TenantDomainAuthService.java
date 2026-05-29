package io.mcpmesh.auth.manager.email;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.cloudflare.CloudflareClient;
import io.mcpmesh.auth.manager.cloudflare.CloudflareProperties;
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Manages the per-tenant SendGrid whitelabel domain auth workflow.
 *
 * <p>{@link #start} kicks the full flow:
 * <ol>
 *   <li>Register the domain with SendGrid (or reuse if already-registered).</li>
 *   <li>Resolve the CF zone for the domain's registrable parent; if it's in
 *       our CF account, auto-push each of the 3 DNS-only CNAMEs.</li>
 *   <li>POST {@code /validate} so SendGrid checks the CNAMEs now resolve.</li>
 *   <li>Cache the domain id + valid flag on the tenant row.</li>
 * </ol>
 *
 * <p>{@link #status} re-queries SendGrid for the current {@code valid} state
 * without touching DNS — used by the UI for polling after manual CNAME edits.
 *
 * <p>{@link #revalidate} re-triggers the validate call (idempotent retry).
 */
@Service
public class TenantDomainAuthService {

    private static final Logger log = LoggerFactory.getLogger(TenantDomainAuthService.class);

    private static final ActorKind ACTOR_KIND = ActorKind.USER;

    /**
     * Fallback zone id for {@code mcp-mesh.io} — used as the "in-our-account"
     * fallback when domain-parent zone resolution fails for some reason.
     * Matches the platform's CF zone id in production.
     */
    private static final String MCP_MESH_ZONE_ID = "2d42b23a17e9d4e0b200742acb76864d";

    private final TenantService tenants;
    private final TenantRepository tenantRepo;
    private final SendGridClient sendgrid;
    private final CloudflareClient cf;
    private final CloudflareProperties cfProps;
    private final AuditService audit;

    public TenantDomainAuthService(TenantService tenants,
                                   TenantRepository tenantRepo,
                                   SendGridClient sendgrid,
                                   CloudflareClient cf,
                                   CloudflareProperties cfProps,
                                   AuditService audit) {
        this.tenants = tenants;
        this.tenantRepo = tenantRepo;
        this.sendgrid = sendgrid;
        this.cf = cf;
        this.cfProps = cfProps;
        this.audit = audit;
    }

    /**
     * Registers + validates a domain end-to-end. Idempotent for re-runs: a
     * second call with the same domain GETs the existing SendGrid record
     * instead of erroring.
     */
    @Transactional
    public DomainAuthResponse start(UUID tenantId, String domain, String actor) {
        if (domain == null || domain.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "email.domain_required: domain is required");
        }
        String d = domain.trim().toLowerCase();
        Tenant t = tenants.get(tenantId);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenant_slug", t.getSlug());
        details.put("domain", d);

        if (!sendgrid.isConfigured()) {
            var ex = new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                "email.sendgrid_not_configured: SendGrid API key not set on auth-manager");
            audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                "tenant.email.domain_auth.start", "tenant", t.getId().toString(),
                Map.of("domain", d), ex, details);
            throw ex;
        }

        // ---- 1. Register or reuse the domain on SendGrid ------------------
        SendGridClient.DomainAuthResult sg;
        try {
            sg = sendgrid.createDomain(d);
        } catch (SendGridClient.SendGridConflictException conflict) {
            // Already registered — fall back to a lookup.
            sg = sendgrid.findDomain(d).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.CONFLICT,
                "email.sendgrid_conflict: SendGrid reports domain " + d + " is registered "
                    + "but lookup returned no record. " + conflict.getMessage()));
        } catch (SendGridClient.SendGridApiException e) {
            audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                "tenant.email.domain_auth.start", "tenant", t.getId().toString(),
                Map.of("domain", d), e, details);
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                "email.sendgrid_error: " + e.getMessage(), e);
        }
        details.put("sendgrid_domain_id", sg.id());

        // ---- 2. Try to auto-push the CNAMEs via Cloudflare ----------------
        String zoneId = resolveZoneId(d);
        boolean zoneInOurAccount = zoneId != null;
        List<DomainAuthResponse.CnameRecord> pushed = new ArrayList<>();
        if (zoneInOurAccount) {
            for (SendGridClient.DnsCname c : sg.cnames()) {
                String pushError = null;
                boolean ok = false;
                try {
                    Optional<String> existing = cf.findCnameRecordId(zoneId, c.host());
                    if (existing.isEmpty()) {
                        cf.createDnsOnlyCnameRecord(zoneId, c.host(), c.target(),
                            "auth-platform tenant " + t.getSlug() + " — SendGrid DKIM");
                    }
                    // If it exists already, leave it alone (likely already
                    // pointed at the correct SG target from a prior run).
                    ok = true;
                } catch (Exception e) {
                    pushError = e.getMessage();
                    log.warn("CF push failed for {}: {}", c.host(), e.getMessage());
                }
                pushed.add(new DomainAuthResponse.CnameRecord(c.host(), c.target(), ok, pushError));
            }
        } else {
            // Zone not in our CF account — return CNAMEs as manual instructions.
            for (SendGridClient.DnsCname c : sg.cnames()) {
                pushed.add(new DomainAuthResponse.CnameRecord(c.host(), c.target(), false,
                    "Cloudflare zone for " + d + " is not in this platform's CF account — add CNAME manually."));
            }
        }

        // ---- 3. Ask SendGrid to validate (best-effort; fine to fail) ------
        boolean valid = sg.valid();
        try {
            SendGridClient.DomainAuthResult after = sendgrid.validateDomain(sg.id());
            valid = after.valid();
            details.put("valid", valid);
        } catch (SendGridClient.SendGridApiException e) {
            log.info("SendGrid validate({}) returned non-2xx — DNS propagation likely pending: {}",
                sg.id(), e.getMessage());
            details.put("validation_pending", e.getMessage());
        }

        // ---- 4. Persist on the tenant row ----------------------------------
        t.setSendgridDomain(sg.id(), valid);
        // Stash the registered domain in settings so TenantEmailService can
        // match candidate fromAddress domains against it without a SG fetch.
        @SuppressWarnings("unchecked")
        Map<String, Object> settings = (Map<String, Object>) t.getSettings();
        if (settings == null) settings = new HashMap<>();
        Object existingSgNode = settings.get("sendgrid");
        Map<String, Object> sgNode = (existingSgNode instanceof Map)
            ? new LinkedHashMap<>((Map<String, Object>) existingSgNode)
            : new LinkedHashMap<>();
        sgNode.put("domain", d);
        settings.put("sendgrid", sgNode);
        // Tenant#getSettings returns a live ref so mutating it is enough; the
        // JPA dirty-checker will write the JSONB on commit.
        tenantRepo.save(t);

        audit.recordSuccess(actor, ACTOR_KIND, t.getId(),
            "tenant.email.domain_auth.start", "tenant", t.getId().toString(),
            Map.of("domain", d), details);

        return new DomainAuthResponse(d, sg.id(), valid, zoneInOurAccount, pushed);
    }

    /**
     * Returns the cached state from the tenant row, refreshing the
     * {@code valid} flag from SendGrid in the same call. Cheaper than start()
     * — no CF calls, no audit event.
     */
    @Transactional
    public DomainAuthResponse status(UUID tenantId) {
        Tenant t = tenants.get(tenantId);
        Integer id = t.getSendgridDomainId();
        if (id == null) {
            return new DomainAuthResponse(null, null, null, false, List.of());
        }
        if (!sendgrid.isConfigured()) {
            // Return whatever we have cached so the UI can still render.
            return cachedResponse(t);
        }
        try {
            SendGridClient.DomainAuthResult sg = sendgrid.getDomain(id);
            if (sg.valid() != Boolean.TRUE.equals(t.getSendgridDomainValid())) {
                t.setSendgridDomain(sg.id(), sg.valid());
                tenantRepo.save(t);
            }
            String registeredDomain = sg.domain() != null ? sg.domain()
                : firstNonNull(getRegisteredDomainSetting(t), "");
            String zoneId = resolveZoneId(registeredDomain);
            return new DomainAuthResponse(
                registeredDomain,
                sg.id(),
                sg.valid(),
                zoneId != null,
                sg.cnames().stream()
                    .map(c -> new DomainAuthResponse.CnameRecord(c.host(), c.target(), true, null))
                    .toList()
            );
        } catch (SendGridClient.SendGridApiException e) {
            log.warn("status: SendGrid lookup failed for domain {}: {}", id, e.getMessage());
            return cachedResponse(t);
        }
    }

    /**
     * Re-runs SendGrid's {@code /validate} call. Idempotent retry — operator
     * uses this after fixing manual DNS to confirm validation succeeded.
     */
    @Transactional
    public DomainAuthResponse revalidate(UUID tenantId, String actor) {
        Tenant t = tenants.get(tenantId);
        Integer id = t.getSendgridDomainId();
        if (id == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "email.no_domain_registered: tenant has not started domain authentication");
        }
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("tenant_slug", t.getSlug());
        details.put("sendgrid_domain_id", id);
        try {
            SendGridClient.DomainAuthResult sg = sendgrid.validateDomain(id);
            t.setSendgridDomain(sg.id(), sg.valid());
            tenantRepo.save(t);
            details.put("valid", sg.valid());
            audit.recordSuccess(actor, ACTOR_KIND, t.getId(),
                "tenant.email.domain_auth.revalidate", "tenant", t.getId().toString(),
                null, details);
            String registered = sg.domain() != null ? sg.domain()
                : firstNonNull(getRegisteredDomainSetting(t), "");
            String zoneId = resolveZoneId(registered);
            return new DomainAuthResponse(
                registered,
                sg.id(),
                sg.valid(),
                zoneId != null,
                sg.cnames().stream()
                    .map(c -> new DomainAuthResponse.CnameRecord(c.host(), c.target(), true, null))
                    .toList()
            );
        } catch (SendGridClient.SendGridApiException e) {
            audit.recordFailure(actor, ACTOR_KIND, t.getId(),
                "tenant.email.domain_auth.revalidate", "tenant", t.getId().toString(),
                null, e, details);
            throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,
                "email.sendgrid_error: " + e.getMessage(), e);
        }
    }

    // -- helpers --------------------------------------------------------------

    private DomainAuthResponse cachedResponse(Tenant t) {
        String registered = getRegisteredDomainSetting(t);
        return new DomainAuthResponse(
            registered,
            t.getSendgridDomainId(),
            t.getSendgridDomainValid(),
            false,
            List.of()
        );
    }

    @SuppressWarnings("unchecked")
    private static String getRegisteredDomainSetting(Tenant t) {
        Map<String, Object> settings = t.getSettings();
        if (settings == null) return null;
        Object sg = settings.get("sendgrid");
        if (!(sg instanceof Map)) return null;
        Object dom = ((Map<String, Object>) sg).get("domain");
        return dom instanceof String s && !s.isBlank() ? s : null;
    }

    private static String firstNonNull(String a, String b) {
        return (a != null && !a.isBlank()) ? a : b;
    }

    /**
     * Resolves the Cloudflare zone id for the given domain's registrable parent,
     * or null when the zone isn't in our CF account. Uses CF's
     * {@code /zones?name=&lt;parent&gt;} lookup; falls back to the hardcoded
     * mcp-mesh.io zone id when the lookup says "yes mcp-mesh.io is ours" but
     * fails to return the zone id (e.g., transient API hiccup).
     */
    private String resolveZoneId(String domain) {
        if (domain == null || domain.isBlank()) return null;
        if (!cfProps.isConfigured()) return null;
        String parent = registrableDomain(domain);
        try {
            Optional<String> id = cf.findZoneId(parent);
            if (id.isPresent()) return id.get();
            // Last-resort fallback for our own domain (CF resolution flakiness).
            if ("mcp-mesh.io".equalsIgnoreCase(parent)) return MCP_MESH_ZONE_ID;
            return null;
        } catch (Exception e) {
            log.warn("resolveZoneId({}) failed: {}", parent, e.getMessage());
            return null;
        }
    }

    /**
     * Returns the registrable parent of the given host: strips leftmost labels
     * down to the last two (good-enough heuristic for the common case of
     * single-label TLDs like {@code .com}, {@code .io}, {@code .org}). For
     * compound TLDs ({@code .co.uk}, etc.) the operator's input domain should
     * already BE the registrable parent — we don't try to over-engineer this.
     */
    static String registrableDomain(String host) {
        if (host == null) return null;
        String h = host.toLowerCase();
        int dots = (int) h.chars().filter(c -> c == '.').count();
        if (dots <= 1) return h;
        int firstDot = h.indexOf('.');
        return h.substring(firstDot + 1);
    }
}
