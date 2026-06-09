package io.mcpmesh.auth.manager.email.templates;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.email.TransactionalEmailService;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * App-facing send API: lets a tenant backend send a branded transactional email
 * through the IAM using one of its stored templates.
 *
 * <pre>
 *   POST /api/v1/tenants/{tenantId}/emails/{typeKey} → render+send, 202 Accepted
 * </pre>
 *
 * UUID-keyed and gated on {@code EMAIL_SEND} (mirrors the UUID-keyed user-invite
 * surface). Only a tenant's <em>stored</em> template resolves here — there is no
 * classpath fallback (that is reserved for the internal invite flow), and the
 * reserved {@code invitation} key is rejected since invitations must go through
 * the user-invite endpoint that provisions the recipient.
 */
@RestController
@RequestMapping("/api/v1/tenants/{tenantId:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}}/emails")
public class EmailSendController {

    private static final ActorKind ACTOR_KIND = ActorKind.SERVICE;

    private final TenantService tenants;
    private final EmailTemplateService templates;
    private final TransactionalEmailService emailService;
    private final AuditService audit;

    public EmailSendController(TenantService tenants,
                              EmailTemplateService templates,
                              TransactionalEmailService emailService,
                              AuditService audit) {
        this.tenants = tenants;
        this.templates = templates;
        this.emailService = emailService;
        this.audit = audit;
    }

    public record SendRequest(
        @Email @NotBlank String to,
        Map<String, Object> model
    ) {}

    public record SendResponse(boolean sent) {}

    @PostMapping("/{typeKey}")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'EMAIL_SEND')")
    // TODO pre-prod: per-tenant rate limit/quota
    public ResponseEntity<SendResponse> send(@PathVariable UUID tenantId,
                                             @PathVariable String typeKey,
                                             @Valid @RequestBody SendRequest req,
                                             Authentication auth) {
        EmailTemplateService.requireValidTypeKey(typeKey);
        if (EmailTemplateService.INVITATION_KEY.equals(typeKey)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                "'invitation' is sent via the user-invite endpoint, not the generic send API");
        }

        Tenant tenant = tenants.get(tenantId);

        // Stored override only — no classpath fallback on the generic send path.
        EmailTemplate stored = templates.get(tenantId, typeKey)
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.NOT_FOUND, "No email template for type: " + typeKey));

        Map<String, Object> model = req.model() == null ? Map.of() : req.model();
        // The subject comes from the template's subject_template, rendered with the
        // model inside the send path; passing it here is a fallback when absent.
        String subject = stored.getSubjectTemplate();
        emailService.send(tenant, typeKey, req.to(), subject, model);

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("typeKey", typeKey);
        details.put("to", req.to());
        audit.recordSuccess(principal(auth), ACTOR_KIND, tenantId,
            "email.send", "email_template", typeKey, null, details);

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(new SendResponse(true));
    }

    private static String principal(Authentication auth) {
        if (auth instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            String pref = jwt.getClaimAsString("preferred_username");
            return pref != null ? pref : jwt.getSubject();
        }
        return "system";
    }
}
