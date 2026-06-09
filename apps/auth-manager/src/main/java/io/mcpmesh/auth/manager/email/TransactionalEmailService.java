package io.mcpmesh.auth.manager.email;

import com.samskivert.mustache.Mustache;
import com.samskivert.mustache.Template;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Generic render + send for catalog transactional emails (entry #1:
 * {@link EmailType#INVITATION}). Loads the type's default logic-less Mustache
 * template, renders it against a generic {@code Map} model, resolves the
 * tenant's effective From, and sends an HTML MIME message via
 * {@link JavaMailSender}.
 *
 * <p>The {@code Map} model is the extensibility seam: future email types just
 * supply different fields. No type-specific code paths live in the render/send
 * machinery.
 *
 * <p>A send failure throws {@link EmailSendException} (unchecked) so callers
 * that must not fail their primary operation (e.g. user creation) can wrap the
 * call in try/catch and log a warning.
 */
@Service
public class TransactionalEmailService {

    private static final Logger log = LoggerFactory.getLogger(TransactionalEmailService.class);

    private final JavaMailSender mailSender;
    private final SmtpProperties smtpProps;
    private final TenantService tenants;
    private final Mustache.Compiler mustache = Mustache.compiler();
    private final Map<EmailType, Template> templateCache = new ConcurrentHashMap<>();

    public TransactionalEmailService(JavaMailSender mailSender,
                                     SmtpProperties smtpProps,
                                     TenantService tenants) {
        this.mailSender = mailSender;
        this.smtpProps = smtpProps;
        this.tenants = tenants;
    }

    /**
     * Renders {@code type}'s default template against {@code model} and sends
     * the result as an HTML email from the tenant's effective From to
     * {@code toAddress}.
     *
     * @throws EmailSendException if compilation, rendering, or SMTP delivery fails.
     */
    public void send(Tenant tenant, EmailType type, String toAddress, String subject,
                     Map<String, Object> model) {
        String html;
        try {
            html = compile(type).execute(model == null ? Map.of() : model);
        } catch (Exception e) {
            throw new EmailSendException(
                "Failed to render " + type + " template: " + e.getMessage(), e);
        }

        try {
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, false, "UTF-8");
            helper.setTo(toAddress);
            helper.setSubject(subject);
            helper.setText(html, true);
            setFrom(helper, tenant);
            mailSender.send(msg);
            log.info("transactional-email: sent {} to {} (tenant={})",
                type, toAddress, tenant.getSlug());
        } catch (Exception e) {
            log.warn("transactional-email: failed to send {} to {} (tenant={}): {}",
                type, toAddress, tenant.getSlug(), e.getMessage());
            throw new EmailSendException(
                "Failed to send " + type + " email to " + toAddress + ": " + e.getMessage(), e);
        }
    }

    /**
     * Builds the INVITATION model + subject for a tenant + recipient and sends
     * the branded invitation. The {@code inviteUrl} points at the tenant's
     * primary hostname; when the tenant has no hostname yet we log a warning and
     * skip the send rather than NPE or mail a broken link.
     *
     * @param inviterName optional display name of the inviting admin; may be null/blank.
     */
    public void sendInvitation(Tenant tenant, String toAddress, String inviterName) {
        String primaryHost = primaryHostname(tenant);
        if (primaryHost == null) {
            log.warn("transactional-email: tenant {} has no hostname; skipping invitation to {}",
                tenant.getSlug(), toAddress);
            return;
        }
        String displayName = tenant.getDisplayName() == null ? tenant.getSlug() : tenant.getDisplayName();
        String inviteUrl = "https://" + primaryHost + "/";

        Map<String, Object> model = new LinkedHashMap<>();
        model.put("tenantDisplayName", displayName);
        model.put("inviteUrl", inviteUrl);
        model.put("recipientEmail", toAddress);
        if (inviterName != null && !inviterName.isBlank()) {
            model.put("inviterName", inviterName.trim());
        }

        String subject = "You've been invited to " + displayName;
        send(tenant, EmailType.INVITATION, toAddress, subject, model);
    }

    // -- helpers --------------------------------------------------------------

    private Template compile(EmailType type) {
        return templateCache.computeIfAbsent(type, t -> {
            ClassPathResource res = new ClassPathResource(t.getTemplateResource());
            try (Reader reader = new InputStreamReader(res.getInputStream(), StandardCharsets.UTF_8)) {
                return mustache.compile(reader);
            } catch (Exception e) {
                throw new EmailSendException(
                    "Failed to load template " + t.getTemplateResource() + ": " + e.getMessage(), e);
            }
        });
    }

    private String primaryHostname(Tenant tenant) {
        List<TenantHostname> hostnames = tenants.hostnamesFor(tenant.getId());
        if (hostnames == null || hostnames.isEmpty()) return null;
        for (TenantHostname h : hostnames) {
            if (h.getHostname() != null && !h.getHostname().isBlank()) {
                return h.getHostname();
            }
        }
        return null;
    }

    /**
     * Resolves the From address (tenant override wins, else platform default
     * {@code auth-manager.smtp.from-address}) + From display name (tenant
     * override, else the tenant display name).
     */
    private void setFrom(MimeMessageHelper helper, Tenant tenant)
            throws jakarta.mail.MessagingException {
        String fromAddress = tenant.getEmailFromAddress();
        if (fromAddress == null || fromAddress.isBlank()) {
            fromAddress = smtpProps.getFromAddress();
        }
        String displayName = tenant.getEmailFromDisplayName();
        if (displayName == null || displayName.isBlank()) {
            displayName = tenant.getDisplayName();
        }
        if (displayName != null && !displayName.isBlank()) {
            try {
                helper.setFrom(fromAddress, displayName);
                return;
            } catch (UnsupportedEncodingException e) {
                // Fall through to address-only From.
            }
        }
        helper.setFrom(fromAddress);
    }
}
