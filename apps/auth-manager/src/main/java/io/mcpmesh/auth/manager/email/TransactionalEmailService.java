package io.mcpmesh.auth.manager.email;

import com.samskivert.mustache.Mustache;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.email.templates.EmailTemplateService;
import io.mcpmesh.auth.manager.email.templates.ResolvedTemplate;
import io.mcpmesh.auth.manager.email.templates.TemplateAsset;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Generic render + send for catalog transactional emails. The render path is:
 * resolve the effective template+assets via {@link EmailTemplateService#resolve}
 * → Mustache-render subject + html against a generic {@code Map} model →
 * CSS-inline the html → expand {@code {{asset:name}}} / {@code cid:name}
 * references into CID parts and attach the asset bytes as inline
 * {@code multipart/related} parts → send.
 *
 * <p>A send failure throws {@link EmailSendException} (unchecked) so callers
 * that must not fail their primary operation (e.g. user creation) can wrap the
 * call in try/catch and log a warning.
 */
@Service
public class TransactionalEmailService {

    private static final Logger log = LoggerFactory.getLogger(TransactionalEmailService.class);

    /** Matches {@code {{asset:NAME}}} and {@code cid:NAME} (NAME = [a-zA-Z0-9_-]+). */
    private static final Pattern ASSET_REF =
        Pattern.compile("\\{\\{\\s*asset:([a-zA-Z0-9_-]+)\\s*\\}\\}|cid:([a-zA-Z0-9_-]+)");

    private final JavaMailSender mailSender;
    private final SmtpProperties smtpProps;
    private final TenantService tenants;
    private final EmailTemplateService templates;
    private final CssInliner cssInliner;
    private final Mustache.Compiler mustache = Mustache.compiler();

    public TransactionalEmailService(JavaMailSender mailSender,
                                     SmtpProperties smtpProps,
                                     TenantService tenants,
                                     EmailTemplateService templates,
                                     CssInliner cssInliner) {
        this.mailSender = mailSender;
        this.smtpProps = smtpProps;
        this.tenants = tenants;
        this.templates = templates;
        this.cssInliner = cssInliner;
    }

    /**
     * Resolves {@code typeKey}'s effective template (tenant override or, for
     * {@code invitation}, the classpath default), renders it against
     * {@code model}, inlines CSS, wires inline assets, and sends.
     *
     * @throws EmailSendException if no template resolves, or rendering / SMTP fails.
     */
    public void send(Tenant tenant, String typeKey, String toAddress, String subject,
                     Map<String, Object> model) {
        ResolvedTemplate tpl = templates.resolve(tenant, typeKey)
            .orElseThrow(() -> new EmailSendException(
                "No email template resolved for type '" + typeKey + "' (tenant="
                    + tenant.getSlug() + ")"));
        sendResolved(tenant, tpl, toAddress, subject, model);
    }

    void sendResolved(Tenant tenant, ResolvedTemplate tpl, String toAddress,
                      String subject, Map<String, Object> model) {
        Map<String, Object> safeModel = model == null ? Map.of() : model;

        String html;
        String effectiveSubject = subject;
        try {
            html = mustache.compile(tpl.htmlTemplate()).execute(safeModel);
            html = cssInliner.inline(html);
            if (tpl.subjectTemplate() != null && !tpl.subjectTemplate().isBlank()) {
                effectiveSubject = mustache.compile(tpl.subjectTemplate()).execute(safeModel);
            }
        } catch (Exception e) {
            throw new EmailSendException(
                "Failed to render " + tpl.typeKey() + " template: " + e.getMessage(), e);
        }

        // Resolve {{asset:name}} / cid:name references to attachable CID parts.
        Map<String, TemplateAsset> byName = new LinkedHashMap<>();
        for (TemplateAsset a : tpl.assets()) {
            byName.put(a.name(), a);
        }
        List<InlineAsset> inline = new ArrayList<>();
        html = rewriteAssetRefs(html, byName, inline);

        try {
            boolean multipart = !inline.isEmpty();
            MimeMessage msg = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(msg, multipart, "UTF-8");
            helper.setTo(toAddress);
            helper.setSubject(effectiveSubject);
            helper.setText(html, true);
            setFrom(helper, tenant);
            for (InlineAsset a : inline) {
                helper.addInline(a.contentId(), new ByteArrayResource(a.asset().bytes()),
                    a.asset().contentType());
            }
            mailSender.send(msg);
            log.info("transactional-email: sent {} to {} (tenant={}, assets={})",
                tpl.typeKey(), toAddress, tenant.getSlug(), inline.size());
        } catch (Exception e) {
            log.warn("transactional-email: failed to send {} to {} (tenant={}): {}",
                tpl.typeKey(), toAddress, tenant.getSlug(), e.getMessage());
            throw new EmailSendException(
                "Failed to send " + tpl.typeKey() + " email to " + toAddress + ": "
                    + e.getMessage(), e);
        }
    }

    /**
     * Builds the INVITATION model + subject for a tenant + recipient and sends
     * the branded invitation, honoring a tenant {@code invitation} override when
     * present (else the classpath default). When the tenant has no hostname yet
     * we log a warning and skip the send rather than mail a broken link.
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
        // Alias so a generic starter template using {{ctaUrl}} also works.
        model.put("ctaUrl", inviteUrl);
        model.put("recipientEmail", toAddress);
        if (inviterName != null && !inviterName.isBlank()) {
            model.put("inviterName", inviterName.trim());
        }

        String subject = "You've been invited to " + displayName;
        send(tenant, EmailTemplateService.INVITATION_KEY, toAddress, subject, model);
    }

    // -- helpers --------------------------------------------------------------

    private record InlineAsset(String contentId, TemplateAsset asset) {}

    /**
     * Rewrites every {@code {{asset:name}}} / {@code cid:name} reference whose
     * name matches a supplied asset into {@code cid:<contentId>}, accumulating
     * one {@link InlineAsset} per distinct referenced asset. References with no
     * matching asset are left untouched.
     */
    private String rewriteAssetRefs(String html, Map<String, TemplateAsset> byName,
                                    List<InlineAsset> out) {
        if (html == null || byName.isEmpty()) return html;
        Map<String, String> cidByName = new LinkedHashMap<>();
        Matcher m = ASSET_REF.matcher(html);
        StringBuilder sb = new StringBuilder();
        while (m.find()) {
            String name = m.group(1) != null ? m.group(1) : m.group(2);
            TemplateAsset asset = byName.get(name);
            if (asset == null) {
                m.appendReplacement(sb, Matcher.quoteReplacement(m.group()));
                continue;
            }
            String cid = cidByName.computeIfAbsent(name, n -> {
                String contentId = n + "@auth-manager";
                out.add(new InlineAsset(contentId, asset));
                return contentId;
            });
            m.appendReplacement(sb, Matcher.quoteReplacement("cid:" + cid));
        }
        m.appendTail(sb);
        return sb.toString();
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
