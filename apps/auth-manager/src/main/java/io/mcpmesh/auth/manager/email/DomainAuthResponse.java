package io.mcpmesh.auth.manager.email;

import java.util.List;

/**
 * Response from the SendGrid domain-auth endpoints — per-tenant whitelabel
 * domain registration + DNS validation state.
 *
 * <ul>
 *   <li>{@code domain} — the bare domain being authenticated.</li>
 *   <li>{@code sendgridDomainId} — SendGrid's domain id (null until /start).</li>
 *   <li>{@code valid} — true after SendGrid validates all 3 CNAMEs resolve.</li>
 *   <li>{@code zoneInOurAccount} — true iff CF auto-pushed the CNAMEs.
 *       When false the caller must add them manually (see {@code cnames}).</li>
 *   <li>{@code cnames} — the 3 SendGrid CNAMEs (mail_cname / dkim1 / dkim2),
 *       each with its push state.</li>
 * </ul>
 */
public record DomainAuthResponse(
    String domain,
    Integer sendgridDomainId,
    Boolean valid,
    boolean zoneInOurAccount,
    List<CnameRecord> cnames
) {
    /**
     * One DNS CNAME emitted by SendGrid for whitelabel domain auth.
     *
     * <ul>
     *   <li>{@code host} — the fully-qualified hostname (e.g. {@code em1234.example.com}).</li>
     *   <li>{@code target} — the SendGrid CNAME target (e.g. {@code u1234.wl.sendgrid.net}).</li>
     *   <li>{@code pushed} — true if Cloudflare DNS now serves this CNAME
     *       (either auto-pushed or already-existing). False means manual
     *       intervention required.</li>
     *   <li>{@code pushError} — error message if push failed, else null.</li>
     * </ul>
     */
    public record CnameRecord(String host, String target, boolean pushed, String pushError) {}
}
