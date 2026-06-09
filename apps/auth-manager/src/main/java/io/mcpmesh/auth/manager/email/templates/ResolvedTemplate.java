package io.mcpmesh.auth.manager.email.templates;

import java.util.List;

/**
 * The effective template the render pipeline should use for a (tenant, typeKey):
 * either the tenant's stored override or, for {@code invitation}, the phase-1
 * classpath default. {@code subjectTemplate} may be null (caller supplies a
 * default subject); {@code assets} is empty for the classpath default.
 */
public record ResolvedTemplate(
    String typeKey,
    String htmlTemplate,
    String subjectTemplate,
    List<TemplateAsset> assets,
    boolean fromTenantOverride
) {
}
