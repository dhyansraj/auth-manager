package io.mcpmesh.auth.manager.email;

/**
 * Catalog of transactional email types auth-manager can render + send via
 * {@link TransactionalEmailService}. Each entry maps to a default logic-less
 * Mustache template on the classpath.
 *
 * <p>Entry #1 of a future transactional-email system. Future types
 * (PROMOTION, PAYMENT_DUE, WELCOME, ...) just add a value + template resource;
 * the render/send machinery is type-agnostic (generic {@code Map} model).
 */
public enum EmailType {

    /**
     * "You've been invited — sign in" email sent to brokered (Google-only /
     * no-password) tenant users in place of KC's UPDATE_PASSWORD action email.
     */
    INVITATION("email-templates/invitation.html.mustache");

    private final String templateResource;

    EmailType(String templateResource) {
        this.templateResource = templateResource;
    }

    /** Classpath resource path of this type's default Mustache template. */
    public String getTemplateResource() {
        return templateResource;
    }
}
