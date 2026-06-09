package io.mcpmesh.auth.manager.email.templates;

/**
 * An inline email asset as supplied to {@code EmailTemplateService.upsert} and
 * as carried in a {@link ResolvedTemplate}. {@code name} is the reference key
 * used in the body ({@code {{asset:name}}} / {@code cid:name}).
 */
public record TemplateAsset(String name, String contentType, byte[] bytes) {
}
