package io.mcpmesh.auth.manager.service.exception;

public class TenantConflictException extends RuntimeException {
    public TenantConflictException(String slug) {
        super("Tenant slug already exists: " + slug);
    }
}
