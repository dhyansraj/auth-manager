package io.mcpmesh.auth.manager.service.exception;

public class TenantNotFoundException extends RuntimeException {
    public TenantNotFoundException(String identifier) {
        super("Tenant not found: " + identifier);
    }
}
