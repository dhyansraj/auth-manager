package io.mcpmesh.auth.manager.service.exception;

public class AppConflictException extends RuntimeException {
    public AppConflictException(String tenantSlug, String appSlug) {
        super("App slug already exists in tenant " + tenantSlug + ": " + appSlug);
    }
}
