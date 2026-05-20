package io.mcpmesh.auth.manager.service.exception;

public class AppNotFoundException extends RuntimeException {
    public AppNotFoundException(String identifier) {
        super("App not found: " + identifier);
    }
}
