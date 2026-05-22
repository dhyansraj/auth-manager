package io.mcpmesh.auth.manager.theme;

import java.util.List;

/**
 * Thrown by {@link ThemeService#upload} when an uploaded theme fails any of
 * the validator's checks. Mapped to HTTP 400 by the global exception handler
 * with the structured {@code errors} array preserved in the response body so
 * the UI can render each item.
 */
public class ThemeValidationException extends RuntimeException {

    private final List<ValidationResult.Error> errors;

    public ThemeValidationException(List<ValidationResult.Error> errors) {
        super("Theme validation failed (" + errors.size() + " errors)");
        this.errors = List.copyOf(errors);
    }

    public List<ValidationResult.Error> errors() {
        return errors;
    }
}
