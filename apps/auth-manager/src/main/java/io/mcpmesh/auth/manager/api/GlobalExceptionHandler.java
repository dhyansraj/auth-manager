package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.roles.RoleInUseException;
import io.mcpmesh.auth.manager.roles.RoleNotFoundException;
import io.mcpmesh.auth.manager.service.exception.AppConflictException;
import io.mcpmesh.auth.manager.service.exception.AppNotFoundException;
import io.mcpmesh.auth.manager.service.exception.TenantConflictException;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import io.mcpmesh.auth.manager.theme.ThemeValidationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(TenantNotFoundException.class)
    public ProblemDetail handleNotFound(TenantNotFoundException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        pd.setTitle("Tenant not found");
        return pd;
    }

    @ExceptionHandler(TenantConflictException.class)
    public ProblemDetail handleConflict(TenantConflictException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        pd.setTitle("Tenant slug already in use");
        return pd;
    }

    @ExceptionHandler(AppNotFoundException.class)
    public ProblemDetail handleAppNotFound(AppNotFoundException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        pd.setTitle("App not found");
        return pd;
    }

    @ExceptionHandler(AppConflictException.class)
    public ProblemDetail handleAppConflict(AppConflictException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        pd.setTitle("App slug already in use");
        return pd;
    }

    @ExceptionHandler(IllegalStateException.class)
    public ProblemDetail handleIllegalState(IllegalStateException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        pd.setTitle("Invalid state transition");
        return pd;
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ProblemDetail handleIllegalArg(IllegalArgumentException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setTitle("Invalid argument");
        return pd;
    }

    @ExceptionHandler(UnsupportedOperationException.class)
    public ProblemDetail handleUnsupported(UnsupportedOperationException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_IMPLEMENTED, ex.getMessage());
        pd.setTitle("Not implemented");
        return pd;
    }

    @ExceptionHandler(RoleNotFoundException.class)
    public ProblemDetail handleRoleNotFound(RoleNotFoundException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.NOT_FOUND, ex.getMessage());
        pd.setTitle("Role not found");
        return pd;
    }

    /**
     * Composite-role delete blocked by existing user assignments. Returns
     * the structured body the UI uses to surface the count ({@code error},
     * {@code userCount}) on top of the standard ProblemDetail fields.
     */
    @ExceptionHandler(RoleInUseException.class)
    public ProblemDetail handleRoleInUse(RoleInUseException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, ex.getMessage());
        pd.setTitle("Role in use");
        pd.setProperties(Map.of(
            "error", "role_in_use",
            "role", ex.roleName(),
            "userCount", ex.userCount()
        ));
        return pd;
    }

    /**
     * Theme zip failed prescan (path traversal, forbidden extension, CSS
     * external URL, etc.). The {@code errors} array carries one entry per
     * problem so the UI can render a checklist.
     */
    @ExceptionHandler(ThemeValidationException.class)
    public ProblemDetail handleThemeValidation(ThemeValidationException ex) {
        var pd = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, ex.getMessage());
        pd.setTitle("Theme validation failed");
        pd.setProperties(Map.of(
            "error", "theme_validation_failed",
            "errors", ex.errors().stream().map(e -> Map.of(
                "code", e.code(),
                "path", e.path() == null ? "" : e.path(),
                "message", e.message()
            )).toList()
        ));
        return pd;
    }

    // MethodArgumentNotValidException is handled by Spring's built-in
    // ResponseEntityExceptionHandler (which already returns ProblemDetail);
    // no override needed for now.
}
