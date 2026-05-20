package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.service.exception.AppConflictException;
import io.mcpmesh.auth.manager.service.exception.AppNotFoundException;
import io.mcpmesh.auth.manager.service.exception.TenantConflictException;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

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

    // MethodArgumentNotValidException is handled by Spring's built-in
    // ResponseEntityExceptionHandler (which already returns ProblemDetail);
    // no override needed for now.
}
