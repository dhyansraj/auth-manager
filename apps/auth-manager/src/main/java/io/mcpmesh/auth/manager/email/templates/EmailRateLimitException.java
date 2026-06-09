package io.mcpmesh.auth.manager.email.templates;

/**
 * Thrown by {@link EmailRateLimiter} when a tenant has exceeded its per-minute
 * burst limit or its per-day send quota on the generic email send API. Carries
 * a {@code retryAfterSeconds} hint that the controller surfaces as a
 * {@code Retry-After} header on the 429 response.
 */
public class EmailRateLimitException extends RuntimeException {

    private final long retryAfterSeconds;

    public EmailRateLimitException(long retryAfterSeconds, String message) {
        super(message);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
