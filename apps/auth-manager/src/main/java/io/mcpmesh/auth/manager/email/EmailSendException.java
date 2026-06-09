package io.mcpmesh.auth.manager.email;

/**
 * Thrown when {@link TransactionalEmailService} fails to render or deliver a
 * transactional email. Unchecked so it doesn't pollute signatures, but callers
 * whose primary operation must survive a mail failure (e.g. user creation)
 * should catch it and log a warning.
 */
public class EmailSendException extends RuntimeException {

    public EmailSendException(String message) {
        super(message);
    }

    public EmailSendException(String message, Throwable cause) {
        super(message, cause);
    }
}
