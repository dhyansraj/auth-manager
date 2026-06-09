package io.mcpmesh.auth.manager.email;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;

/**
 * Builds the {@link JavaMailSender} auth-manager uses to send mail directly
 * (branded invitations etc.), pointed at the in-cluster {@code smtp-relay}
 * service via {@link SmtpProperties}.
 *
 * <p>Parallel to {@link SmtpConfigBootstrap}, which points tenant KC realms at
 * the same relay: the relay listens on unauthenticated SMTP :25 inside the
 * cluster trust boundary, so no username/password and no STARTTLS.
 */
@Configuration
public class MailConfig {

    @Bean
    public JavaMailSender javaMailSender(SmtpProperties smtpProps) {
        JavaMailSenderImpl sender = new JavaMailSenderImpl();
        sender.setHost(smtpProps.getHost());
        sender.setPort(smtpProps.getPort());
        // Unauthenticated internal relay: no credentials, no STARTTLS.
        var props = sender.getJavaMailProperties();
        props.put("mail.smtp.auth", "false");
        props.put("mail.smtp.starttls.enable", "false");
        return sender;
    }
}
