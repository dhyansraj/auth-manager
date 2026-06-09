package io.mcpmesh.auth.manager;

import io.mcpmesh.auth.manager.cloudflare.CloudflareProperties;
import io.mcpmesh.auth.manager.email.SmtpProperties;
import io.mcpmesh.auth.manager.email.templates.EmailRateLimitProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({CloudflareProperties.class, SmtpProperties.class, EmailRateLimitProperties.class})
public class Application {

    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
