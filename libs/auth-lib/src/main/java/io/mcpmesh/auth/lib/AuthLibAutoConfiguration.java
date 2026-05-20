package io.mcpmesh.auth.lib;

import io.mcpmesh.auth.lib.security.SecurityConfig;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@EnableConfigurationProperties(AuthLibProperties.class)
@Import(SecurityConfig.class)
public class AuthLibAutoConfiguration {
}
