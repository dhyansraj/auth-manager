package io.mcpmesh.auth.manager.service;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import javax.sql.DataSource;

/**
 * Two-DataSource setup for auth-manager:
 *
 * <ul>
 *   <li><b>Primary</b> ({@code @Primary}, used by JPA / Flyway / Hibernate /
 *       Spring's repo layer) — connects as {@code authmanager} to the
 *       {@code authmanager} database. Properties bound from
 *       {@code spring.datasource.*}.</li>
 *   <li>{@code cnpgSuperuserDataSource} — secondary connection as
 *       {@code postgres} to the {@code postgres} maintenance database.
 *       Used <i>only</i> by {@link TenantDatabaseService} to run CREATE
 *       USER / CREATE DATABASE / DROP DATABASE DDL when provisioning
 *       per-tenant databases.</li>
 * </ul>
 *
 * <p>WHY THIS EXISTS: Spring Boot's auto-configuration creates a default
 * DataSource only when there is no {@link DataSource} bean in the context.
 * Declaring the superuser bean ALONE would suppress the default — JPA
 * would then point at the maintenance DB and every repository query
 * would return empty (literally happened during the v0.1.53 rollout).
 * Keep BOTH beans explicit so the wiring is unambiguous.
 */
@Configuration
public class CnpgSuperuserDataSourceConfig {

    /**
     * Re-creates the primary DataSource that Spring Boot would normally
     * autoconfigure from {@code spring.datasource.*}. We must declare it
     * explicitly because adding ANY second {@link DataSource} bean
     * suppresses auto-configuration entirely.
     */
    @Bean
    @Primary
    public DataSource primaryDataSource(
        @Value("${spring.datasource.url}") String url,
        @Value("${spring.datasource.username}") String username,
        @Value("${spring.datasource.password}") String password
    ) {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(url);
        cfg.setUsername(username);
        cfg.setPassword(password);
        cfg.setPoolName("HikariPool-1");
        return new HikariDataSource(cfg);
    }

    @Bean(name = "cnpgSuperuserDataSource", destroyMethod = "close")
    public DataSource cnpgSuperuserDataSource(
        @Value("${platform-pg.superuser.url}") String url,
        @Value("${platform-pg.superuser.username}") String username,
        @Value("${platform-pg.superuser.password}") String password
    ) {
        HikariConfig cfg = new HikariConfig();
        cfg.setJdbcUrl(url);
        cfg.setUsername(username);
        cfg.setPassword(password);
        cfg.setPoolName("cnpg-superuser-pool");
        // Ops-only path (provision / deprovision invoked manually by operator).
        cfg.setMaximumPoolSize(2);
        cfg.setMinimumIdle(0);
        cfg.setIdleTimeout(60_000);
        return new HikariDataSource(cfg);
    }
}
