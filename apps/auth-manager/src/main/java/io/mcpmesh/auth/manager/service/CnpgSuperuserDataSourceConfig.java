package io.mcpmesh.auth.manager.service;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/**
 * Secondary DataSource pointing at the CNPG superuser connection on the
 * shared platform-pg cluster's maintenance database ({@code postgres}).
 * Used exclusively by {@link TenantDatabaseService} to run CREATE
 * USER / CREATE DATABASE / DROP DATABASE DDL when provisioning per-tenant
 * databases.
 *
 * <p>The primary app DataSource (configured via {@code spring.datasource.*})
 * uses the {@code authmanager} role on the {@code authmanager} database
 * and stays untouched.
 */
@Configuration
public class CnpgSuperuserDataSourceConfig {

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
