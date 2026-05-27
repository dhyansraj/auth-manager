package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.audit.ActorKind;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.sql.DataSource;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Provisions per-tenant Postgres databases on the shared CNPG cluster
 * (platform-pg). One database + one owner-user per tenant; password is
 * generated randomly and returned ONCE on the provision call (same
 * reveal-once pattern as KC client secrets — auth-manager doesn't persist
 * the password anywhere).
 *
 * <p>Source of truth for "does the tenant have a DB?" is CNPG itself —
 * we query {@code pg_database} on the maintenance DB rather than tracking
 * a column in our own tables. This keeps the operator workflow honest
 * (the DB row tracks reality, not intent).
 */
@Service
public class TenantDatabaseService {

    private static final Logger log = LoggerFactory.getLogger(TenantDatabaseService.class);

    private static final String CNPG_HOST = "platform-pg-rw.auth-platform.svc.cluster.local";
    private static final int CNPG_PORT = 5432;
    private static final int CONNECTION_LIMIT = 50;

    /** Defense-in-depth slug validation before string-interpolating into DDL. */
    private static final Pattern SAFE_SLUG = Pattern.compile("^[a-z0-9][a-z0-9-]{0,49}$");

    /** URL-safe alphanumeric — no characters that need escaping in env files / URLs. */
    private static final char[] PASSWORD_ALPHABET =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    private final JdbcTemplate jdbc;
    private final AuditService audit;
    private final SecureRandom random = new SecureRandom();

    public TenantDatabaseService(
        @Qualifier("cnpgSuperuserDataSource") DataSource cnpgSuperuserDataSource,
        AuditService audit
    ) {
        this.jdbc = new JdbcTemplate(cnpgSuperuserDataSource);
        this.audit = audit;
    }

    public record ProvisionResult(
        String host,
        int port,
        String database,
        String username,
        String password,
        String jdbcUrl
    ) {}

    /** True iff a database named {@code t_<slug>} exists on the cluster. */
    public boolean existsFor(String slug) {
        String dbName = dbNameFor(slug);
        Integer present = jdbc.query(
            "SELECT 1 FROM pg_database WHERE datname = ?",
            ps -> ps.setString(1, dbName),
            rs -> rs.next() ? 1 : 0
        );
        return present != null && present == 1;
    }

    /**
     * CREATE USER + CREATE DATABASE + GRANT. Returns the connection
     * coordinates including the freshly-generated password (reveal-once).
     */
    public ProvisionResult provisionFor(Tenant tenant, String actor) {
        String slug = tenant.getSlug();
        validateSlug(slug);

        String dbName = dbNameFor(slug);
        String userName = dbName;

        if (existsFor(slug)) {
            throw new IllegalStateException(
                "Database " + dbName + " already provisioned for tenant '" + slug + "'");
        }

        String password = randomPassword(32);

        try {
            // CREATE USER / CREATE DATABASE cannot use prepared parameters,
            // so we string-interpolate after strict slug validation.
            // Identifier is double-quoted; password is single-quoted with any
            // literal single quotes doubled (paranoia — randomPassword only
            // emits alphanumerics so there will never be a single quote).
            String escapedPassword = password.replace("'", "''");
            jdbc.execute(
                "CREATE USER \"" + userName + "\""
                + " WITH PASSWORD '" + escapedPassword + "'"
                + " CONNECTION LIMIT " + CONNECTION_LIMIT
            );
            try {
                jdbc.execute("CREATE DATABASE \"" + dbName + "\" OWNER \"" + userName + "\"");
                jdbc.execute(
                    "GRANT ALL PRIVILEGES ON DATABASE \"" + dbName + "\" TO \"" + userName + "\""
                );
            } catch (RuntimeException e) {
                // CREATE DATABASE failed after CREATE USER — clean up the
                // orphan role so a retry isn't stuck on "user already exists".
                try {
                    jdbc.execute("DROP USER IF EXISTS \"" + userName + "\"");
                } catch (RuntimeException rollbackErr) {
                    log.warn("Failed to roll back orphan user {} after DB create failed: {}",
                        userName, rollbackErr.getMessage());
                }
                throw e;
            }
        } catch (RuntimeException e) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("slug", slug);
            details.put("database", dbName);
            details.put("username", userName);
            audit.recordFailure(actor, ActorKind.USER, tenant.getId(),
                "tenant.db.provision", "database", dbName, null, e, details);
            throw e;
        }

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("slug", slug);
        details.put("database", dbName);
        details.put("username", userName);
        audit.recordSuccess(actor, ActorKind.USER, tenant.getId(),
            "tenant.db.provision", "database", dbName, null, details);

        return new ProvisionResult(
            CNPG_HOST,
            CNPG_PORT,
            dbName,
            userName,
            password,
            "jdbc:postgresql://" + CNPG_HOST + ":" + CNPG_PORT + "/" + dbName
        );
    }

    /**
     * Drops the database + user. Idempotent — silently returns when the
     * database is already absent.
     */
    public void deprovisionFor(Tenant tenant, String actor) {
        String slug = tenant.getSlug();
        validateSlug(slug);

        String dbName = dbNameFor(slug);
        String userName = dbName;

        if (!existsFor(slug)) {
            return;
        }

        try {
            // Order matters: REVOKE before DROP DATABASE (otherwise the role
            // still has dependencies blocking DROP USER). FORCE in DROP
            // DATABASE evicts active connections so tenants accidentally
            // holding connections don't block deprovision.
            try {
                jdbc.execute(
                    "REVOKE ALL ON DATABASE \"" + dbName + "\" FROM \"" + userName + "\""
                );
            } catch (RuntimeException e) {
                log.debug("REVOKE failed (likely role/db already partially gone): {}", e.getMessage());
            }
            jdbc.execute("DROP DATABASE IF EXISTS \"" + dbName + "\" WITH (FORCE)");
            jdbc.execute("DROP USER IF EXISTS \"" + userName + "\"");
        } catch (RuntimeException e) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("slug", slug);
            details.put("database", dbName);
            audit.recordFailure(actor, ActorKind.USER, tenant.getId(),
                "tenant.db.deprovision", "database", dbName, null, e, details);
            throw e;
        }

        Map<String, Object> details = new LinkedHashMap<>();
        details.put("slug", slug);
        details.put("database", dbName);
        audit.recordSuccess(actor, ActorKind.USER, tenant.getId(),
            "tenant.db.deprovision", "database", dbName, null, details);
    }

    /**
     * Map a tenant slug to its canonical database/user identifier:
     * {@code t_<slug-with-hyphens-as-underscores>}. Postgres allows hyphens
     * in quoted identifiers but it's a constant source of pain in env files
     * and connection strings — sticking to {@code [a-z0-9_]} keeps everything
     * downstream simple.
     */
    public static String dbNameFor(String slug) {
        return "t_" + slug.replace('-', '_');
    }

    private static void validateSlug(String slug) {
        if (slug == null || !SAFE_SLUG.matcher(slug).matches()) {
            throw new IllegalArgumentException(
                "Refusing to interpolate unsafe slug into DDL: " + slug);
        }
    }

    private String randomPassword(int len) {
        StringBuilder sb = new StringBuilder(len);
        for (int i = 0; i < len; i++) {
            sb.append(PASSWORD_ALPHABET[random.nextInt(PASSWORD_ALPHABET.length)]);
        }
        return sb.toString();
    }
}
