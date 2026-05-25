package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.UsermanagementBootstrap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DefaultRolesBootstrap} -- focuses on the startup
 * backfill loop that re-establishes per-tenant KC state across every active
 * tenant realm. Stubs all KC + bootstrap collaborators.
 */
class DefaultRolesBootstrapTest {

    private KeycloakAdminService keycloak;
    private TenantRepository tenantRepo;
    private UsermanagementBootstrap usermgmtBootstrap;
    private DefaultRolesBootstrap bootstrap;

    @BeforeEach
    void setUp() {
        keycloak = mock(KeycloakAdminService.class);
        tenantRepo = mock(TenantRepository.class);
        usermgmtBootstrap = mock(UsermanagementBootstrap.class);
        bootstrap = new DefaultRolesBootstrap(keycloak, tenantRepo, usermgmtBootstrap);
    }

    private Tenant tenant(String slug, String realmName) {
        Tenant t = mock(Tenant.class);
        when(t.getId()).thenReturn(UUID.randomUUID());
        when(t.getSlug()).thenReturn(slug);
        when(t.getRealmName()).thenReturn(realmName);
        return t;
    }

    @Test
    void backfill_callsRedirectUriSetterForEveryTenantRealm() {
        // Two active tenants, both with proper "t-" realm prefix and a
        // usermanagement client present. We expect ensureStandardRedirectUris
        // to be called once per tenant.
        Tenant app1 = tenant("app1", "t-app1");
        Tenant app2 = tenant("app2", "t-app2");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc())
            .thenReturn(List.of(app1, app2));
        when(keycloak.findClientUuid("t-app1", UsermanagementBootstrap.CLIENT_SLUG))
            .thenReturn(Optional.of("uuid-app1"));
        when(keycloak.findClientUuid("t-app2", UsermanagementBootstrap.CLIENT_SLUG))
            .thenReturn(Optional.of("uuid-app2"));

        bootstrap.run(null);

        verify(usermgmtBootstrap, times(1)).ensureStandardRedirectUris(app1, "uuid-app1");
        verify(usermgmtBootstrap, times(1)).ensureStandardRedirectUris(app2, "uuid-app2");
    }

    @Test
    void backfill_skipsTenantsWithoutUsermanagementClient() {
        // Tenant exists in DB but the realm doesn't have a usermanagement
        // client (e.g. the realm was hand-deleted but the DB row remained).
        Tenant ghost = tenant("ghost", "t-ghost");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc())
            .thenReturn(List.of(ghost));
        when(keycloak.findClientUuid("t-ghost", UsermanagementBootstrap.CLIENT_SLUG))
            .thenReturn(Optional.empty());

        bootstrap.run(null);

        verify(usermgmtBootstrap, never()).ensureStandardRedirectUris(any(), any());
    }

    @Test
    void backfill_skipsTenantsWithoutRealmNameOrWithWrongPrefix() {
        // Tenant with null realm (e.g. provisioning failed) -- skip entirely.
        Tenant pending = tenant("pending", null);
        // Tenant whose realmName doesn't start with "t-" (e.g. "master" left
        // by a mis-imported row) -- skip entirely.
        Tenant odd = tenant("odd", "master");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc())
            .thenReturn(List.of(pending, odd));

        bootstrap.run(null);

        verify(keycloak, never()).findClientUuid(eq("master"), any());
        verify(usermgmtBootstrap, never()).ensureStandardRedirectUris(any(), any());
    }

    @Test
    void backfill_perRealmFailureDoesNotAbortLoop() {
        // First tenant throws on lookup; second tenant must still get processed.
        Tenant broken = tenant("broken", "t-broken");
        Tenant healthy = tenant("healthy", "t-healthy");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc())
            .thenReturn(List.of(broken, healthy));
        when(keycloak.findClientUuid("t-broken", UsermanagementBootstrap.CLIENT_SLUG))
            .thenThrow(new RuntimeException("connection refused"));
        when(keycloak.findClientUuid("t-healthy", UsermanagementBootstrap.CLIENT_SLUG))
            .thenReturn(Optional.of("uuid-healthy"));

        bootstrap.run(null);

        verify(usermgmtBootstrap, times(1)).ensureStandardRedirectUris(healthy, "uuid-healthy");
        verify(usermgmtBootstrap, never()).ensureStandardRedirectUris(eq(broken), any());
    }

    @Test
    void backfill_topLevelFailureIsSwallowed() {
        // The startup loop must NEVER propagate an exception (would crash the
        // entire app context). Simulate a repo lookup failure.
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc())
            .thenThrow(new RuntimeException("DB connection refused"));

        // Should not throw.
        bootstrap.run(null);
    }
}
