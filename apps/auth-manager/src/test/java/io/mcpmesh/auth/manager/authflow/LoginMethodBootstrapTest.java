package io.mcpmesh.auth.manager.authflow;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.DefaultApplicationArguments;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LoginMethodBootstrap}. Verifies that the startup pass
 * reverts every active tenant realm's {@code browserFlow} from the cloned
 * {@code mcpmesh-browser} alias back to KC's built-in {@code browser}, and is
 * a no-op for realms already on the built-in.
 */
class LoginMethodBootstrapTest {

    TenantRepository tenantRepo;
    Keycloak kcAdmin;
    LoginMethodBootstrap bootstrap;

    @BeforeEach
    void setUp() {
        tenantRepo = mock(TenantRepository.class);
        kcAdmin = mock(Keycloak.class);
        bootstrap = new LoginMethodBootstrap(tenantRepo, kcAdmin);
    }

    @Test
    void revertsRealmOnMcpmeshBrowserToBuiltin() {
        Tenant t = newTenant("happyfeet");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc()).thenReturn(List.of(t));

        RealmResource realmResource = mock(RealmResource.class);
        RealmRepresentation rep = new RealmRepresentation();
        rep.setBrowserFlow(LoginMethodBootstrap.MCPMESH_BROWSER_FLOW);
        when(kcAdmin.realm("t-happyfeet")).thenReturn(realmResource);
        when(realmResource.toRepresentation()).thenReturn(rep);

        bootstrap.run(new DefaultApplicationArguments());

        ArgumentCaptor<RealmRepresentation> captor = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(realmResource).update(captor.capture());
        assertThat(captor.getValue().getBrowserFlow())
            .isEqualTo(LoginMethodBootstrap.BUILTIN_BROWSER_FLOW);
    }

    @Test
    void isNoOpForRealmAlreadyOnBuiltinBrowser() {
        Tenant t = newTenant("app1");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc()).thenReturn(List.of(t));

        RealmResource realmResource = mock(RealmResource.class);
        RealmRepresentation rep = new RealmRepresentation();
        rep.setBrowserFlow(LoginMethodBootstrap.BUILTIN_BROWSER_FLOW);
        when(kcAdmin.realm("t-app1")).thenReturn(realmResource);
        when(realmResource.toRepresentation()).thenReturn(rep);

        bootstrap.run(new DefaultApplicationArguments());

        verify(realmResource, never()).update(any(RealmRepresentation.class));
    }

    @Test
    void skipsNonTenantRealms() {
        // Tenants whose realmName doesn't start with "t-" are skipped (e.g. the
        // master realm or platform-internal realms). No KC interaction at all.
        Tenant t = new Tenant("master", "Master", "system", new HashMap<>());
        setField(t, "id", UUID.randomUUID());
        setField(t, "realmName", "master");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc()).thenReturn(List.of(t));

        bootstrap.run(new DefaultApplicationArguments());

        verify(kcAdmin, never()).realm(any());
    }

    @Test
    void perRealmFailureDoesNotAbortBatch() {
        Tenant t1 = newTenant("bad");
        Tenant t2 = newTenant("good");
        when(tenantRepo.findAllByDeletedAtIsNullOrderByCreatedAtDesc())
            .thenReturn(List.of(t1, t2));

        // First realm: kcAdmin.realm() throws.
        when(kcAdmin.realm("t-bad")).thenThrow(new RuntimeException("boom"));

        // Second realm: needs revert.
        RealmResource goodRealm = mock(RealmResource.class);
        RealmRepresentation goodRep = new RealmRepresentation();
        goodRep.setBrowserFlow(LoginMethodBootstrap.MCPMESH_BROWSER_FLOW);
        when(kcAdmin.realm("t-good")).thenReturn(goodRealm);
        when(goodRealm.toRepresentation()).thenReturn(goodRep);

        bootstrap.run(new DefaultApplicationArguments());

        // Good tenant still got reverted despite the bad one's failure.
        verify(goodRealm).update(any(RealmRepresentation.class));
    }

    private static Tenant newTenant(String slug) {
        Tenant t = new Tenant(slug, slug, "system", new HashMap<>());
        setField(t, "id", UUID.randomUUID());
        setField(t, "realmName", "t-" + slug);
        return t;
    }

    private static void setField(Object target, String name, Object value) {
        try {
            Field f = target.getClass().getDeclaredField(name);
            f.setAccessible(true);
            f.set(target, value);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }
}
