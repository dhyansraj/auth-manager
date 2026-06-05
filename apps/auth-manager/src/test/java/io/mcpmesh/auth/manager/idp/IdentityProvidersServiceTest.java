package io.mcpmesh.auth.manager.idp;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.authflow.LoginMethodService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IdentityProvidersService}. Specifically validates
 * that toggling an IdP OFF persists the alias on
 * {@code tenant.settings.disabledIdps} so a subsequent bootstrap pass won't
 * re-create it (bug fix: HF GitHub re-enable after pod restart).
 */
class IdentityProvidersServiceTest {

    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000abc");
    private static final String SLUG = "app1";
    private static final String REALM = "t-" + SLUG;

    private TenantService tenants;
    private TenantRepository tenantRepo;
    private IdentityProvidersBootstrap idp;
    private KeycloakAdminService keycloak;
    private AuditService audit;
    private LoginMethodService loginMethods;

    private IdentityProvidersService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        tenantRepo = mock(TenantRepository.class);
        idp = mock(IdentityProvidersBootstrap.class);
        keycloak = mock(KeycloakAdminService.class);
        audit = mock(AuditService.class);
        loginMethods = mock(LoginMethodService.class);

        service = new IdentityProvidersService(tenants, tenantRepo, idp, keycloak, audit, loginMethods);

        tenant = newTenant();
        when(tenants.getBySlug(SLUG)).thenReturn(tenant);
        when(idp.isAvailable(anyString())).thenReturn(true);
    }

    @Test
    void toggleOff_persistsAliasInDisabledSet_andRemovesFromKc() {
        // Currently enabled in KC.
        when(idp.isEnabled(REALM, "github")).thenReturn(true);

        IdentityProviderDto result = service.setEnabled(SLUG, "github", false, "alice");

        // Tenant entity now records github as operator-disabled.
        assertThat(tenant.getDisabledIdps()).contains("github");
        // Persisted via repo save.
        verify(tenantRepo).save(tenant);
        // KC remove was called.
        verify(idp).removeProvider(REALM, "github");
        // Audit success.
        verify(audit).recordSuccess(anyString(), any(), any(),
            eq("idp.disable"), anyString(), eq("github"), any(), any());
        assertThat(result.id()).isEqualTo("github");
    }

    @Test
    void toggleOn_clearsAliasFromDisabledSet_andAddsToKc() {
        // Tenant previously had github disabled.
        tenant.setIdpDisabled("github", true);
        when(idp.isEnabled(REALM, "github")).thenReturn(false);

        service.setEnabled(SLUG, "github", true, "alice");

        // Disabled-set cleared.
        assertThat(tenant.getDisabledIdps()).doesNotContain("github");
        verify(tenantRepo).save(tenant);
        verify(idp).addProvider(REALM, "github");
        verify(audit).recordSuccess(anyString(), any(), any(),
            eq("idp.enable"), anyString(), eq("github"), any(), any());
    }

    @Test
    void setInviteOnly_persistsFlag_appliesKc_andAudits() {
        RegistrationStateDto result = service.setInviteOnly(SLUG, true, "alice");

        assertThat(tenant.isInviteOnly()).isTrue();
        verify(tenantRepo).save(tenant);
        verify(keycloak).setInviteOnly(REALM, true);
        verify(audit).recordSuccess(anyString(), any(), any(),
            eq("tenant.invite_only.set"), eq("tenant"), eq(SLUG), any(), any());
        assertThat(result.inviteOnly()).isTrue();
        assertThat(result.registrationAllowed()).isFalse();
    }

    @Test
    void getRegistrationState_reflectsTenantFlag() {
        tenant.setInviteOnly(true);
        RegistrationStateDto state = service.getRegistrationState(SLUG);
        assertThat(state.inviteOnly()).isTrue();
        assertThat(state.registrationAllowed()).isFalse();
    }

    private static Tenant newTenant() {
        Tenant t = new Tenant(SLUG, "App 1", "system", new HashMap<>());
        setField(t, "id", TENANT_ID);
        setField(t, "realmName", REALM);
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
