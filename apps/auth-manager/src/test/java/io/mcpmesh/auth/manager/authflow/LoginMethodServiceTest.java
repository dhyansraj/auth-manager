package io.mcpmesh.auth.manager.authflow;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.ArgumentCaptor;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LoginMethodService} — the realm-attribute + theme-CSS
 * implementation of the per-tenant password-login toggle.
 *
 * <p>The service no longer mutates KC auth flows. The only KC interaction is
 * a read + write of the realm attribute {@code mcpmesh.passwordLoginEnabled}.
 * Tests verify (a) attribute persistence, (b) default-true semantics when
 * the attribute is absent, and (c) the "must have at least one login method"
 * invariant.
 */
class LoginMethodServiceTest {

    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000123");
    private static final String SLUG = "app1";
    private static final String REALM = "t-" + SLUG;

    TenantService tenants;
    Keycloak kcAdmin;
    IdentityProvidersBootstrap idp;
    AuditService audit;

    RealmResource realmResource;
    RealmRepresentation realmRep;

    LoginMethodService service;
    Tenant tenant;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        kcAdmin = mock(Keycloak.class);
        idp = mock(IdentityProvidersBootstrap.class);
        audit = mock(AuditService.class);
        realmResource = mock(RealmResource.class);
        realmRep = new RealmRepresentation();

        when(kcAdmin.realm(REALM)).thenReturn(realmResource);
        when(realmResource.toRepresentation()).thenReturn(realmRep);

        service = new LoginMethodService(tenants, kcAdmin, idp, audit);

        tenant = newTenant(SLUG, "App 1");
        when(tenants.get(TENANT_ID)).thenReturn(tenant);
    }

    @Test
    void setPasswordEnabled_false_writesAttributeFalse() {
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));

        service.setPasswordEnabled(TENANT_ID, false, "alice");

        ArgumentCaptor<RealmRepresentation> captor = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(realmResource).update(captor.capture());
        RealmRepresentation updated = captor.getValue();
        assertThat(updated.getAttributes())
            .containsEntry(LoginMethodService.PASSWORD_ENABLED_ATTR, "false");
        verify(audit).recordSuccess(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any());
    }

    @Test
    void setPasswordEnabled_true_writesAttributeTrue() {
        when(idp.listEnabledProviders(REALM)).thenReturn(Set.of());
        // Simulate the attribute currently being "false".
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put(LoginMethodService.PASSWORD_ENABLED_ATTR, "false");
        realmRep.setAttributes(attrs);

        service.setPasswordEnabled(TENANT_ID, true, "alice");

        ArgumentCaptor<RealmRepresentation> captor = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(realmResource).update(captor.capture());
        assertThat(captor.getValue().getAttributes())
            .containsEntry(LoginMethodService.PASSWORD_ENABLED_ATTR, "true");
    }

    @Test
    void setPasswordEnabled_true_preservesExistingAttributes() {
        when(idp.listEnabledProviders(REALM)).thenReturn(Set.of());
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("some.other.key", "preserve-me");
        attrs.put(LoginMethodService.PASSWORD_ENABLED_ATTR, "false");
        realmRep.setAttributes(attrs);

        service.setPasswordEnabled(TENANT_ID, true, "alice");

        ArgumentCaptor<RealmRepresentation> captor = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(realmResource).update(captor.capture());
        assertThat(captor.getValue().getAttributes())
            .containsEntry("some.other.key", "preserve-me")
            .containsEntry(LoginMethodService.PASSWORD_ENABLED_ATTR, "true");
    }

    @Test
    void setPasswordEnabled_false_refusesWhenZeroIdpsEnabled() {
        when(idp.listEnabledProviders(REALM)).thenReturn(Set.of());

        assertThatThrownBy(() -> service.setPasswordEnabled(TENANT_ID, false, "alice"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("no_methods_remaining");

        verify(realmResource, never()).update(any(RealmRepresentation.class));
        verify(audit).recordFailure(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any(), any());
    }

    @Test
    void setPasswordEnabled_true_alwaysSucceeds_evenWithNoIdps() {
        // Enabling password on a realm with zero IdPs is fine — we still have
        // a login method (password).
        when(idp.listEnabledProviders(REALM)).thenReturn(Set.of());

        LoginMethodStatus status = service.setPasswordEnabled(TENANT_ID, true, "alice");

        ArgumentCaptor<RealmRepresentation> captor = ArgumentCaptor.forClass(RealmRepresentation.class);
        verify(realmResource).update(captor.capture());
        assertThat(captor.getValue().getAttributes())
            .containsEntry(LoginMethodService.PASSWORD_ENABLED_ATTR, "true");
        assertThat(status.passwordEnabled()).isTrue();
    }

    @Test
    void isPasswordEnabled_defaultsTrueWhenAttributeAbsent() {
        // Fresh realm — no attributes map at all.
        realmRep.setAttributes(null);

        assertThat(service.isPasswordEnabled(REALM)).isTrue();
    }

    @Test
    void isPasswordEnabled_defaultsTrueWhenKeyMissingFromAttributes() {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put("unrelated.key", "value");
        realmRep.setAttributes(attrs);

        assertThat(service.isPasswordEnabled(REALM)).isTrue();
    }

    @Test
    void isPasswordEnabled_returnsFalseWhenAttributeFalse() {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put(LoginMethodService.PASSWORD_ENABLED_ATTR, "false");
        realmRep.setAttributes(attrs);

        assertThat(service.isPasswordEnabled(REALM)).isFalse();
    }

    @Test
    void isPasswordEnabled_returnsTrueWhenAttributeTrue() {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put(LoginMethodService.PASSWORD_ENABLED_ATTR, "true");
        realmRep.setAttributes(attrs);

        assertThat(service.isPasswordEnabled(REALM)).isTrue();
    }

    @Test
    void checkSetIdpEnabled_refusesDisablingLastIdpWhenPasswordOff() {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put(LoginMethodService.PASSWORD_ENABLED_ATTR, "false");
        realmRep.setAttributes(attrs);
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));

        assertThatThrownBy(() -> service.checkSetIdpEnabled(TENANT_ID, "google", false))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("no_methods_remaining");
    }

    @Test
    void checkSetIdpEnabled_allowsDisablingIdpWhenPasswordOn() {
        // Attribute absent → default ON.
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));

        // Should not throw.
        service.checkSetIdpEnabled(TENANT_ID, "google", false);
    }

    @Test
    void checkSetIdpEnabled_allowsDisablingNonLastIdpWhenPasswordOff() {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put(LoginMethodService.PASSWORD_ENABLED_ATTR, "false");
        realmRep.setAttributes(attrs);
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google", "github")));

        // Disabling github still leaves google → fine.
        service.checkSetIdpEnabled(TENANT_ID, "github", false);
    }

    @Test
    void checkSetIdpEnabled_isNoOpWhenWantEnabledTrue() {
        // Enable path never checks anything — no realm fetch even needed.
        service.checkSetIdpEnabled(TENANT_ID, "google", true);
        verify(tenants, never()).get(any(UUID.class));
    }

    @Test
    void get_reflectsAttributeAndIdpList() {
        Map<String, String> attrs = new LinkedHashMap<>();
        attrs.put(LoginMethodService.PASSWORD_ENABLED_ATTR, "false");
        realmRep.setAttributes(attrs);
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google", "github")));

        LoginMethodStatus status = service.get(TENANT_ID);

        assertThat(status.passwordEnabled()).isFalse();
        assertThat(status.enabledIdpAliases()).containsExactly("google", "github");
    }

    // -- helpers --------------------------------------------------------------

    private static Tenant newTenant(String slug, String displayName) {
        Tenant t = new Tenant(slug, displayName, "system", new HashMap<>());
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
