package io.mcpmesh.auth.manager.authflow;

import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.keycloak.IdentityProvidersBootstrap;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthenticationManagementResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.AuthenticationExecutionInfoRepresentation;
import org.keycloak.representations.idm.AuthenticationFlowRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.springframework.web.server.ResponseStatusException;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link LoginMethodService}. Stubs the KC admin client at the
 * flows() / realm() level and validates the clone-on-first-call behavior,
 * the password-toggle requirement flip, and the "no methods remaining"
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
    AuthenticationManagementResource flowsResource;
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
        flowsResource = mock(AuthenticationManagementResource.class);
        realmRep = new RealmRepresentation();
        realmRep.setBrowserFlow(LoginMethodService.BUILTIN_BROWSER_FLOW);

        when(kcAdmin.realm(REALM)).thenReturn(realmResource);
        when(realmResource.toRepresentation()).thenReturn(realmRep);
        when(realmResource.flows()).thenReturn(flowsResource);

        service = new LoginMethodService(tenants, kcAdmin, idp, audit);

        tenant = newTenant(SLUG, "App 1");
        when(tenants.get(TENANT_ID)).thenReturn(tenant);
    }

    @Test
    void setPasswordEnabled_false_refusesWhenZeroIdpsEnabled() {
        when(idp.listEnabledProviders(REALM)).thenReturn(Set.of());

        assertThatThrownBy(() -> service.setPasswordEnabled(TENANT_ID, false, "alice"))
            .isInstanceOf(ResponseStatusException.class)
            .hasMessageContaining("no_methods_remaining");

        // Should not clone the flow on a refused call.
        verify(flowsResource, never()).copy(anyString(), any());
        verify(flowsResource, never()).updateExecutions(anyString(), any());
        verify(audit).recordFailure(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any(), any());
    }

    @Test
    void setPasswordEnabled_false_succeedsWithAtLeastOneIdp() {
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));
        // No flows yet — copy() will be called.
        when(flowsResource.getFlows()).thenReturn(List.of());
        Response copyResp = mock(Response.class);
        when(copyResp.getStatus()).thenReturn(201);
        when(flowsResource.copy(eq(LoginMethodService.BUILTIN_BROWSER_FLOW), any()))
            .thenReturn(copyResp);

        // For the post-mutation get() in the service return, executions show
        // the password form as DISABLED after the flip + REQUIRED for the
        // initial isPasswordEnabled check used by the audit/log line.
        AuthenticationExecutionInfoRepresentation passwordExec = makeExec("Username Password Form", "REQUIRED");
        List<AuthenticationExecutionInfoRepresentation> execs = new ArrayList<>(List.of(passwordExec));
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW)).thenReturn(execs);

        LoginMethodStatus status = service.setPasswordEnabled(TENANT_ID, false, "alice");

        verify(flowsResource).copy(eq(LoginMethodService.BUILTIN_BROWSER_FLOW), any());
        verify(realmResource).update(realmRep);
        assertThat(realmRep.getBrowserFlow()).isEqualTo(LoginMethodService.MCPMESH_BROWSER_FLOW);
        verify(flowsResource).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(passwordExec.getRequirement()).isEqualTo("DISABLED");
        assertThat(status.passwordEnabled()).isFalse();
        verify(audit).recordSuccess(anyString(), any(), any(), anyString(),
            anyString(), anyString(), any(), any());
    }

    @Test
    void setPasswordEnabled_true_alwaysSucceeds_evenWithNoIdps() {
        when(idp.listEnabledProviders(REALM)).thenReturn(Set.of());
        when(flowsResource.getFlows()).thenReturn(List.of());
        Response copyResp = mock(Response.class);
        when(copyResp.getStatus()).thenReturn(201);
        when(flowsResource.copy(eq(LoginMethodService.BUILTIN_BROWSER_FLOW), any()))
            .thenReturn(copyResp);
        AuthenticationExecutionInfoRepresentation passwordExec = makeExec("Username Password Form", "DISABLED");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(List.of(passwordExec)));

        LoginMethodStatus status = service.setPasswordEnabled(TENANT_ID, true, "alice");

        verify(flowsResource).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(passwordExec.getRequirement()).isEqualTo("REQUIRED");
        assertThat(status.passwordEnabled()).isTrue();
    }

    @Test
    void cloneHappensOnFirstCall_whenRealmUsesBuiltinBrowser() {
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));
        // No mcpmesh-browser flow exists yet — copy() should be called.
        when(flowsResource.getFlows()).thenReturn(List.of(builtinFlowRepr()));
        Response copyResp = mock(Response.class);
        when(copyResp.getStatus()).thenReturn(201);
        when(flowsResource.copy(eq(LoginMethodService.BUILTIN_BROWSER_FLOW), any()))
            .thenReturn(copyResp);
        AuthenticationExecutionInfoRepresentation passwordExec = makeExec("Username Password Form", "REQUIRED");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(List.of(passwordExec)));

        service.setPasswordEnabled(TENANT_ID, true, "alice");

        verify(flowsResource).copy(eq(LoginMethodService.BUILTIN_BROWSER_FLOW), any());
        verify(realmResource).update(realmRep);
    }

    @Test
    void subsequentCalls_doNotRecloneFlow() {
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));
        // Realm already points at mcpmesh-browser → no clone, no realm.update().
        realmRep.setBrowserFlow(LoginMethodService.MCPMESH_BROWSER_FLOW);
        AuthenticationExecutionInfoRepresentation passwordExec = makeExec("Username Password Form", "REQUIRED");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(List.of(passwordExec)));

        service.setPasswordEnabled(TENANT_ID, false, "alice");

        verify(flowsResource, never()).copy(anyString(), any());
        verify(realmResource, never()).update(any(RealmRepresentation.class));
        verify(flowsResource).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(passwordExec.getRequirement()).isEqualTo("DISABLED");
    }

    // -- helpers --------------------------------------------------------------

    private static AuthenticationExecutionInfoRepresentation makeExec(String displayName, String requirement) {
        AuthenticationExecutionInfoRepresentation e = new AuthenticationExecutionInfoRepresentation();
        e.setDisplayName(displayName);
        e.setRequirement(requirement);
        return e;
    }

    private static AuthenticationFlowRepresentation builtinFlowRepr() {
        AuthenticationFlowRepresentation f = new AuthenticationFlowRepresentation();
        f.setAlias(LoginMethodService.BUILTIN_BROWSER_FLOW);
        return f;
    }

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
