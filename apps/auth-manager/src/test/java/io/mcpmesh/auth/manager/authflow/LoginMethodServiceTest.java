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
 * the password-toggle requirement flip across {@code Forms}, the UPF leaf,
 * and (KC v26+) the {@code Organization} subflow, plus the "no methods
 * remaining" invariant.
 *
 * <p>Flow layouts in this test mirror the verified-live KC v26 structure of
 * the cloned {@code mcpmesh-browser} flow on a real tenant realm:
 *
 * <pre>
 * level 0: Cookie                            (authenticator)
 * level 0: Identity Provider Redirector      (authenticator)
 * level 0: mcpmesh-browser Organization      (subflow)        ← Organization parent
 * level 1:   organization (Org Identity-First)  (authenticator, providerId=organization)
 * level 1:   mcpmesh-browser Browser - Conditional Organization (subflow, CONDITIONAL)
 * level 2:     condition-user-configured     (authenticator)
 * level 0: mcpmesh-browser forms             (subflow)        ← Forms parent
 * level 1:   auth-username-password-form     (authenticator, providerId=auth-username-password-form)
 * level 1:   mcpmesh-browser Browser - Conditional 2FA (subflow, CONDITIONAL)
 * level 2:     condition-user-configured     (authenticator)
 * </pre>
 *
 * <p>Note: KC v26 prefixes cloned-subflow display names with the parent flow
 * alias, so {@code "forms"} becomes {@code "mcpmesh-browser forms"}. We
 * intentionally use realistic display names (and at least one arbitrary one)
 * to guard against any future regression that hard-codes a name match.
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

        Kcv26FlowLayout layout = kcv26Layout("REQUIRED", "ALTERNATIVE", "ALTERNATIVE");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(layout.all));

        LoginMethodStatus status = service.setPasswordEnabled(TENANT_ID, false, "alice");

        verify(flowsResource).copy(eq(LoginMethodService.BUILTIN_BROWSER_FLOW), any());
        verify(realmResource).update(realmRep);
        assertThat(realmRep.getBrowserFlow()).isEqualTo(LoginMethodService.MCPMESH_BROWSER_FLOW);
        // Forms, UPF, AND Organization should all be PUT.
        verify(flowsResource, times(3)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(layout.upf.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.forms.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.organization.getRequirement()).isEqualTo("DISABLED");
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
        Kcv26FlowLayout layout = kcv26Layout("DISABLED", "DISABLED", "DISABLED");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(layout.all));

        LoginMethodStatus status = service.setPasswordEnabled(TENANT_ID, true, "alice");

        verify(flowsResource, times(3)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(layout.upf.getRequirement()).isEqualTo("REQUIRED");
        assertThat(layout.forms.getRequirement()).isEqualTo("ALTERNATIVE");
        assertThat(layout.organization.getRequirement()).isEqualTo("ALTERNATIVE");
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
        Kcv26FlowLayout layout = kcv26Layout("REQUIRED", "ALTERNATIVE", "ALTERNATIVE");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(layout.all));

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
        Kcv26FlowLayout layout = kcv26Layout("REQUIRED", "ALTERNATIVE", "ALTERNATIVE");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(layout.all));

        service.setPasswordEnabled(TENANT_ID, false, "alice");

        verify(flowsResource, never()).copy(anyString(), any());
        verify(realmResource, never()).update(any(RealmRepresentation.class));
        verify(flowsResource, times(3)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(layout.upf.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.forms.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.organization.getRequirement()).isEqualTo("DISABLED");
    }

    @Test
    void setPasswordEnabled_false_disablesFormsUpfAndOrganization() {
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));
        realmRep.setBrowserFlow(LoginMethodService.MCPMESH_BROWSER_FLOW);
        Kcv26FlowLayout layout = kcv26Layout("REQUIRED", "ALTERNATIVE", "ALTERNATIVE");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(layout.all));

        service.setPasswordEnabled(TENANT_ID, false, "alice");

        // All three executions must be PUT to KC and all three end DISABLED.
        verify(flowsResource, times(3)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(layout.forms.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.upf.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.organization.getRequirement()).isEqualTo("DISABLED");
    }

    @Test
    void setPasswordEnabled_true_restoresFormsToAlternative_upfToRequired_organizationToAlternative() {
        when(idp.listEnabledProviders(REALM)).thenReturn(Set.of());
        realmRep.setBrowserFlow(LoginMethodService.MCPMESH_BROWSER_FLOW);
        // The broken state from a prior bug: everything DISABLED.
        Kcv26FlowLayout layout = kcv26Layout("DISABLED", "DISABLED", "DISABLED");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(layout.all));

        service.setPasswordEnabled(TENANT_ID, true, "alice");

        verify(flowsResource, times(3)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(layout.forms.getRequirement()).isEqualTo("ALTERNATIVE");
        assertThat(layout.upf.getRequirement()).isEqualTo("REQUIRED");
        assertThat(layout.organization.getRequirement()).isEqualTo("ALTERNATIVE");
    }

    @Test
    void setPasswordEnabled_repairsPartiallyBrokenState_evenWhenLeafAlreadyDisabled() {
        // Simulates a tenant left in the bug-2 broken state:
        // UPF=DISABLED but Forms=ALTERNATIVE, Organization=ALTERNATIVE — exactly
        // what the previous bad fix produced. New code must still PUT all three
        // (no "already correct, skip" early-return).
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));
        realmRep.setBrowserFlow(LoginMethodService.MCPMESH_BROWSER_FLOW);
        Kcv26FlowLayout layout = kcv26Layout("DISABLED", "ALTERNATIVE", "ALTERNATIVE");
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(layout.all));

        service.setPasswordEnabled(TENANT_ID, false, "alice");

        verify(flowsResource, times(3)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(layout.forms.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.upf.getRequirement()).isEqualTo("DISABLED");
        assertThat(layout.organization.getRequirement()).isEqualTo("DISABLED");
    }

    @Test
    void setPasswordEnabled_silentlySkipsOrganization_whenSubflowMissing_olderKc() {
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));
        realmRep.setBrowserFlow(LoginMethodService.MCPMESH_BROWSER_FLOW);
        // Older-KC layout: no Organization subflow / no "organization" leaf.
        var cookie = makeExec("Cookie", "ALTERNATIVE", "auth-cookie", false, 0);
        var idpRedirect = makeExec("Identity Provider Redirector", "ALTERNATIVE",
            "identity-provider-redirector", false, 0);
        var forms = makeSubflow("forms", "ALTERNATIVE", 0);
        var upf = makeExec("Username Password Form", "REQUIRED", "auth-username-password-form", false, 1);
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(List.of(cookie, idpRedirect, forms, upf)));

        service.setPasswordEnabled(TENANT_ID, false, "alice");

        // Only Forms + UPF are PUT; Organization mutation silently skipped.
        verify(flowsResource, times(2)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(forms.getRequirement()).isEqualTo("DISABLED");
        assertThat(upf.getRequirement()).isEqualTo("DISABLED");
    }

    @Test
    void setPasswordEnabled_findsFormsByStructure_ignoringDisplayName() {
        // Forms has an arbitrary displayName ("mcpmesh-browser foo" — could be
        // any KC quirk) but is still the level-0 subflow parent of UPF.
        when(idp.listEnabledProviders(REALM))
            .thenReturn(new LinkedHashSet<>(List.of("google")));
        realmRep.setBrowserFlow(LoginMethodService.MCPMESH_BROWSER_FLOW);
        var cookie = makeExec("Cookie", "ALTERNATIVE", "auth-cookie", false, 0);
        var weirdForms = makeSubflow("mcpmesh-browser foo", "ALTERNATIVE", 0);
        var upf = makeExec("Some Random Display Name", "REQUIRED",
            "auth-username-password-form", false, 1);
        when(flowsResource.getExecutions(LoginMethodService.MCPMESH_BROWSER_FLOW))
            .thenReturn(new ArrayList<>(List.of(cookie, weirdForms, upf)));

        service.setPasswordEnabled(TENANT_ID, false, "alice");

        // Forms identified despite the arbitrary displayName.
        verify(flowsResource, times(2)).updateExecutions(eq(LoginMethodService.MCPMESH_BROWSER_FLOW),
            any(AuthenticationExecutionInfoRepresentation.class));
        assertThat(weirdForms.getRequirement()).isEqualTo("DISABLED");
        assertThat(upf.getRequirement()).isEqualTo("DISABLED");
    }

    // -- helpers --------------------------------------------------------------

    private static AuthenticationExecutionInfoRepresentation makeExec(
            String displayName, String requirement, String providerId,
            boolean authenticationFlow, int level) {
        AuthenticationExecutionInfoRepresentation e = new AuthenticationExecutionInfoRepresentation();
        e.setDisplayName(displayName);
        e.setRequirement(requirement);
        e.setProviderId(providerId);
        e.setAuthenticationFlow(authenticationFlow);
        e.setLevel(level);
        return e;
    }

    private static AuthenticationExecutionInfoRepresentation makeSubflow(
            String displayName, String requirement, int level) {
        // KC's REST returns subflow representations without a providerId.
        return makeExec(displayName, requirement, null, true, level);
    }

    /**
     * Builds a list of executions mirroring the live KC v26 cloned-browser
     * structure, exposing the three mutation targets (forms, upf, organization)
     * as named fields for assertion.
     */
    private static Kcv26FlowLayout kcv26Layout(
            String upfRequirement, String formsRequirement, String organizationRequirement) {
        Kcv26FlowLayout l = new Kcv26FlowLayout();
        var cookie = makeExec("Cookie", "ALTERNATIVE", "auth-cookie", false, 0);
        var kerberos = makeExec("Kerberos", "DISABLED", "auth-spnego", false, 0);
        var idpRedirect = makeExec("Identity Provider Redirector", "ALTERNATIVE",
            "identity-provider-redirector", false, 0);
        l.organization = makeSubflow("mcpmesh-browser Organization", organizationRequirement, 0);
        var orgLeaf = makeExec("Organization Identity-First Login", "ALTERNATIVE",
            "organization", false, 1);
        var orgConditional = makeSubflow(
            "mcpmesh-browser Browser - Conditional Organization", "CONDITIONAL", 1);
        var orgCondUserConfigured = makeExec("Condition - user configured", "REQUIRED",
            "conditional-user-configured", false, 2);
        l.forms = makeSubflow("mcpmesh-browser forms", formsRequirement, 0);
        l.upf = makeExec("Username Password Form", upfRequirement,
            "auth-username-password-form", false, 1);
        var browser2fa = makeSubflow(
            "mcpmesh-browser Browser - Conditional 2FA", "CONDITIONAL", 1);
        var twofaCondUserConfigured = makeExec("Condition - user configured", "REQUIRED",
            "conditional-user-configured", false, 2);

        l.all = List.of(
            cookie, kerberos, idpRedirect,
            l.organization, orgLeaf, orgConditional, orgCondUserConfigured,
            l.forms, l.upf, browser2fa, twofaCondUserConfigured
        );
        return l;
    }

    /** Bundle of the named executions in a kcv26Layout for easy assertion. */
    private static final class Kcv26FlowLayout {
        AuthenticationExecutionInfoRepresentation forms;
        AuthenticationExecutionInfoRepresentation upf;
        AuthenticationExecutionInfoRepresentation organization;
        List<AuthenticationExecutionInfoRepresentation> all;
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
