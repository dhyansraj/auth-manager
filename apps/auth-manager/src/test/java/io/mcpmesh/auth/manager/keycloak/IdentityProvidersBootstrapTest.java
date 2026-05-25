package io.mcpmesh.auth.manager.keycloak;

import io.mcpmesh.auth.manager.persistence.TenantRepository;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.IdentityProviderResource;
import org.keycloak.admin.client.resource.IdentityProvidersResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.representations.idm.IdentityProviderMapperRepresentation;
import org.keycloak.representations.idm.IdentityProviderRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IdentityProvidersBootstrap}. Stubs the KC admin
 * client; no real server needed.
 */
class IdentityProvidersBootstrapTest {

    private static final String REALM = "t-app1";

    private Keycloak admin;
    private RealmResource realm;
    private IdentityProvidersResource idps;
    private IdentityProviderResource googleResource;
    private IdentityProviderResource githubResource;
    private TenantRepository tenantRepo;

    @BeforeEach
    void setUp() {
        admin = mock(Keycloak.class);
        realm = mock(RealmResource.class);
        idps = mock(IdentityProvidersResource.class);
        googleResource = mock(IdentityProviderResource.class);
        githubResource = mock(IdentityProviderResource.class);
        tenantRepo = mock(TenantRepository.class);

        when(admin.realm(REALM)).thenReturn(realm);
        when(realm.identityProviders()).thenReturn(idps);
        when(idps.get("google")).thenReturn(googleResource);
        when(idps.get("github")).thenReturn(githubResource);
        when(realm.toRepresentation()).thenReturn(new RealmRepresentation());
    }

    private PlatformOAuthProperties fullCreds() {
        return new PlatformOAuthProperties(
            new PlatformOAuthProperties.Provider("g-id", "g-secret"),
            new PlatformOAuthProperties.Provider("gh-id", "gh-secret")
        );
    }

    private PlatformOAuthProperties noCreds() {
        return new PlatformOAuthProperties(
            new PlatformOAuthProperties.Provider(null, null),
            new PlatformOAuthProperties.Provider(null, null)
        );
    }

    private static Response createdResponse() {
        return Response.status(Response.Status.CREATED).build();
    }

    @Test
    void ensureProviders_createsIdP_whenMissing() {
        // Both providers missing on the realm.
        when(googleResource.toRepresentation()).thenThrow(new NotFoundException("missing"));
        when(githubResource.toRepresentation()).thenThrow(new NotFoundException("missing"));
        when(idps.create(any())).thenAnswer(inv -> createdResponse());

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        bootstrap.ensureProviders(REALM, Set.of("google", "github"));

        ArgumentCaptor<IdentityProviderRepresentation> cap =
            ArgumentCaptor.forClass(IdentityProviderRepresentation.class);
        verify(idps, times(2)).create(cap.capture());

        var aliases = cap.getAllValues().stream().map(IdentityProviderRepresentation::getAlias).toList();
        assertThat(aliases).contains("google", "github");

        var googleRep = cap.getAllValues().stream()
            .filter(r -> "google".equals(r.getAlias())).findFirst().orElseThrow();
        assertThat(googleRep.getProviderId()).isEqualTo("google");
        assertThat(googleRep.isEnabled()).isTrue();
        assertThat(googleRep.isTrustEmail()).isTrue();
        assertThat(googleRep.getConfig()).containsEntry("clientId", "g-id");
        assertThat(googleRep.getConfig()).containsEntry("clientSecret", "g-secret");
        assertThat(googleRep.getConfig()).containsEntry("syncMode", "IMPORT");
    }

    @Test
    void ensureProviders_isNoOp_whenAlreadyConfigured() {
        // Both already exist on the realm.
        when(googleResource.toRepresentation()).thenReturn(new IdentityProviderRepresentation());
        when(githubResource.toRepresentation()).thenReturn(new IdentityProviderRepresentation());

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        bootstrap.ensureProviders(REALM, Set.of("google", "github"));

        verify(idps, never()).create(any());
    }

    @Test
    void ensureProviders_skipsProvider_whenCredsMissing() {
        // Only github has creds; google's are null.
        var creds = new PlatformOAuthProperties(
            new PlatformOAuthProperties.Provider(null, null),
            new PlatformOAuthProperties.Provider("gh-id", "gh-secret")
        );
        when(githubResource.toRepresentation()).thenThrow(new NotFoundException("missing"));
        when(idps.create(any())).thenAnswer(inv -> createdResponse());

        var bootstrap = new IdentityProvidersBootstrap(admin, creds, tenantRepo);
        bootstrap.ensureProviders(REALM, Set.of("google", "github"));

        // Only github should be created.
        ArgumentCaptor<IdentityProviderRepresentation> cap =
            ArgumentCaptor.forClass(IdentityProviderRepresentation.class);
        verify(idps, times(1)).create(cap.capture());
        assertThat(cap.getValue().getAlias()).isEqualTo("github");
    }

    @Test
    void ensureProviders_swallowsRealmNotFound() {
        when(realm.toRepresentation()).thenThrow(new NotFoundException("nope"));
        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        bootstrap.ensureProviders("t-ghost", Set.of("google", "github"));
        verify(idps, never()).create(any());
    }

    @Test
    void removeProvider_returnsTrue_andCallsRemove_whenPresent() {
        when(googleResource.toRepresentation()).thenReturn(new IdentityProviderRepresentation());
        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        boolean removed = bootstrap.removeProvider(REALM, "google");
        assertThat(removed).isTrue();
        verify(googleResource).remove();
    }

    @Test
    void removeProvider_returnsFalse_whenAbsent() {
        when(googleResource.toRepresentation()).thenThrow(new NotFoundException("missing"));
        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        boolean removed = bootstrap.removeProvider(REALM, "google");
        assertThat(removed).isFalse();
        verify(googleResource, never()).remove();
    }

    @Test
    void addProvider_rejects_whenCredsMissing() {
        var bootstrap = new IdentityProvidersBootstrap(admin, noCreds(), tenantRepo);
        try {
            bootstrap.addProvider(REALM, "google");
            org.junit.jupiter.api.Assertions.fail("expected IllegalStateException");
        } catch (IllegalStateException expected) {
            // good
        }
        verify(idps, never()).create(any());
    }

    @Test
    void addProvider_rejects_unsupportedProvider() {
        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        try {
            bootstrap.addProvider(REALM, "facebook");
            org.junit.jupiter.api.Assertions.fail("expected IllegalArgumentException");
        } catch (IllegalArgumentException expected) {
            // good
        }
    }

    @Test
    void isAvailable_reflectsCreds() {
        var partial = new PlatformOAuthProperties(
            new PlatformOAuthProperties.Provider("g", "s"),
            new PlatformOAuthProperties.Provider(null, null)
        );
        var bootstrap = new IdentityProvidersBootstrap(admin, partial, tenantRepo);
        assertThat(bootstrap.isAvailable("google")).isTrue();
        assertThat(bootstrap.isAvailable("github")).isFalse();
    }

    @Test
    void defaultProvidersForNewTenant_onlyIncludesConfigured() {
        var partial = new PlatformOAuthProperties(
            new PlatformOAuthProperties.Provider("g", "s"),
            new PlatformOAuthProperties.Provider(null, null)
        );
        var bootstrap = new IdentityProvidersBootstrap(admin, partial, tenantRepo);
        assertThat(bootstrap.defaultProvidersForNewTenant()).containsExactly("google");
    }

    @Test
    void run_skipsBackfill_whenNoCredsConfigured() {
        var bootstrap = new IdentityProvidersBootstrap(admin, noCreds(), tenantRepo);
        bootstrap.run(null);
        // Never reaches realm interactions.
        verify(tenantRepo, never()).findAllByDeletedAtIsNullOrderByCreatedAtDesc();
    }

    // -------------------------------------------------------------------------
    // Hardcoded-role mapper management
    // -------------------------------------------------------------------------

    private static IdentityProviderMapperRepresentation hardcodedRoleMapper(String id, String roleName) {
        IdentityProviderMapperRepresentation m = new IdentityProviderMapperRepresentation();
        m.setId(id);
        m.setName("hardcoded-role-" + roleName);
        m.setIdentityProviderAlias("google");
        m.setIdentityProviderMapper("oidc-hardcoded-role-idp-mapper");
        Map<String, String> cfg = new HashMap<>();
        cfg.put("role", roleName);
        cfg.put("syncMode", "IMPORT");
        m.setConfig(cfg);
        return m;
    }

    @Test
    void ensureHardcodedRoleMapper_createsMapper_whenMissing() {
        when(googleResource.getMappers()).thenReturn(List.of());
        when(googleResource.addMapper(any())).thenAnswer(inv -> createdResponse());

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        boolean created = bootstrap.ensureHardcodedRoleMapper(REALM, "google", "customer");

        assertThat(created).isTrue();
        ArgumentCaptor<IdentityProviderMapperRepresentation> cap =
            ArgumentCaptor.forClass(IdentityProviderMapperRepresentation.class);
        verify(googleResource, times(1)).addMapper(cap.capture());
        IdentityProviderMapperRepresentation rep = cap.getValue();
        assertThat(rep.getName()).isEqualTo("hardcoded-role-customer");
        assertThat(rep.getIdentityProviderAlias()).isEqualTo("google");
        assertThat(rep.getIdentityProviderMapper()).isEqualTo("oidc-hardcoded-role-idp-mapper");
        assertThat(rep.getConfig()).containsEntry("role", "customer");
        assertThat(rep.getConfig()).containsEntry("syncMode", "IMPORT");
    }

    @Test
    void ensureHardcodedRoleMapper_isIdempotent_whenAlreadyPresent() {
        when(googleResource.getMappers())
            .thenReturn(List.of(hardcodedRoleMapper("m1", "customer")));

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        boolean created = bootstrap.ensureHardcodedRoleMapper(REALM, "google", "customer");

        assertThat(created).isFalse();
        verify(googleResource, never()).addMapper(any());
    }

    @Test
    void removeHardcodedRoleMapper_returnsFalse_whenMissing() {
        when(googleResource.getMappers()).thenReturn(List.of());

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        boolean removed = bootstrap.removeHardcodedRoleMapper(REALM, "google", "customer");

        assertThat(removed).isFalse();
        verify(googleResource, never()).delete(any());
    }

    @Test
    void removeHardcodedRoleMapper_deletes_whenPresent() {
        when(googleResource.getMappers())
            .thenReturn(List.of(hardcodedRoleMapper("m1", "customer")));

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        boolean removed = bootstrap.removeHardcodedRoleMapper(REALM, "google", "customer");

        assertThat(removed).isTrue();
        verify(googleResource).delete("m1");
    }

    @Test
    void listHardcodedRoles_returnsRoleNames_fromMatchingMappers() {
        when(googleResource.getMappers()).thenReturn(List.of(
            hardcodedRoleMapper("m1", "customer"),
            hardcodedRoleMapper("m2", "provider")
        ));

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        Set<String> roles = bootstrap.listHardcodedRoles(REALM, "google");

        assertThat(roles).containsExactlyInAnyOrder("customer", "provider");
    }

    @Test
    void listEnabledProviders_returnsAliases_fromFindAll() {
        IdentityProviderRepresentation g = new IdentityProviderRepresentation();
        g.setAlias("google");
        IdentityProviderRepresentation gh = new IdentityProviderRepresentation();
        gh.setAlias("github");
        when(idps.findAll()).thenReturn(List.of(g, gh));

        var bootstrap = new IdentityProvidersBootstrap(admin, fullCreds(), tenantRepo);
        Set<String> enabled = bootstrap.listEnabledProviders(REALM);

        assertThat(enabled).containsExactly("google", "github");
    }
}
