package io.mcpmesh.auth.manager.keycloak;

import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.ProtocolMappersResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RolesResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the Phase-2 onboarding additions on {@link KeycloakAdminService}:
 * {@code setClientFlowFlags}, {@code ensureAudienceMapper},
 * {@code findServiceAccountUserId}, {@code listClientRoleNames}.
 * Stubs the Keycloak admin client; no real KC server.
 */
class KeycloakAdminServiceProfileTest {

    private static final String REALM = "t-acme";
    private static final String CLIENT_UUID = "client-uuid";

    private Keycloak admin;
    private RealmResource realm;
    private ClientsResource clientsResource;
    private ClientResource clientResource;
    private ProtocolMappersResource protocolMappers;
    private KeycloakAdminService service;

    @BeforeEach
    void setUp() {
        admin = mock(Keycloak.class);
        realm = mock(RealmResource.class);
        clientsResource = mock(ClientsResource.class);
        clientResource = mock(ClientResource.class);
        protocolMappers = mock(ProtocolMappersResource.class);

        when(admin.realm(REALM)).thenReturn(realm);
        when(realm.clients()).thenReturn(clientsResource);
        when(clientsResource.get(CLIENT_UUID)).thenReturn(clientResource);
        when(clientResource.getProtocolMappers()).thenReturn(protocolMappers);

        service = new KeycloakAdminService(admin);
    }

    // ----- setClientFlowFlags ----------------------------------------------

    @Test
    void setClientFlowFlags_writesAllThreeFieldsAndPutsBack() {
        ClientRepresentation rep = new ClientRepresentation();
        rep.setStandardFlowEnabled(true);
        rep.setDirectAccessGrantsEnabled(true);
        rep.setServiceAccountsEnabled(true);
        when(clientResource.toRepresentation()).thenReturn(rep);

        service.setClientFlowFlags(REALM, CLIENT_UUID, false, false, true);

        ArgumentCaptor<ClientRepresentation> cap = ArgumentCaptor.forClass(ClientRepresentation.class);
        verify(clientResource).update(cap.capture());
        ClientRepresentation written = cap.getValue();
        assertThat(written.isStandardFlowEnabled()).isFalse();
        assertThat(written.isDirectAccessGrantsEnabled()).isFalse();
        assertThat(written.isServiceAccountsEnabled()).isTrue();
    }

    // ----- ensureAudienceMapper --------------------------------------------

    @Test
    void ensureAudienceMapper_createsNewMapperWhenNoneExists() {
        when(protocolMappers.getMappersPerProtocol("openid-connect")).thenReturn(List.of());
        Response ok = mock(Response.class);
        when(ok.getStatus()).thenReturn(201);
        when(protocolMappers.createMapper(any(ProtocolMapperRepresentation.class))).thenReturn(ok);

        boolean created = service.ensureAudienceMapper(REALM, CLIENT_UUID, "invoices");

        assertThat(created).isTrue();
        ArgumentCaptor<ProtocolMapperRepresentation> cap = ArgumentCaptor.forClass(ProtocolMapperRepresentation.class);
        verify(protocolMappers).createMapper(cap.capture());
        ProtocolMapperRepresentation rep = cap.getValue();
        assertThat(rep.getName()).isEqualTo("audience-invoices");
        assertThat(rep.getProtocol()).isEqualTo("openid-connect");
        assertThat(rep.getProtocolMapper()).isEqualTo("oidc-audience-mapper");
        assertThat(rep.getConfig())
            .containsEntry("included.client.audience", "invoices")
            .containsEntry("id.token.claim", "false")
            .containsEntry("access.token.claim", "true");
    }

    @Test
    void ensureAudienceMapper_idempotentWhenAlreadyPresent() {
        ProtocolMapperRepresentation existing = new ProtocolMapperRepresentation();
        existing.setName("audience-invoices");
        existing.setProtocol("openid-connect");
        existing.setProtocolMapper("oidc-audience-mapper");
        existing.setConfig(Map.of("included.client.audience", "invoices"));
        when(protocolMappers.getMappersPerProtocol("openid-connect")).thenReturn(List.of(existing));

        boolean created = service.ensureAudienceMapper(REALM, CLIENT_UUID, "invoices");

        assertThat(created).isFalse();
        verify(protocolMappers, never()).createMapper(any(ProtocolMapperRepresentation.class));
    }

    @Test
    void ensureAudienceMapper_returnsFalseOnHttpFailure() {
        when(protocolMappers.getMappersPerProtocol("openid-connect")).thenReturn(List.of());
        Response bad = mock(Response.class);
        when(bad.getStatus()).thenReturn(500);
        when(protocolMappers.createMapper(any(ProtocolMapperRepresentation.class))).thenReturn(bad);

        boolean created = service.ensureAudienceMapper(REALM, CLIENT_UUID, "invoices");

        assertThat(created).isFalse();
    }

    // ----- findServiceAccountUserId ----------------------------------------

    @Test
    void findServiceAccountUserId_returnsUserUuid() {
        UserRepresentation user = new UserRepresentation();
        user.setId("sa-user-id");
        when(clientResource.getServiceAccountUser()).thenReturn(user);

        var opt = service.findServiceAccountUserId(REALM, CLIENT_UUID);
        assertThat(opt).contains("sa-user-id");
    }

    @Test
    void findServiceAccountUserId_returnsEmptyOnNull() {
        when(clientResource.getServiceAccountUser()).thenReturn(null);
        var opt = service.findServiceAccountUserId(REALM, CLIENT_UUID);
        assertThat(opt).isEmpty();
    }

    @Test
    void findServiceAccountUserId_returnsEmptyOnException() {
        when(clientResource.getServiceAccountUser()).thenThrow(new RuntimeException("svc accts disabled"));
        var opt = service.findServiceAccountUserId(REALM, CLIENT_UUID);
        assertThat(opt).isEmpty();
    }

    // ----- listClientRoleNames ---------------------------------------------

    @Test
    void listClientRoleNames_returnsRoleNames() {
        RolesResource roles = mock(RolesResource.class);
        when(clientResource.roles()).thenReturn(roles);
        RoleRepresentation r1 = new RoleRepresentation(); r1.setName("USER_LIST");
        RoleRepresentation r2 = new RoleRepresentation(); r2.setName("USER_INVITE");
        when(roles.list()).thenReturn(List.of(r1, r2));

        List<String> names = service.listClientRoleNames(REALM, CLIENT_UUID);
        assertThat(names).containsExactly("USER_LIST", "USER_INVITE");
    }

    @Test
    void listClientRoleNames_returnsEmptyOnException() {
        RolesResource roles = mock(RolesResource.class);
        when(clientResource.roles()).thenReturn(roles);
        when(roles.list()).thenThrow(new RuntimeException("kc down"));

        List<String> names = service.listClientRoleNames(REALM, CLIENT_UUID);
        assertThat(names).isEmpty();
    }
}
