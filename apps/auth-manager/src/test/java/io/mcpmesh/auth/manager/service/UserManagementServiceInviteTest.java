package io.mcpmesh.auth.manager.service;

import io.mcpmesh.auth.manager.api.dto.CreateUserRequest;
import io.mcpmesh.auth.manager.audit.AuditService;
import io.mcpmesh.auth.manager.authflow.LoginMethodService;
import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.email.TransactionalEmailService;
import io.mcpmesh.auth.manager.keycloak.KeycloakAdminService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.UserRepresentation;

import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies the invite-send branch in {@link UserManagementService#create}:
 * <ul>
 *   <li>brokered tenant (isPasswordEnabled=false) → set emailVerified true +
 *       send branded invitation, NO UPDATE_PASSWORD email;</li>
 *   <li>password tenant (isPasswordEnabled=true) → UPDATE_PASSWORD email, NO
 *       branded invitation, NO emailVerified mutation.</li>
 * </ul>
 */
class UserManagementServiceInviteTest {

    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-0000000000aa");
    private static final String REALM = "t-app1";
    private static final String USER_ID = "user-123";
    private static final String EMAIL = "newuser@example.com";

    private TenantService tenants;
    private KeycloakAdminService keycloak;
    private AuditService audit;
    private LoginMethodService loginMethods;
    private TransactionalEmailService transactionalEmail;

    private UserManagementService service;
    private Tenant tenant;

    @BeforeEach
    void setUp() {
        tenants = mock(TenantService.class);
        keycloak = mock(KeycloakAdminService.class);
        audit = mock(AuditService.class);
        loginMethods = mock(LoginMethodService.class);
        transactionalEmail = mock(TransactionalEmailService.class);

        service = new UserManagementService(tenants, keycloak, audit, loginMethods, transactionalEmail);

        tenant = mock(Tenant.class);
        when(tenant.getRealmName()).thenReturn(REALM);
        when(tenants.get(TENANT_ID)).thenReturn(tenant);

        when(keycloak.createUser(eq(REALM), anyString(), anyString(), any(), any()))
            .thenReturn(USER_ID);

        // get(tenantId, userId) at the end of create()
        UserRepresentation u = new UserRepresentation();
        u.setId(USER_ID);
        u.setEmail(EMAIL);
        when(keycloak.getUser(REALM, USER_ID)).thenReturn(u);
        when(keycloak.getUserClientRoles(eq(REALM), eq(USER_ID), anyString()))
            .thenReturn(List.of());
    }

    private CreateUserRequest req() {
        return new CreateUserRequest(EMAIL, "New", "User", List.of(), true);
    }

    @Test
    void brokeredTenant_marksVerifiedAndSendsBrandedInvite() {
        when(loginMethods.isPasswordEnabled(REALM)).thenReturn(false);

        service.create(TENANT_ID, req(), "admin");

        verify(keycloak).setEmailVerified(REALM, USER_ID, true);
        verify(transactionalEmail).sendInvitation(tenant, EMAIL, null);
        verify(keycloak, never()).sendExecuteActionsEmail(anyString(), anyString(), anyList(), anyInt());
    }

    @Test
    void passwordTenant_sendsUpdatePasswordAndNoBrandedInvite() {
        when(loginMethods.isPasswordEnabled(REALM)).thenReturn(true);

        service.create(TENANT_ID, req(), "admin");

        verify(keycloak).sendExecuteActionsEmail(REALM, USER_ID, List.of("UPDATE_PASSWORD"), 86400);
        verify(transactionalEmail, never()).sendInvitation(any(), anyString(), any());
        verify(keycloak, never()).setEmailVerified(anyString(), anyString(), anyBoolean());
    }
}
