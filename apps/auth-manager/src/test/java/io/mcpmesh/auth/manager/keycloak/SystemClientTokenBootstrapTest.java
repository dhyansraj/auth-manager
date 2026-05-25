package io.mcpmesh.auth.manager.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SystemClientTokenBootstrap} -- focuses on the
 * disable-lightweight-tokens loop across realms + clients. Stubs the KC
 * admin service entirely.
 */
class SystemClientTokenBootstrapTest {

    private KeycloakAdminService keycloak;
    private SystemClientTokenBootstrap bootstrap;

    @BeforeEach
    void setUp() {
        keycloak = mock(KeycloakAdminService.class);
        bootstrap = new SystemClientTokenBootstrap(keycloak);
    }

    private static RealmRepresentation realm(String name) {
        RealmRepresentation r = new RealmRepresentation();
        r.setRealm(name);
        return r;
    }

    @Test
    void patchesEveryKnownSystemClient_acrossMultipleRealms() {
        // Two realms, every known client present in both.
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev"), realm("t-app1")));
        for (String clientId : SystemClientTokenBootstrap.SYSTEM_CLIENTS) {
            when(keycloak.findClientUuid("dev", clientId))
                .thenReturn(Optional.of("dev-" + clientId));
            when(keycloak.findClientUuid("t-app1", clientId))
                .thenReturn(Optional.of("app1-" + clientId));
        }

        bootstrap.run(null);

        // Each (realm, client) pair gets exactly one setClientAttributes call
        // with the lightweight-token attr disabled.
        for (String clientId : SystemClientTokenBootstrap.SYSTEM_CLIENTS) {
            verify(keycloak, times(1)).setClientAttributes(
                eq("dev"), eq("dev-" + clientId),
                eq(Map.of(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false")));
            verify(keycloak, times(1)).setClientAttributes(
                eq("t-app1"), eq("app1-" + clientId),
                eq(Map.of(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false")));
        }
    }

    @Test
    void skipsClientsMissingFromRealm() {
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        // Only admin-cli + account exist in this realm; the rest are absent.
        for (String clientId : SystemClientTokenBootstrap.SYSTEM_CLIENTS) {
            if ("admin-cli".equals(clientId) || "account".equals(clientId)) {
                when(keycloak.findClientUuid("dev", clientId))
                    .thenReturn(Optional.of("uuid-" + clientId));
            } else {
                when(keycloak.findClientUuid("dev", clientId))
                    .thenReturn(Optional.empty());
            }
        }

        bootstrap.run(null);

        verify(keycloak, times(1)).setClientAttributes(
            eq("dev"), eq("uuid-admin-cli"), anyMap());
        verify(keycloak, times(1)).setClientAttributes(
            eq("dev"), eq("uuid-account"), anyMap());
        // The other clients have no UUID, so no setter call.
        verify(keycloak, times(2)).setClientAttributes(anyString(), anyString(), anyMap());
    }

    @Test
    void perClientFailureDoesNotAbortLoop() {
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        // admin-cli lookup blows up; the others must still be processed.
        for (String clientId : SystemClientTokenBootstrap.SYSTEM_CLIENTS) {
            if ("admin-cli".equals(clientId)) {
                when(keycloak.findClientUuid("dev", clientId))
                    .thenThrow(new RuntimeException("KC down for this one"));
            } else {
                when(keycloak.findClientUuid("dev", clientId))
                    .thenReturn(Optional.of("uuid-" + clientId));
            }
        }

        bootstrap.run(null);

        // Every non-broken client got its setter call (size = SYSTEM_CLIENTS - 1).
        verify(keycloak, times(SystemClientTokenBootstrap.SYSTEM_CLIENTS.size() - 1))
            .setClientAttributes(anyString(), anyString(), anyMap());
    }

    @Test
    void perRealmIterationContinuesPastFailedRealm() {
        // First realm's iteration fails on EVERY client lookup; second realm
        // is healthy. We expect the healthy realm to still get its clients
        // patched.
        when(keycloak.listRealms()).thenReturn(List.of(realm("broken"), realm("healthy")));
        for (String clientId : SystemClientTokenBootstrap.SYSTEM_CLIENTS) {
            when(keycloak.findClientUuid("broken", clientId))
                .thenThrow(new RuntimeException("realm DB lock"));
            when(keycloak.findClientUuid("healthy", clientId))
                .thenReturn(Optional.of("h-" + clientId));
        }

        bootstrap.run(null);

        verify(keycloak, times(SystemClientTokenBootstrap.SYSTEM_CLIENTS.size()))
            .setClientAttributes(eq("healthy"), anyString(), anyMap());
        verify(keycloak, never()).setClientAttributes(eq("broken"), anyString(), anyMap());
    }

    @Test
    void topLevelFailureIsSwallowed() {
        // listRealms() throwing must not propagate (would crash app context).
        when(keycloak.listRealms()).thenThrow(new RuntimeException("KC unreachable"));

        bootstrap.run(null);  // no throw

        verify(keycloak, never()).setClientAttributes(anyString(), anyString(), any());
    }

    @Test
    void skipsRealmsWithoutAName() {
        // Defensive: a realm representation with null/blank name shouldn't
        // crash the loop -- KC sometimes returns oddballs during migrations.
        RealmRepresentation blank = new RealmRepresentation();
        blank.setRealm("");
        RealmRepresentation nullName = new RealmRepresentation();
        nullName.setRealm(null);
        when(keycloak.listRealms()).thenReturn(List.of(blank, nullName));

        bootstrap.run(null);

        verify(keycloak, never()).findClientUuid(anyString(), anyString());
        verify(keycloak, never()).setClientAttributes(anyString(), anyString(), any());
    }

    @Test
    void verifyAttributeKey() {
        // Document the exact KC attribute key in a test so a typo here
        // produces a focused failure instead of a "tokens still lightweight"
        // post-deploy surprise.
        assertThat(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR)
            .isEqualTo("client.use.lightweight.access.token.enabled");
    }

    @Test
    void systemClientsListIncludesUsermanagementAndAllKcDefaults() {
        // Same intent: assert the curated set so adding/removing a client
        // requires a deliberate test update.
        assertThat(SystemClientTokenBootstrap.SYSTEM_CLIENTS).containsExactlyInAnyOrder(
            "usermanagement",
            "admin-cli",
            "account",
            "account-console",
            "realm-management",
            "security-admin-console",
            "broker");
    }

    @Test
    void capturesAttributesMapPassedToSetter() {
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        when(keycloak.findClientUuid(eq("dev"), anyString())).thenReturn(Optional.empty());
        when(keycloak.findClientUuid("dev", "admin-cli")).thenReturn(Optional.of("u-admin"));

        bootstrap.run(null);

        ArgumentCaptor<Map<String, String>> cap = ArgumentCaptor.forClass(Map.class);
        verify(keycloak).setClientAttributes(eq("dev"), eq("u-admin"), cap.capture());
        assertThat(cap.getValue())
            .containsEntry(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false");
    }
}
