package io.mcpmesh.auth.manager.keycloak;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.mockito.ArgumentCaptor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link SystemClientTokenBootstrap} -- exercises both the
 * lightweight-token disable AND the webOrigins backfill on system clients
 * across realms. Stubs the KC admin service entirely; captures the mutator
 * lambda passed to {@code mutateClient} and applies it to a fake
 * {@link ClientRepresentation} to verify the per-rep changes.
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

    private static ClientRepresentation clientRep(String clientId) {
        ClientRepresentation rep = new ClientRepresentation();
        rep.setClientId(clientId);
        return rep;
    }

    @SuppressWarnings("unchecked")
    private static Predicate<ClientRepresentation> anyMutator() {
        return any(Predicate.class);
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<Predicate<ClientRepresentation>> mutatorCaptor() {
        return ArgumentCaptor.forClass(Predicate.class);
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
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        // Each (realm, client) pair gets exactly one mutateClient call.
        for (String clientId : SystemClientTokenBootstrap.SYSTEM_CLIENTS) {
            verify(keycloak, times(1)).mutateClient(
                eq("dev"), eq("dev-" + clientId), anyMutator());
            verify(keycloak, times(1)).mutateClient(
                eq("t-app1"), eq("app1-" + clientId), anyMutator());
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
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        verify(keycloak, times(1)).mutateClient(
            eq("dev"), eq("uuid-admin-cli"), anyMutator());
        verify(keycloak, times(1)).mutateClient(
            eq("dev"), eq("uuid-account"), anyMutator());
        // The other clients have no UUID, so no mutateClient call.
        verify(keycloak, times(2)).mutateClient(anyString(), anyString(), anyMutator());
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
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        // Every non-broken client got its mutateClient call (size = SYSTEM_CLIENTS - 1).
        verify(keycloak, times(SystemClientTokenBootstrap.SYSTEM_CLIENTS.size() - 1))
            .mutateClient(anyString(), anyString(), anyMutator());
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
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        verify(keycloak, times(SystemClientTokenBootstrap.SYSTEM_CLIENTS.size()))
            .mutateClient(eq("healthy"), anyString(), anyMutator());
        verify(keycloak, never()).mutateClient(eq("broken"), anyString(), anyMutator());
    }

    @Test
    void topLevelFailureIsSwallowed() {
        // listRealms() throwing must not propagate (would crash app context).
        when(keycloak.listRealms()).thenThrow(new RuntimeException("KC unreachable"));

        bootstrap.run(null);  // no throw

        verify(keycloak, never()).mutateClient(anyString(), anyString(), any());
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
        verify(keycloak, never()).mutateClient(anyString(), anyString(), any());
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
    void webOriginClientsContainsOnlySpaConsoles() {
        // Document the SPA-only subset that gets the webOrigins=["+"] backfill.
        assertThat(SystemClientTokenBootstrap.WEB_ORIGIN_CLIENTS)
            .containsExactlyInAnyOrder("account-console", "security-admin-console");
    }

    @Test
    void mutator_disablesLightweightTokensWhenAttrMissing() {
        // admin-cli with no attributes map -> mutator should set
        // lightweight=false and return true.
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        when(keycloak.findClientUuid(eq("dev"), anyString())).thenReturn(Optional.empty());
        when(keycloak.findClientUuid("dev", "admin-cli")).thenReturn(Optional.of("u-admin"));
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        ArgumentCaptor<Predicate<ClientRepresentation>> cap = mutatorCaptor();
        verify(keycloak).mutateClient(eq("dev"), eq("u-admin"), cap.capture());

        ClientRepresentation rep = clientRep("admin-cli");
        boolean changed = cap.getValue().test(rep);

        assertThat(changed).isTrue();
        assertThat(rep.getAttributes())
            .containsEntry(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false");
        // admin-cli isn't an SPA -> webOrigins must not be touched.
        assertThat(rep.getWebOrigins()).isNull();
    }

    @Test
    void mutator_isNoOpWhenLightweightAlreadyDisabledAndNotSpaClient() {
        // admin-cli with attrs already at "false" + not in WEB_ORIGIN_CLIENTS ->
        // mutator must return false so the underlying PUT is skipped.
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        when(keycloak.findClientUuid(eq("dev"), anyString())).thenReturn(Optional.empty());
        when(keycloak.findClientUuid("dev", "admin-cli")).thenReturn(Optional.of("u-admin"));
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(false);

        bootstrap.run(null);

        ArgumentCaptor<Predicate<ClientRepresentation>> cap = mutatorCaptor();
        verify(keycloak).mutateClient(eq("dev"), eq("u-admin"), cap.capture());

        ClientRepresentation rep = clientRep("admin-cli");
        HashMap<String, String> attrs = new HashMap<>();
        attrs.put(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false");
        rep.setAttributes(attrs);

        boolean changed = cap.getValue().test(rep);

        assertThat(changed).isFalse();
        assertThat(rep.getAttributes())
            .containsEntry(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false");
        assertThat(rep.getWebOrigins()).isNull();
    }

    @Test
    void mutator_backfillsWebOriginsOnSpaClientWithEmptyList() {
        // account-console with empty webOrigins -> mutator sets ["+"] AND
        // disables lightweight tokens, returns true.
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        when(keycloak.findClientUuid(eq("dev"), anyString())).thenReturn(Optional.empty());
        when(keycloak.findClientUuid("dev", "account-console"))
            .thenReturn(Optional.of("u-account-console"));
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        ArgumentCaptor<Predicate<ClientRepresentation>> cap = mutatorCaptor();
        verify(keycloak).mutateClient(eq("dev"), eq("u-account-console"), cap.capture());

        ClientRepresentation rep = clientRep("account-console");
        rep.setWebOrigins(new ArrayList<>());
        boolean changed = cap.getValue().test(rep);

        assertThat(changed).isTrue();
        assertThat(rep.getAttributes())
            .containsEntry(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false");
        assertThat(rep.getWebOrigins()).containsExactly("+");
    }

    @Test
    void mutator_backfillsWebOriginsOnSpaClientWithNullList() {
        // security-admin-console with null webOrigins -> mutator sets ["+"].
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        when(keycloak.findClientUuid(eq("dev"), anyString())).thenReturn(Optional.empty());
        when(keycloak.findClientUuid("dev", "security-admin-console"))
            .thenReturn(Optional.of("u-sec-admin"));
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        ArgumentCaptor<Predicate<ClientRepresentation>> cap = mutatorCaptor();
        verify(keycloak).mutateClient(eq("dev"), eq("u-sec-admin"), cap.capture());

        ClientRepresentation rep = clientRep("security-admin-console");
        // webOrigins left at null
        boolean changed = cap.getValue().test(rep);

        assertThat(changed).isTrue();
        assertThat(rep.getWebOrigins()).containsExactly("+");
    }

    @Test
    void mutator_leavesNonEmptyWebOriginsAlone() {
        // account-console with operator-customised webOrigins -> mutator must
        // NOT clobber the list. Lightweight-token disable still applies, so
        // overall the mutator returns true (changed=true) but webOrigins is
        // untouched.
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        when(keycloak.findClientUuid(eq("dev"), anyString())).thenReturn(Optional.empty());
        when(keycloak.findClientUuid("dev", "account-console"))
            .thenReturn(Optional.of("u-account-console"));
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(true);

        bootstrap.run(null);

        ArgumentCaptor<Predicate<ClientRepresentation>> cap = mutatorCaptor();
        verify(keycloak).mutateClient(eq("dev"), eq("u-account-console"), cap.capture());

        ClientRepresentation rep = clientRep("account-console");
        List<String> custom = new ArrayList<>(List.of("https://custom.example.com"));
        rep.setWebOrigins(custom);
        boolean changed = cap.getValue().test(rep);

        // Lightweight-token disable still fired, so the overall mutator
        // reports a change.
        assertThat(changed).isTrue();
        // webOrigins must be preserved verbatim.
        assertThat(rep.getWebOrigins()).containsExactly("https://custom.example.com");
    }

    @Test
    void mutator_isFullNoOpWhenSpaClientAlreadyHasBothAttrAndWebOrigins() {
        // account-console with lightweight already false AND webOrigins already
        // populated -> mutator returns false.
        when(keycloak.listRealms()).thenReturn(List.of(realm("dev")));
        when(keycloak.findClientUuid(eq("dev"), anyString())).thenReturn(Optional.empty());
        when(keycloak.findClientUuid("dev", "account-console"))
            .thenReturn(Optional.of("u-account-console"));
        when(keycloak.mutateClient(anyString(), anyString(), anyMutator())).thenReturn(false);

        bootstrap.run(null);

        ArgumentCaptor<Predicate<ClientRepresentation>> cap = mutatorCaptor();
        verify(keycloak).mutateClient(eq("dev"), eq("u-account-console"), cap.capture());

        ClientRepresentation rep = clientRep("account-console");
        HashMap<String, String> attrs = new HashMap<>();
        attrs.put(SystemClientTokenBootstrap.LIGHTWEIGHT_TOKEN_ATTR, "false");
        rep.setAttributes(attrs);
        rep.setWebOrigins(new ArrayList<>(List.of("+")));

        boolean changed = cap.getValue().test(rep);

        assertThat(changed).isFalse();
        assertThat(rep.getWebOrigins()).containsExactly("+");
    }
}
