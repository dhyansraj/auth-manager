package io.mcpmesh.auth.manager.email;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Focused unit tests for {@link SendGridClient}'s JSON parsing + the
 * validate-vs-GET merge rule (backlog #104). No live HTTP — these exercise the
 * static parse/merge helpers directly.
 */
class SendGridClientTest {

    private static final ObjectMapper M = new ObjectMapper();

    private static JsonNode json(String s) {
        try {
            return M.readTree(s);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void parseDomain_readsTopLevelValidTrue() {
        JsonNode node = json("""
            { "id": 101, "domain": "example.com", "valid": true,
              "dns": {
                "mail_cname": { "host": "em.example.com", "data": "u.wl.sendgrid.net" },
                "dkim1": { "host": "s1._domainkey.example.com", "data": "s1.dk.sendgrid.net" },
                "dkim2": { "host": "s2._domainkey.example.com", "data": "s2.dk.sendgrid.net" }
              } }
            """);

        SendGridClient.DomainAuthResult r = SendGridClient.parseDomain(node);

        assertThat(r.id()).isEqualTo(101);
        assertThat(r.domain()).isEqualTo("example.com");
        assertThat(r.valid()).isTrue();
        assertThat(r.cnames()).hasSize(3);
    }

    @Test
    void parseDomain_validFalseAndMissingDefaultsFalse() {
        assertThat(SendGridClient.parseDomain(json("{\"id\":1,\"valid\":false}")).valid()).isFalse();
        // missing `valid` field must default to false, not blow up
        assertThat(SendGridClient.parseDomain(json("{\"id\":1}")).valid()).isFalse();
    }

    /**
     * Root-cause guard for backlog #104: the /validate POST response's
     * top-level `valid:true` must win over a stale GET record that still
     * reports valid:false right after validation.
     */
    @Test
    void mergeValidateResult_validatePostWinsOverStaleGet() {
        JsonNode validateResp = json("""
            { "id": 101, "valid": true,
              "validation_results": { "mail_cname": { "valid": true } } }
            """);
        SendGridClient.DomainAuthResult staleGet = new SendGridClient.DomainAuthResult(
            101, "example.com", false, // GET still says false
            List.of(new SendGridClient.DnsCname("em.example.com", "u.wl.sendgrid.net")));

        SendGridClient.DomainAuthResult merged =
            SendGridClient.mergeValidateResult(validateResp, staleGet);

        assertThat(merged.valid()).isTrue();           // authoritative from POST
        assertThat(merged.id()).isEqualTo(101);
        assertThat(merged.domain()).isEqualTo("example.com");
        assertThat(merged.cnames()).hasSize(1);        // stable fields from GET
    }

    @Test
    void mergeValidateResult_validateFalseIsHonored() {
        JsonNode validateResp = json("{\"id\":101,\"valid\":false}");
        SendGridClient.DomainAuthResult getRecord =
            new SendGridClient.DomainAuthResult(101, "example.com", true, List.of());

        SendGridClient.DomainAuthResult merged =
            SendGridClient.mergeValidateResult(validateResp, getRecord);

        assertThat(merged.valid()).isFalse();
    }
}
