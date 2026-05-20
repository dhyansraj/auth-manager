package io.mcpmesh.auth.manager.routing;

import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@Testcontainers
class RoutingTableIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @Container
    @ServiceConnection(name = "redis")
    static GenericContainer<?> redis = new GenericContainer<>(DockerImageName.parse("redis:7-alpine"))
        .withExposedPorts(6379);

    @Autowired RoutingTableService routing;
    @Autowired StringRedisTemplate redisTpl;

    @Test
    void publish_writes_hash_with_backend_and_tenant_fields() {
        routing.publish("acme.local", "acme-svc:8080", "acme");

        var fields = redisTpl.opsForHash().entries("host:acme.local");
        assertThat(fields).containsEntry("backend", "acme-svc:8080");
        assertThat(fields).containsEntry("tenant",  "acme");
    }

    @Test
    void unpublish_removes_key() {
        routing.publish("temp.local", "temp:80", "tempo");
        routing.unpublish("temp.local");

        assertThat(redisTpl.hasKey("host:temp.local")).isFalse();
    }

    @Test
    void publishAll_handles_multiple_hostnames() {
        UUID tenantId = UUID.randomUUID();
        var hostnames = List.of(
            new TenantHostname("one.local", tenantId, "svc1:80"),
            new TenantHostname("two.local", tenantId, "svc2:80")
        );
        routing.publishAll(hostnames, "acme");

        assertThat(redisTpl.opsForHash().get("host:one.local", "backend")).isEqualTo("svc1:80");
        assertThat(redisTpl.opsForHash().get("host:two.local", "backend")).isEqualTo("svc2:80");
    }
}
