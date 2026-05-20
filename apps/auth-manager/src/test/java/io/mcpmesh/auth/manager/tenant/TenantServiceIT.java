package io.mcpmesh.auth.manager.tenant;

import io.mcpmesh.auth.manager.domain.tenant.Tenant;
import io.mcpmesh.auth.manager.domain.tenant.TenantStatus;
import io.mcpmesh.auth.manager.persistence.TenantRepository;
import io.mcpmesh.auth.manager.service.TenantService;
import io.mcpmesh.auth.manager.service.exception.TenantConflictException;
import io.mcpmesh.auth.manager.service.exception.TenantNotFoundException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(properties = {
    "spring.autoconfigure.exclude=" +
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration," +
        "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"
})
@Testcontainers
class TenantServiceIT {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16");

    @Autowired
    TenantService service;

    @Autowired
    TenantRepository repo;

    @BeforeEach
    void clean() {
        repo.deleteAll();
    }

    @Test
    void create_persists_tenant_in_pending_status() {
        Tenant t = service.create("bank1", "Bank 1", Map.of("region", "us-east-1"), "tester");

        assertThat(t.getId()).isNotNull();
        assertThat(t.getSlug()).isEqualTo("bank1");
        assertThat(t.getDisplayName()).isEqualTo("Bank 1");
        assertThat(t.getStatus()).isEqualTo(TenantStatus.PENDING);
        assertThat(t.getRealmName()).isNull();
        assertThat(t.getSettings()).containsEntry("region", "us-east-1");
        assertThat(t.getCreatedAt()).isNotNull();
        assertThat(t.getCreatedBy()).isEqualTo("tester");
    }

    @Test
    void create_rejects_duplicate_slug() {
        service.create("bank1", "Bank 1", null, "tester");

        assertThatThrownBy(() -> service.create("bank1", "Whatever", null, "tester"))
            .isInstanceOf(TenantConflictException.class);
    }

    @Test
    void get_returns_existing_tenant() {
        Tenant created = service.create("bank2", "Bank 2", null, "tester");
        Tenant fetched = service.get(created.getId());
        assertThat(fetched.getSlug()).isEqualTo("bank2");
    }

    @Test
    void get_throws_when_missing() {
        assertThatThrownBy(() -> service.get(java.util.UUID.randomUUID()))
            .isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void softDelete_hides_tenant_from_listings() {
        Tenant t = service.create("bank3", "Bank 3", null, "tester");
        service.softDelete(t.getId(), "tester");

        assertThat(service.list()).extracting(Tenant::getSlug).doesNotContain("bank3");
        assertThatThrownBy(() -> service.get(t.getId()))
            .isInstanceOf(TenantNotFoundException.class);
    }
}
