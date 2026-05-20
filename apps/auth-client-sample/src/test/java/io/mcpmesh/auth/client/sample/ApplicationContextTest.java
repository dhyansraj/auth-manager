package io.mcpmesh.auth.client.sample;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest
@TestPropertySource(properties = {
    "auth-lib.issuer-uri=http://localhost:0/realms/test",
    "auth-lib.client-id=test-client",
    "auth-lib.client-secret=test-secret",
    "spring.autoconfigure.exclude=" +
        "org.springframework.boot.autoconfigure.data.redis.RedisAutoConfiguration," +
        "org.springframework.boot.autoconfigure.data.redis.RedisRepositoriesAutoConfiguration"
})
class ApplicationContextTest {

    @Test
    void contextLoads() {
        // If we got here, the bean graph (incl. auth-lib auto-config) loaded.
    }
}
