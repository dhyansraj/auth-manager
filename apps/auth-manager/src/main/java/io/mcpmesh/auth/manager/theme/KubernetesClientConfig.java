package io.mcpmesh.auth.manager.theme;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.KubernetesClientBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires a singleton {@link KubernetesClient} for the theme subsystem.
 *
 * <p>When auth-manager runs inside a pod (the only deployment mode that
 * exercises this code), Fabric8's default builder auto-discovers the
 * in-cluster ServiceAccount token + namespace. In tests, a {@code @MockitoBean}
 * supplies a mock — the {@link ConditionalOnMissingBean} guard lets that
 * mock take precedence.
 */
@Configuration
public class KubernetesClientConfig {

    private static final Logger log = LoggerFactory.getLogger(KubernetesClientConfig.class);

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean(KubernetesClient.class)
    public KubernetesClient kubernetesClient() {
        KubernetesClient client = new KubernetesClientBuilder().build();
        log.info("Kubernetes client initialized (namespace={})", client.getNamespace());
        return client;
    }
}
