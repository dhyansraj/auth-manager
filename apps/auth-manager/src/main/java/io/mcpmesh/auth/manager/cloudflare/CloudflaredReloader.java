package io.mcpmesh.auth.manager.cloudflare;

import io.fabric8.kubernetes.client.KubernetesClient;
import io.fabric8.kubernetes.client.dsl.base.PatchContext;
import io.fabric8.kubernetes.client.dsl.base.PatchType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Rolls the cloudflared deployment so it picks up the freshly-PUT tunnel
 * ingress config. Uses the same {@code spec.template.metadata.annotations
 * .kubectl.kubernetes.io/restartedAt} mechanism as {@code kubectl rollout
 * restart}.
 *
 * <p>Reuses the auto-wired {@link KubernetesClient} bean from
 * {@code theme/KubernetesClientConfig}.
 */
@Component
public class CloudflaredReloader {

    private static final Logger log = LoggerFactory.getLogger(CloudflaredReloader.class);

    static final String NAMESPACE = "auth-platform";
    static final String DEPLOYMENT_NAME = "auth-platform-cloudflared";
    static final String RESTARTED_AT_ANNOTATION = "kubectl.kubernetes.io/restartedAt";

    private final KubernetesClient k8s;

    public CloudflaredReloader(KubernetesClient k8s) {
        this.k8s = k8s;
    }

    /**
     * Patches the cloudflared deployment's pod-template restartedAt annotation.
     * Triggers a rolling restart (same mechanism as {@code kubectl rollout restart}).
     */
    public void reloadCloudflared() {
        try {
            String now = Instant.now().toString();
            String patch = "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\""
                + RESTARTED_AT_ANNOTATION + "\":\"" + now + "\"}}}}}";
            k8s.apps().deployments().inNamespace(NAMESPACE).withName(DEPLOYMENT_NAME)
                .patch(PatchContext.of(PatchType.STRATEGIC_MERGE), patch);
            log.info("CloudflaredReloader: triggered rollout via annotation={}", now);
        } catch (Exception e) {
            log.warn("CloudflaredReloader: failed to trigger cloudflared rollout: {}", e.getMessage());
        }
    }
}
