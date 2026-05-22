package io.mcpmesh.auth.manager.theme;

import io.fabric8.kubernetes.api.model.apps.StatefulSet;
import io.fabric8.kubernetes.api.model.apps.StatefulSetStatus;
import io.fabric8.kubernetes.client.KubernetesClient;
import jakarta.ws.rs.NotFoundException;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.RealmRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Drives the two cluster-side actions that complete a theme apply:
 * <ol>
 *   <li>Update the realm's {@code loginTheme}, {@code accountTheme},
 *       {@code emailTheme} via Keycloak admin API.</li>
 *   <li>Trigger a rolling restart of the platform-kc StatefulSet by patching
 *       its pod-template {@code restartedAt} annotation -- this is the same
 *       mechanism {@code kubectl rollout restart} uses, just expressed via
 *       the typed Fabric8 client.</li>
 * </ol>
 *
 * <p>Rollout status is read back from the StatefulSet's
 * {@code .status.{currentRevision, updateRevision, readyReplicas, replicas}}
 * — the standard signals for "is the deploy still rolling".
 *
 * <p>When a tenant's theme is reset to default, callers pass {@code null} for
 * the theme name -- the realm fields are cleared and KC falls back to the
 * built-in {@code keycloak.v2} theme.
 */
@Component
public class ThemeApplier {

    private static final Logger log = LoggerFactory.getLogger(ThemeApplier.class);

    static final String KC_STATEFULSET_NAME = "platform-kc-keycloak";
    static final String RESTARTED_AT_ANNOTATION = "kubectl.kubernetes.io/restartedAt";

    private final Keycloak keycloak;
    private final KubernetesClient k8s;
    private final String namespace;

    public ThemeApplier(
        Keycloak keycloak,
        KubernetesClient k8s,
        @Value("${mcpmesh.namespace:auth-platform}") String namespace
    ) {
        this.keycloak = keycloak;
        this.k8s = k8s;
        this.namespace = namespace;
    }

    /**
     * Applies the named theme to the tenant's realm and triggers a rolling
     * restart so KC picks up the freshly-materialized files. Pass
     * {@code themeName=null} to reset to default (clears the realm fields).
     */
    public void applyTheme(String realmName, String themeName) {
        updateRealmTheme(realmName, themeName);
        triggerRollout();
    }

    public void updateRealmTheme(String realmName, String themeName) {
        try {
            RealmRepresentation rep = keycloak.realm(realmName).toRepresentation();
            rep.setLoginTheme(themeName);
            rep.setAccountTheme(themeName);
            rep.setEmailTheme(themeName);
            keycloak.realm(realmName).update(rep);
            log.info("Set realm '{}' theme fields to '{}'", realmName, themeName);
        } catch (NotFoundException e) {
            log.warn("Realm '{}' not found; cannot set theme", realmName);
            throw e;
        }
    }

    /**
     * Trigger a rolling restart of the platform-kc StatefulSet by patching
     * the {@code spec.template.metadata.annotations} with a fresh timestamp.
     */
    public void triggerRollout() {
        String timestamp = Instant.now().toString();
        var resource = k8s.apps().statefulSets()
            .inNamespace(namespace)
            .withName(KC_STATEFULSET_NAME);
        // Use a JSON merge-patch with ONLY the changed annotation. Avoid the
        // edit()/serialize-full-object path because Fabric8's Jackson hits a
        // NullPointerException when ManagedFieldsEntry.fieldsV1 (a raw JSON
        // tree the apiserver attaches for kubectl-style ownership tracking)
        // round-trips through Java serialization.
        String mergePatch = String.format(
            "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"%s\":\"%s\"}}}}}",
            RESTARTED_AT_ANNOTATION, timestamp);
        try {
            resource.patch(io.fabric8.kubernetes.client.dsl.base.PatchContext.of(
                io.fabric8.kubernetes.client.dsl.base.PatchType.JSON_MERGE), mergePatch);
        } catch (io.fabric8.kubernetes.client.KubernetesClientException e) {
            if (e.getCode() == 404) {
                log.warn("StatefulSet {} not found in namespace {}; skipping rollout",
                    KC_STATEFULSET_NAME, namespace);
                return;
            }
            throw e;
        }
        log.info("Triggered rolling restart of {} via {}={}",
            KC_STATEFULSET_NAME, RESTARTED_AT_ANNOTATION, timestamp);
    }

    public RolloutStatus getRolloutStatus() {
        StatefulSet sts = k8s.apps().statefulSets()
            .inNamespace(namespace)
            .withName(KC_STATEFULSET_NAME)
            .get();
        if (sts == null) {
            log.debug("StatefulSet {} not found; reporting READY", KC_STATEFULSET_NAME);
            return RolloutStatus.ready();
        }
        StatefulSetStatus status = sts.getStatus();
        if (status == null) {
            return RolloutStatus.rollingOut(0);
        }
        Integer desired = sts.getSpec() != null ? sts.getSpec().getReplicas() : null;
        Integer ready = status.getReadyReplicas();
        Integer updated = status.getUpdatedReplicas();
        String currentRev = status.getCurrentRevision();
        String updateRev = status.getUpdateRevision();

        int desiredCount = desired == null ? 1 : desired;
        int readyCount = ready == null ? 0 : ready;
        int updatedCount = updated == null ? 0 : updated;

        boolean revisionsMatch = currentRev == null
            || updateRev == null
            || currentRev.equals(updateRev);

        if (revisionsMatch && readyCount >= desiredCount) {
            return RolloutStatus.ready();
        }
        int progress = desiredCount == 0 ? 0
            : (int) ((Math.min(readyCount, updatedCount) * 100L) / desiredCount);
        return RolloutStatus.rollingOut(progress);
    }
}
