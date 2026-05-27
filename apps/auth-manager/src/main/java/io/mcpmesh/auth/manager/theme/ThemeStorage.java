package io.mcpmesh.auth.manager.theme;

import io.fabric8.kubernetes.api.model.ConfigMap;
import io.fabric8.kubernetes.api.model.ConfigMapBuilder;
import io.fabric8.kubernetes.api.model.ObjectMetaBuilder;
import io.fabric8.kubernetes.client.KubernetesClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * CRUD for per-tenant theme ConfigMaps.
 *
 * <p>Each tenant theme lives in a single ConfigMap named {@code theme-t-<slug>}
 * in the auth-platform namespace. Text files (CSS, properties, JSON) go into
 * {@code data}; binary files (images, fonts) go into {@code binaryData}.
 *
 * <p>Path encoding: ConfigMap keys may not contain "/". We use "__" (double
 * underscore) as the path separator and the init container in the platform-kc
 * StatefulSet decodes this when materializing the directory tree.
 *
 * <p>The {@code mcpmesh/theme=true} label lets the init container enumerate
 * all per-tenant themes with a single labelled list call.
 */
@Component
public class ThemeStorage {

    private static final Logger log = LoggerFactory.getLogger(ThemeStorage.class);

    static final String THEME_LABEL = "mcpmesh/theme";
    static final String PATH_SEPARATOR_ENCODING = "__";
    static final String CONFIGMAP_NAME_PREFIX = "theme-t-";
    static final String LAST_MODIFIED_ANNOTATION = "mcpmesh.io/theme-last-modified";

    private final KubernetesClient k8s;
    private final String namespace;

    public ThemeStorage(
        KubernetesClient k8s,
        @Value("${mcpmesh.namespace:auth-platform}") String namespace
    ) {
        this.k8s = k8s;
        this.namespace = namespace;
    }

    /**
     * Creates (or replaces) the per-tenant theme ConfigMap.
     *
     * @param slug  tenant slug (the t- prefix is added internally)
     * @param files map from in-zip path (POSIX-style, no leading slash) to bytes
     */
    public void saveTheme(String slug, Map<String, byte[]> files) {
        String name = configMapNameFor(slug);
        Map<String, String> data = new LinkedHashMap<>();
        Map<String, String> binaryData = new LinkedHashMap<>();

        for (Map.Entry<String, byte[]> e : files.entrySet()) {
            String key = encodePath(e.getKey());
            byte[] bytes = e.getValue();
            if (ThemeValidator.isBinary(e.getKey())) {
                binaryData.put(key, Base64.getEncoder().encodeToString(bytes));
            } else {
                data.put(key, new String(bytes, StandardCharsets.UTF_8));
            }
        }

        ConfigMap cm = new ConfigMapBuilder()
            .withMetadata(new ObjectMetaBuilder()
                .withName(name)
                .withNamespace(namespace)
                .addToLabels(THEME_LABEL, "true")
                .addToLabels("app.kubernetes.io/managed-by", "auth-manager")
                .addToLabels("app.kubernetes.io/component", "tenant-theme")
                .addToAnnotations(LAST_MODIFIED_ANNOTATION, Instant.now().toString())
                .build())
            .withData(data)
            .withBinaryData(binaryData)
            .build();

        // Upsert: try create; on conflict, replace. Fabric8 6.x deprecated
        // createOrReplace() in favour of resource().createOr(update), but the
        // simpler get-then-create/update pattern below works on every version
        // and is easier to reason about for our small payloads.
        var existing = k8s.configMaps().inNamespace(namespace).withName(name).get();
        if (existing == null) {
            k8s.configMaps().inNamespace(namespace).resource(cm).create();
        } else {
            // Preserve the existing resourceVersion so Kubernetes accepts the update.
            cm.getMetadata().setResourceVersion(existing.getMetadata().getResourceVersion());
            k8s.configMaps().inNamespace(namespace).resource(cm).update();
        }
        log.info("Saved theme ConfigMap {} with {} text + {} binary files",
            name, data.size(), binaryData.size());
    }

    /**
     * Reads the raw file map (decoded paths) from the tenant's theme ConfigMap.
     * Returns empty if no ConfigMap exists. Used by the branding merge path
     * which needs to overlay slot HTML onto an existing tenant zip.
     *
     * <p>Both text and binary entries are surfaced — binaryData values are
     * base64-decoded back to raw bytes so callers see the same shape as the
     * Validator's extracted-files map.
     */
    public Optional<Map<String, byte[]>> readThemeFiles(String slug) {
        ConfigMap cm = k8s.configMaps()
            .inNamespace(namespace)
            .withName(configMapNameFor(slug))
            .get();
        if (cm == null) {
            return Optional.empty();
        }
        Map<String, byte[]> out = new LinkedHashMap<>();
        if (cm.getData() != null) {
            for (Map.Entry<String, String> e : cm.getData().entrySet()) {
                out.put(decodePath(e.getKey()), e.getValue().getBytes(StandardCharsets.UTF_8));
            }
        }
        if (cm.getBinaryData() != null) {
            for (Map.Entry<String, String> e : cm.getBinaryData().entrySet()) {
                out.put(decodePath(e.getKey()), Base64.getDecoder().decode(e.getValue()));
            }
        }
        return Optional.of(out);
    }

    public Optional<ThemeMeta> getTheme(String slug) {
        ConfigMap cm = k8s.configMaps()
            .inNamespace(namespace)
            .withName(configMapNameFor(slug))
            .get();
        if (cm == null) {
            return Optional.empty();
        }
        int fileCount = (cm.getData() == null ? 0 : cm.getData().size())
            + (cm.getBinaryData() == null ? 0 : cm.getBinaryData().size());
        long totalBytes = 0;
        if (cm.getData() != null) {
            for (String v : cm.getData().values()) {
                totalBytes += v.getBytes(StandardCharsets.UTF_8).length;
            }
        }
        if (cm.getBinaryData() != null) {
            for (String v : cm.getBinaryData().values()) {
                // Base64 payload; decode length is what we want
                totalBytes += (v.length() * 3L) / 4L;
            }
        }
        Instant lastModified = null;
        if (cm.getMetadata() != null && cm.getMetadata().getAnnotations() != null) {
            String ann = cm.getMetadata().getAnnotations().get(LAST_MODIFIED_ANNOTATION);
            if (ann != null) {
                try { lastModified = Instant.parse(ann); }
                catch (DateTimeParseException ignored) {}
            }
        }
        if (lastModified == null && cm.getMetadata() != null && cm.getMetadata().getCreationTimestamp() != null) {
            try { lastModified = Instant.parse(cm.getMetadata().getCreationTimestamp()); }
            catch (DateTimeParseException ignored) {}
        }
        return Optional.of(new ThemeMeta(true, fileCount, totalBytes, lastModified));
    }

    public boolean deleteTheme(String slug) {
        var deleted = k8s.configMaps()
            .inNamespace(namespace)
            .withName(configMapNameFor(slug))
            .delete();
        boolean removed = deleted != null && !deleted.isEmpty();
        if (removed) {
            log.info("Deleted theme ConfigMap {}", configMapNameFor(slug));
        }
        return removed;
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    static String configMapNameFor(String slug) {
        return CONFIGMAP_NAME_PREFIX + slug;
    }

    static String encodePath(String path) {
        return path.replace("/", PATH_SEPARATOR_ENCODING);
    }

    static String decodePath(String key) {
        return key.replace(PATH_SEPARATOR_ENCODING, "/");
    }
}
