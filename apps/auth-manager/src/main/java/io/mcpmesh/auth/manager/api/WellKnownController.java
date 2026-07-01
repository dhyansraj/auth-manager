package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.domain.app.App;
import io.mcpmesh.auth.manager.domain.tenant.TenantHostname;
import io.mcpmesh.auth.manager.persistence.AppRepository;
import io.mcpmesh.auth.manager.persistence.TenantHostnameRepository;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Serves iOS Universal Links (apple-app-site-association) and Android App Links
 * (assetlinks.json) association files for a tenant subdomain. Fetched anonymously
 * by Apple/Google, so these paths are permitAll in SecurityConfig.
 *
 * <p>The tenant is resolved from the incoming Host header (the edge forwards the
 * original tenant Host and the literal {@code /.well-known/...} path unchanged).
 */
@RestController
public class WellKnownController {

    private static final String NATIVE_PROFILE = "NATIVE_PKCE";

    private final TenantHostnameRepository hostnames;
    private final AppRepository apps;

    public WellKnownController(TenantHostnameRepository hostnames, AppRepository apps) {
        this.hostnames = hostnames;
        this.apps = apps;
    }

    @GetMapping(value = "/.well-known/apple-app-site-association", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> appleAppSiteAssociation(@RequestHeader("Host") String host) {
        List<App> nativeApps = nativeAppsForHost(host);

        List<Map<String, Object>> details = new ArrayList<>();
        for (App app : nativeApps) {
            if (hasText(app.getIosTeamId()) && hasText(app.getIosBundleId())) {
                details.add(Map.of(
                    "appID", app.getIosTeamId() + "." + app.getIosBundleId(),
                    "paths", List.of("/auth/callback", "/auth/*")
                ));
            }
        }
        if (details.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        return Map.of("applinks", Map.of(
            "apps", List.of(),
            "details", details
        ));
    }

    @GetMapping(value = "/.well-known/assetlinks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public List<Map<String, Object>> assetLinks(@RequestHeader("Host") String host) {
        List<App> nativeApps = nativeAppsForHost(host);

        List<Map<String, Object>> statements = new ArrayList<>();
        for (App app : nativeApps) {
            if (hasText(app.getAndroidPackage()) && hasText(app.getAndroidCertSha256())) {
                statements.add(Map.of(
                    "relation", List.of("delegate_permission/common.handle_all_urls"),
                    "target", Map.of(
                        "namespace", "android_app",
                        "package_name", app.getAndroidPackage(),
                        "sha256_cert_fingerprints", List.of(app.getAndroidCertSha256().trim().split("[,\\s]+"))
                    )
                ));
            }
        }
        if (statements.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }

        return statements;
    }

    private List<App> nativeAppsForHost(String host) {
        String hostname = stripPort(host);
        UUID tenantId = hostnames.findByHostname(hostname)
            .map(TenantHostname::getTenantId)
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));

        List<App> result = new ArrayList<>();
        for (App app : apps.findByTenantIdOrderByCreatedAtDesc(tenantId)) {
            if (NATIVE_PROFILE.equals(app.getProfile())) {
                result.add(app);
            }
        }
        return result;
    }

    private static String stripPort(String host) {
        if (host == null) {
            return "";
        }
        String h = host.trim();
        int colon = h.indexOf(':');
        return colon >= 0 ? h.substring(0, colon) : h;
    }

    private static boolean hasText(String s) {
        return s != null && !s.isBlank();
    }
}
