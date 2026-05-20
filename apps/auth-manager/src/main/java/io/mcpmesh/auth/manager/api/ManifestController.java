package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.AccessManifest;
import io.mcpmesh.auth.manager.api.dto.AppManifestResponse;
import io.mcpmesh.auth.manager.service.ManifestService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/apps/{appId}/manifests")
public class ManifestController {

    private final ManifestService service;

    public ManifestController(ManifestService service) {
        this.service = service;
    }

    @PostMapping("/apply")
    public AppManifestResponse apply(
        @PathVariable UUID tenantId,
        @PathVariable UUID appId,
        @Valid @RequestBody AccessManifest manifest
    ) {
        var result = service.apply(tenantId, appId, manifest, "system");
        return AppManifestResponse.from(result.manifest(), result.noOp());
    }

    @GetMapping
    public List<AppManifestResponse> list(@PathVariable UUID tenantId, @PathVariable UUID appId) {
        return service.listForApp(tenantId, appId).stream()
            .map(m -> AppManifestResponse.from(m, false))
            .toList();
    }
}
