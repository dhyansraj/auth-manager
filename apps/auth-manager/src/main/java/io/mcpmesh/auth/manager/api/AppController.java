package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.AppResponse;
import io.mcpmesh.auth.manager.api.dto.CreateAppRequest;
import io.mcpmesh.auth.manager.service.AppService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/tenants/{tenantId}/apps")
public class AppController {

    private final AppService service;

    public AppController(AppService service) {
        this.service = service;
    }

    @PostMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'APPS_EDIT')")
    public ResponseEntity<AppResponse> create(
        @PathVariable UUID tenantId,
        @Valid @RequestBody CreateAppRequest req,
        UriComponentsBuilder uriBuilder
    ) {
        var result = service.create(tenantId, req.slug(), req.displayName(), "system");
        var body = AppResponse.from(result.app(), result.clientSecret());
        var location = uriBuilder.path("/api/v1/tenants/{t}/apps/{a}")
            .buildAndExpand(tenantId, result.app().getId()).toUri();
        return ResponseEntity.created(location).body(body);
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'APPS_EDIT')")
    public List<AppResponse> list(@PathVariable UUID tenantId) {
        return service.listByTenant(tenantId).stream().map(AppResponse::from).toList();
    }

    @GetMapping("/{appId}")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'APPS_EDIT')")
    public AppResponse get(@PathVariable UUID tenantId, @PathVariable UUID appId) {
        return AppResponse.from(service.get(tenantId, appId));
    }

    @DeleteMapping("/{appId}")
    @PreAuthorize("@perms.hasOnTenantId(#tenantId, 'APPS_EDIT')")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID tenantId, @PathVariable UUID appId) {
        service.delete(tenantId, appId, "system");
    }
}
