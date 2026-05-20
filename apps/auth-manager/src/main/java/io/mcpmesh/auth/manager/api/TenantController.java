package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.api.dto.CreateTenantRequest;
import io.mcpmesh.auth.manager.api.dto.TenantResponse;
import io.mcpmesh.auth.manager.service.TenantService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
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
@RequestMapping("/api/v1/tenants")
public class TenantController {

    private final TenantService service;

    public TenantController(TenantService service) {
        this.service = service;
    }

    @PostMapping
    public ResponseEntity<TenantResponse> create(
        @Valid @RequestBody CreateTenantRequest req,
        UriComponentsBuilder uriBuilder
    ) {
        // TODO(security): replace "system" with the authenticated principal once
        //                 auth-lib v2 lands. See PLAN.org Phase 2.
        var t = service.create(
            req.slug(), req.displayName(), req.settings(), req.hostnames(), "system");
        var body = TenantResponse.from(t, service.hostnamesFor(t.getId()));
        var location = uriBuilder.path("/api/v1/tenants/{id}").buildAndExpand(t.getId()).toUri();
        return ResponseEntity.created(location).body(body);
    }

    @GetMapping
    public List<TenantResponse> list() {
        return service.list().stream()
            .map(t -> TenantResponse.from(t, service.hostnamesFor(t.getId())))
            .toList();
    }

    @GetMapping("/{id}")
    public TenantResponse get(@PathVariable UUID id) {
        var t = service.get(id);
        return TenantResponse.from(t, service.hostnamesFor(t.getId()));
    }

    @GetMapping("/by-slug/{slug}")
    public TenantResponse getBySlug(@PathVariable String slug) {
        var t = service.getBySlug(slug);
        return TenantResponse.from(t, service.hostnamesFor(t.getId()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(org.springframework.http.HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID id) {
        service.softDelete(id, "system");  // TODO(security): real actor
    }

    @PostMapping("/{id}/retry")
    public TenantResponse retry(@PathVariable UUID id) {
        // TODO(security): replace "system" with the authenticated principal.
        var t = service.retryProvisioning(id, "system");
        return TenantResponse.from(t, service.hostnamesFor(t.getId()));
    }
}
