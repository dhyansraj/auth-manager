package io.mcpmesh.auth.manager.api;

import io.mcpmesh.auth.manager.routing.RoutingConfigService;
import io.mcpmesh.auth.manager.routing.model.RoutingConfig;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Routing-rules CRUD for a tenant. Read + replace; rules are managed
 * as a single atomic blob (no per-rule add/remove).
 */
@RestController
@RequestMapping("/api/v1/tenants/{slug}/routes")
public class RouteController {

    private final RoutingConfigService service;

    public RouteController(RoutingConfigService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("@perms.hasOnTenant(#slug, 'TENANT_VIEW')")
    public RoutingConfig get(@PathVariable String slug) {
        return service.getForTenant(slug);
    }

    @PutMapping
    @PreAuthorize("@perms.hasOnTenant(#slug, 'ROUTES_EDIT')")
    public RoutingConfig replace(
        @PathVariable String slug,
        @Valid @RequestBody RoutingConfig body
    ) {
        return service.replaceForTenant(slug, body);
    }
}
