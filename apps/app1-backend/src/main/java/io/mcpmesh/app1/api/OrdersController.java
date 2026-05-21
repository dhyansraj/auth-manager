package io.mcpmesh.app1.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Mounted at /api/orders so the platform-edge "/api/* REQUIRED" rule
 * gates this endpoint at the edge (returns 401 before reaching us when
 * no token is present), while a valid token still lets us validate it
 * via auth-lib v2 + @PreAuthorize on the resource-server side.
 */
@RestController
@RequestMapping("/api/orders")
public class OrdersController {

    @GetMapping
    @PreAuthorize("hasAuthority('PERMISSION_ORDER_VIEW')")
    public List<Map<String, Object>> list() {
        return List.of(
            Map.of("id", 1, "item", "Widget",   "qty", 3),
            Map.of("id", 2, "item", "Gizmo",    "qty", 1),
            Map.of("id", 3, "item", "Sprocket", "qty", 5)
        );
    }
}
