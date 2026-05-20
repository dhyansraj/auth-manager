package io.mcpmesh.auth.manager.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * One hostname-to-backend route attached to a tenant.
 *
 * @param host    Public hostname (DNS-safe, lowercase). Becomes the
 *                Host header OpenResty sees.
 * @param backend Internal upstream "host:port" the request proxies to.
 */
public record HostnameAssignment(

    @NotBlank
    @Size(min = 1, max = 253)
    @Pattern(regexp = "^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$",
             message = "must be a lowercase DNS-safe hostname")
    String host,

    @NotBlank
    @Size(min = 1, max = 253)
    String backend
) {}
