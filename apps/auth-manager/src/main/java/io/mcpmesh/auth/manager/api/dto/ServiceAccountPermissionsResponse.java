package io.mcpmesh.auth.manager.api.dto;

import java.util.List;

/**
 * Effective permission set on an app's service-account user after a PUT.
 */
public record ServiceAccountPermissionsResponse(
    List<String> permissions
) {}
