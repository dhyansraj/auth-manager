package io.mcpmesh.auth.manager.api.dto;

import jakarta.validation.constraints.NotEmpty;
import java.util.Set;

public record UpdateUserRolesRequest(
    @NotEmpty Set<String> roles  // full desired role set; service diffs add/remove
) {}
