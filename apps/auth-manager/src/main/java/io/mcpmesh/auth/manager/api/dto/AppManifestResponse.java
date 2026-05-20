package io.mcpmesh.auth.manager.api.dto;

import io.mcpmesh.auth.manager.domain.app.AppManifest;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record AppManifestResponse(
    UUID id,
    UUID appId,
    Integer version,
    String hash,
    Map<String, Object> manifest,
    Instant appliedAt,
    String appliedBy,
    boolean noOp
) {
    public static AppManifestResponse from(AppManifest m, boolean noOp) {
        return new AppManifestResponse(
            m.getId(), m.getAppId(), m.getVersion(), m.getHash(),
            m.getManifestJson(), m.getAppliedAt(), m.getAppliedBy(), noOp);
    }
}
