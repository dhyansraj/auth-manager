package io.mcpmesh.auth.manager.theme;

import java.time.Instant;

/**
 * Public summary of a tenant's current theme. Returned by both
 * {@code GET /theme} and {@code POST /theme}.
 *
 * <p>{@code configured=false} means no ConfigMap exists; the other fields are
 * zero/null in that case so the UI can render the "no theme" state.
 */
public record ThemeMeta(
    boolean configured,
    int fileCount,
    long totalBytes,
    Instant lastModified
) {
    public static ThemeMeta absent() {
        return new ThemeMeta(false, 0, 0L, null);
    }
}
