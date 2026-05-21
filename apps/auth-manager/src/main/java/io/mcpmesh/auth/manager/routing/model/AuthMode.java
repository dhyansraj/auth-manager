package io.mcpmesh.auth.manager.routing.model;

/**
 * How OpenResty should treat the JWT for requests matching a routing rule.
 *
 * <ul>
 *   <li>{@code PUBLIC}   - bypass auth entirely; request is forwarded as-is.</li>
 *   <li>{@code REQUIRED} - reject (401) if no valid JWT for the tenant realm.</li>
 *   <li>{@code OPTIONAL} - validate if present; forward either way.</li>
 * </ul>
 */
public enum AuthMode {
    PUBLIC,
    REQUIRED,
    OPTIONAL
}
