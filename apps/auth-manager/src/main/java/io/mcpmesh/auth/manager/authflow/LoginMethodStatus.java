package io.mcpmesh.auth.manager.authflow;

import java.util.List;

/**
 * Per-tenant login-method state — what users can authenticate WITH on this
 * tenant's realm.
 *
 * <ul>
 *   <li>{@code passwordEnabled} — true when the cloned {@code mcpmesh-browser}
 *       flow's "Username Password Form" execution is REQUIRED. False means
 *       social-only login (IdP brokering is the only option).</li>
 *   <li>{@code enabledIdpAliases} — KC IdP aliases currently registered on
 *       the realm. Used by the UI to surface "you have N social providers
 *       enabled" + to enforce the "must have at least one login method"
 *       invariant.</li>
 * </ul>
 */
public record LoginMethodStatus(
    boolean passwordEnabled,
    List<String> enabledIdpAliases
) {}
